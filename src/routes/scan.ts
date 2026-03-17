/**
 * Scan Routes
 * POST /api/scan/quick  — Run a free external quick scan (1/month)
 * GET  /api/scan/:id    — Retrieve a scan report by ID
 * GET  /api/scan/history — User's scan history
 */

import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { FREE_SCANS_PER_MONTH, QUICK_SCAN_CREDIT_COST } from '../types';
import { getAdminClient } from '../services/supabase';
import { performQuickScan } from '../services/external-scanner';
import { calculateQuickScore } from '../services/quick-score';
import { validateDomainSafety, normalizeDomainInput } from '../utils/url-safety';

const scan = new Hono<{ Bindings: Env; Variables: Variables }>();

// ============================================================
// POST /quick — Run a Quick Scan
// ============================================================

scan.post('/quick', async (c) => {
  const user = c.get('user');
  const userId = c.get('userId');

  // Parse and validate domain
  const body = await c.req.json<{ domain?: string }>().catch(() => ({} as { domain?: string }));
  const domain = body.domain?.trim().toLowerCase();

  if (!domain) {
    return c.json({ error: 'Domain is required' }, 400);
  }

  // Normalize and validate domain
  const cleanDomain = normalizeDomainInput(domain);
  const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

  if (!domainRegex.test(cleanDomain)) {
    return c.json({ error: 'Invalid domain format' }, 400);
  }

  // SSRF protection: validate domain doesn't resolve to private IPs
  const safetyCheck = await validateDomainSafety(cleanDomain);
  if (!safetyCheck.safe) {
    console.error(`SSRF blocked: ${cleanDomain} - ${safetyCheck.reason}`);
    return c.json({ error: 'Domain not accessible' }, 400);
  }

  const admin = getAdminClient(c.env);

  // Get or verify account exists
  const { data: account, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, free_scans_used, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !account) {
    return c.json({ error: 'Account not found. Please set up your account first.' }, 404);
  }

  if (account.status === 'suspended') {
    return c.json({ error: 'Account is suspended' }, 403);
  }

  // Check free scan limit (1 per calendar month)
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const { count: scansThisMonth } = await admin
    .from('security_reports')
    .select('id', { count: 'exact', head: true })
    .eq('account_id', account.id)
    .eq('report_type', 'quick_scan')
    .gte('created_at', monthStart);

  const freeExhausted = (scansThisMonth || 0) >= FREE_SCANS_PER_MONTH;
  let creditCost = 0;

  if (freeExhausted) {
    // Free scans used up — this will cost credits
    creditCost = QUICK_SCAN_CREDIT_COST;

    if (account.credit_balance < creditCost) {
      return c.json(
        {
          error: 'Insufficient credits',
          message: `Free Quick Scans exhausted. Additional scans cost ${creditCost} credits. Your balance: ${account.credit_balance}.`,
          creditCost,
          currentBalance: account.credit_balance,
          limit: FREE_SCANS_PER_MONTH,
          used: scansThisMonth,
          resetsAt: new Date(now.getFullYear(), now.getMonth() + 1, 1).toISOString(),
        },
        402
      );
    }
  }

  // Create report record (status: running)
  const { data: report, error: insertError } = await admin
    .from('security_reports')
    .insert({
      account_id: account.id,
      domain: cleanDomain,
      report_type: 'quick_scan',
      status: 'running',
      credits_charged: 0,
    })
    .select('id')
    .single();

  if (insertError || !report) {
    console.error('Failed to create report:', insertError);
    return c.json({ error: 'Failed to start scan' }, 500);
  }

  try {
    // Run the external scan
    const scanData = await performQuickScan(cleanDomain);

    // Calculate score
    const result = calculateQuickScore(scanData, report.id);

    // Update report with results
    const { error: updateError } = await admin
      .from('security_reports')
      .update({
        status: 'completed',
        score: result.overallScore,
        grade: result.overallGrade,
        data: {
          scanData,
          result,
        },
        completed_at: new Date().toISOString(),
      })
      .eq('id', report.id);

    if (updateError) {
      console.error('Failed to save report:', updateError);
    }

    // Deduct credits if this was a paid scan
    if (creditCost > 0) {
      // Deduct credits via RPC
      await admin.rpc('deduct_security_credits', {
        p_account_id: account.id,
        p_amount: creditCost,
        p_description: `Quick Scan: ${cleanDomain}`,
        p_report_id: report.id,
      });

      // Update report to reflect credits charged
      await admin
        .from('security_reports')
        .update({ credits_charged: creditCost })
        .eq('id', report.id);
    }

    // Increment free_scans_used counter
    await admin
      .from('security_accounts')
      .update({
        free_scans_used: (account.free_scans_used || 0) + 1,
      })
      .eq('id', account.id);

    return c.json({
      success: true,
      report: result,
      creditsCharged: creditCost,
    });
  } catch (err: any) {
    console.error('Scan failed:', err);

    // Mark report as failed
    await admin
      .from('security_reports')
      .update({
        status: 'failed',
        data: { error: err.message || 'Scan failed' },
      })
      .eq('id', report.id);

    return c.json(
      {
        error: 'Scan failed',
        message: `Could not scan ${cleanDomain}. The site may be unreachable or blocking requests.`,
        reportId: report.id,
      },
      500
    );
  }
});

// ============================================================
// GET /history — User's scan history
// ============================================================

scan.get('/history', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const limit = Math.min(parseInt(c.req.query('limit') || '20'), 50);
  const offset = parseInt(c.req.query('offset') || '0');

  // Get account ID
  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // Get reports (newest first) — include data for JSONB extraction
  const { data: rawReports, error, count } = await admin
    .from('security_reports')
    .select('id, domain, report_type, score, grade, status, credits_charged, created_at, completed_at, data', {
      count: 'exact',
    })
    .eq('account_id', account.id)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    console.error('Failed to fetch history:', error);
    return c.json({ error: 'Failed to fetch scan history' }, 500);
  }

  // Enrich with JSONB data, then strip the heavy `data` field
  const reports = (rawReports || []).map((r: any) => {
    const result = r.data?.result || {};
    const categories = result.categories || [];
    const recommendations = result.recommendations || [];
    return {
      id: r.id,
      domain: r.domain,
      report_type: r.report_type,
      score: r.score,
      grade: r.grade,
      status: r.status,
      credits_charged: r.credits_charged,
      created_at: r.created_at,
      completed_at: r.completed_at,
      // Enriched fields from JSONB
      duration_ms: result.durationMs || 0,
      categories_count: categories.length,
      categories_summary: categories.map((c: any) => ({
        label: c.label || c.category || '',
        score: c.score ?? 0,
        grade: c.grade || '',
      })),
      recommendations_count: recommendations.length,
      recommendations_high: recommendations.filter((r: any) => r.priority === 'high').length,
      recommendations_medium: recommendations.filter((r: any) => r.priority === 'medium').length,
      recommendations_low: recommendations.filter((r: any) => r.priority === 'low').length,
      error_message: r.data?.error || null,
    };
  });

  // Free scan usage this month
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();

  const { count: scansThisMonth } = await admin
    .from('security_reports')
    .select('id', { count: 'exact', head: true })
    .eq('account_id', account.id)
    .eq('report_type', 'quick_scan')
    .gte('created_at', monthStart);

  // Get current credit balance for frontend display
  const { data: accountBalance } = await admin
    .from('security_accounts')
    .select('credit_balance')
    .eq('id', account.id)
    .single();

  return c.json({
    reports,
    total: count || 0,
    limit,
    offset,
    freeScans: {
      used: scansThisMonth || 0,
      limit: FREE_SCANS_PER_MONTH,
      resetsAt: new Date(now.getFullYear(), now.getMonth() + 1, 1).toISOString(),
    },
    paidScanCost: QUICK_SCAN_CREDIT_COST,
    creditBalance: accountBalance?.credit_balance || 0,
  });
});

// ============================================================
// GET /:id — Retrieve a specific report
// ============================================================

scan.get('/:id', async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('id');
  const admin = getAdminClient(c.env);

  // Get account ID
  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // Get report (must belong to this user)
  const { data: report, error } = await admin
    .from('security_reports')
    .select('*')
    .eq('id', reportId)
    .eq('account_id', account.id)
    .single();

  if (error || !report) {
    return c.json({ error: 'Report not found' }, 404);
  }

  return c.json({ report });
});

export default scan;
