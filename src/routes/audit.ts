/**
 * Audit Routes
 * GET  /api/audit/pre-check  \u2014 Token permission pre-check (NO credit charge)
 * POST /api/audit/start      \u2014 Start a security audit (deducts credits, runs synchronously)
 * GET  /api/audit/:id        \u2014 Retrieve an audit report by ID
 * GET  /api/audit/history    \u2014 User's audit history
 */

import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient } from '../services/supabase';
import { collectAuditData } from '../services/audit/collector';
import { calculateScore, generateRecommendations } from '../services/audit/score-engine';
import { CfApiError, cfFetch } from '../services/audit/cf-rest';
import type {
  AuditTier,
  AuditReport,
  StartAuditRequest,
} from '../types/audit';
import {
  AUDIT_CREDIT_COSTS,
  AUDIT_TIER_MAP,
  AUDIT_TIER_NAMES,
} from '../types/audit';

const audit = new Hono<{ Bindings: Env; Variables: Variables }>();

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Helper: Tolerant CF API fetch (returns null on error)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

async function cfCheckPermission(path: string, token: string): Promise<any | null> {
  try {
    const resp = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    });
    // Clear HTTP auth failures = no permission
    if (resp.status === 401 || resp.status === 403) return null;

    const text = await resp.text();
    try {
      const json = JSON.parse(text);
      // Cloudflare sometimes returns 200 with success:false + code 10000 for auth errors
      if (json.success === false) {
        const hasAuthError = (json.errors || []).some((e: any) =>
          e.code === 10000 && /auth|unauthorized|forbidden/i.test(e.message || '')
        );
        return hasAuthError ? null : json;
      }
      return json;
    } catch {
      // Non-JSON response (e.g. logs/received returns text "Retention is not turned on")
      // Since we already passed the 401/403 check, the permission exists
      return { permissionGranted: true, message: text.slice(0, 200) };
    }
  } catch {
    return null;
  }
}

// GraphQL-based Analytics permission check (REST analytics API is sunset)
async function cfFetchGraphQLAnalytics(zoneId: string, token: string): Promise<any | null> {
  try {
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const query = {
      query: `{ viewer { zones(filter: {zoneTag: "${zoneId}"}) { httpRequests1dGroups(limit: 1, filter: {date_gt: "${yesterday}"}) { sum { requests } } } } }`,
    };
    const resp = await fetch('https://api.cloudflare.com/client/v4/graphql', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(query),
    });
    if (!resp.ok) return null;
    const json = await resp.json() as any;
    // GraphQL returns data.viewer.zones[0] if permission exists
    return json?.data?.viewer?.zones?.[0] ? json : null;
  } catch {
    return null;
  }
}

// Required permissions by tier
const TIER_PERMISSIONS: Record<AuditTier, { required: string[]; optional: string[] }> = {
  basic: {
    required: ['Zone:Read', 'Firewall Services:Read', 'DNS:Read'],
    optional: ['Analytics:Read'],
  },
  pro: {
    required: ['Zone:Read', 'Firewall Services:Read', 'DNS:Read', 'Analytics:Read'],
    optional: ['Logs:Read', 'SSL and Certificates:Read'],
  },
  complete: {
    required: ['Zone:Read', 'Firewall Services:Read', 'DNS:Read', 'Analytics:Read'],
    optional: ['Logs:Read', 'SSL and Certificates:Read', 'Page Shield:Read', 'Health Checks:Read', 'Account Access: Audit Logs', 'Notifications:Read'],
  },
};

async function discoverAuditTokenPermissions(
  zoneId: string,
  accountId: string,
  token: string,
): Promise<{ available: string[]; missing: string[] }> {
  const checks = [
    { name: 'Zone:Read', test: () => cfCheckPermission(`/zones/${zoneId}`, token) },
    { name: 'Analytics:Read', test: () => cfFetchGraphQLAnalytics(zoneId, token) },
    { name: 'Firewall Services:Read', test: () => cfCheckPermission(`/zones/${zoneId}/firewall/access_rules/rules?per_page=1`, token) },
    { name: 'DNS:Read', test: () => cfCheckPermission(`/zones/${zoneId}/dns_records?per_page=1`, token) },
    { name: 'SSL and Certificates:Read', test: () => cfCheckPermission(`/zones/${zoneId}/ssl/certificate_packs?per_page=1`, token) },
    { name: 'Logs:Read', test: () => cfCheckPermission(`/zones/${zoneId}/logs/received?start=2024-01-01T00:00:00Z&end=2024-01-01T00:01:00Z&count=1`, token) },
    { name: 'Page Shield:Read', test: () => cfCheckPermission(`/zones/${zoneId}/page_shield/scripts?per_page=1`, token) },
    { name: 'Health Checks:Read', test: () => cfCheckPermission(`/zones/${zoneId}/healthchecks`, token) },
    { name: 'Account Access: Audit Logs', test: () => cfCheckPermission(`/accounts/${accountId}/audit_logs?per_page=1`, token) },
    { name: 'Notifications:Read', test: () => cfCheckPermission(`/accounts/${accountId}/alerting/v3/policies`, token) },
  ];

  const results = await Promise.all(
    checks.map(async (check) => ({ name: check.name, ok: (await check.test()) !== null })),
  );

  const available: string[] = [];
  const missing: string[] = [];
  for (const r of results) {
    if (r.ok) available.push(r.name);
    else missing.push(r.name);
  }

  return { available, missing };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /pre-check \u2014 Token Permission Pre-Check (NO credit charge)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

audit.post('/pre-check', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const body = await c.req.json<{
    zone_id?: string;
    api_token?: string;
    account_id?: string;
    tier?: AuditTier;
  }>().catch(() => ({}));

  const { zone_id: zoneId, api_token: apiToken, account_id: accountId = '', tier = 'basic' } = body;

  if (!zoneId || !apiToken) {
    return c.json({ error: 'Missing required fields: zone_id, api_token' }, 400);
  }

  if (!/^[a-f0-9]{32}$/.test(zoneId)) {
    return c.json({ error: 'Invalid Zone ID format.' }, 400);
  }

  const validTiers: AuditTier[] = ['basic', 'pro', 'complete'];
  if (!validTiers.includes(tier)) {
    return c.json({ error: `Invalid tier: ${tier}` }, 400);
  }

  // Get user account for credit balance
  const { data: account } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // Fetch zone info (basic test + get zone name/plan)
  let zoneName = zoneId;
  let cfPlan = 'unknown';
  const zoneResult = await cfCheckPermission(`/zones/${zoneId}`, apiToken);
  if (zoneResult?.result) {
    zoneName = zoneResult.result.name || zoneId;
    cfPlan = zoneResult.result.plan?.name || 'unknown';
  }

  // Discover all token permissions in parallel
  const permissions = await discoverAuditTokenPermissions(zoneId, accountId, apiToken);

  // Determine which required permissions are missing for this tier
  const tierPerms = TIER_PERMISSIONS[tier];
  const missingRequired = tierPerms.required.filter((p) => !permissions.available.includes(p));
  const missingOptional = tierPerms.optional.filter((p) => !permissions.available.includes(p));
  const canRun = missingRequired.length === 0;

  // Estimate collectors affected
  const collectorsAffected = missingOptional.length; // rough: 1 optional perm ~ 1 collector

  const creditCost = AUDIT_CREDIT_COSTS[tier];
  const insufficientCredits = account.credit_balance < creditCost;

  return c.json({
    can_run: canRun && !insufficientCredits,
    zone_info: {
      zone_id: zoneId,
      zone_name: zoneName,
      cf_plan: cfPlan,
      zone_valid: zoneResult !== null,
    },
    permissions: {
      available: permissions.available,
      missing: permissions.missing,
      required_for_tier: tierPerms.required,
      optional_for_tier: tierPerms.optional,
      missing_required: missingRequired,
      missing_optional: missingOptional,
      collectors_affected: collectorsAffected,
    },
    credits: {
      required: creditCost,
      available: account.credit_balance,
      sufficient: !insufficientCredits,
    },
    tier,
    blocked_reasons: [
      ...(missingRequired.length > 0 ? [`Missing required permissions: ${missingRequired.join(', ')}`] : []),
      ...(insufficientCredits ? [`Insufficient credits (need ${creditCost}, have ${account.credit_balance})`] : []),
      ...(!zoneResult ? ['Zone ID not found or token has no Zone:Read permission'] : []),
    ],
  });
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// POST /start \u2014 Run a Security Audit
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

audit.post('/start', async (c) => {
  const userId = c.get('userId');

  const body = await c.req.json<Partial<StartAuditRequest>>().catch(() => ({}));
  const { zone_id, api_token, tier } = body;

  // Validate inputs
  if (!zone_id || !api_token || !tier) {
    return c.json({ error: 'Missing required fields: zone_id, api_token, tier' }, 400);
  }

  const validTiers: AuditTier[] = ['basic', 'pro', 'complete'];
  if (!validTiers.includes(tier)) {
    return c.json({ error: `Invalid tier: ${tier}. Must be one of: ${validTiers.join(', ')}` }, 400);
  }

  // Zone ID format validation (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(zone_id)) {
    return c.json({ error: 'Invalid Zone ID format. Expected a 32-character hexadecimal string.' }, 400);
  }

  // API token basic validation (at least 20 chars, no spaces)
  if (api_token.length < 20 || /\s/.test(api_token)) {
    return c.json({ error: 'Invalid API token format.' }, 400);
  }

  const creditCost = AUDIT_CREDIT_COSTS[tier];
  const admin = getAdminClient(c.env);

  // Get account
  const { data: account, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !account) {
    return c.json({ error: 'Account not found. Please set up your account first.' }, 404);
  }

  if (account.status === 'suspended') {
    return c.json({ error: 'Account is suspended' }, 403);
  }

  // Check credit balance
  if (account.credit_balance < creditCost) {
    return c.json({
      error: 'Insufficient credits',
      message: `${AUDIT_TIER_NAMES[tier].en} requires ${creditCost} credits. Your balance: ${account.credit_balance}.`,
      creditCost,
      currentBalance: account.credit_balance,
      tier,
    }, 402);
  }

  // Deduct credits BEFORE running the audit
  const { error: deductError } = await admin.rpc('deduct_security_credits', {
    p_account_id: account.id,
    p_amount: creditCost,
    p_description: `${AUDIT_TIER_NAMES[tier].en}: Zone ${zone_id}`,
    p_report_id: null,
  });

  if (deductError) {
    console.error('Credit deduction failed:', deductError);
    return c.json({ error: 'Failed to deduct credits. Please try again.' }, 500);
  }

  // Create report record (status: running)
  const { data: report, error: insertError } = await admin
    .from('security_reports')
    .insert({
      account_id: account.id,
      domain: zone_id,
      report_type: 'audit',
      status: 'running',
      credits_charged: creditCost,
    })
    .select('id')
    .single();

  if (insertError || !report) {
    console.error('Failed to create report:', insertError);
    await admin.rpc('add_security_credits', {
      p_account_id: account.id,
      p_amount: creditCost,
      p_description: `Refund: failed to start ${AUDIT_TIER_NAMES[tier].en}`,
      p_report_id: null,
    });
    return c.json({ error: 'Failed to start audit' }, 500);
  }

  try {
    const startTime = Date.now();
    const collectionResult = await collectAuditData(zone_id, api_token, tier);
    const scoreBreakdown = calculateScore(collectionResult.data, tier);
    const recommendations = generateRecommendations(collectionResult.data, scoreBreakdown, tier);
    const durationMs = Date.now() - startTime;

    const auditReport: AuditReport = {
      version: '1.0',
      tier,
      tier_id: AUDIT_TIER_MAP[tier],
      zone_id,
      zone_name: collectionResult.data.zone_info.name,
      cf_plan: collectionResult.cfPlan,
      generated_at: new Date().toISOString(),
      duration_ms: durationMs,
      analysis_period: collectionResult.analysisPeriod,
      score: scoreBreakdown,
      data: collectionResult.data,
      recommendations,
      collectors_run: collectionResult.collectorsRun,
      collectors_skipped: collectionResult.collectorsSkipped,
      collectors_warned: collectionResult.collectorsWarned,
    };

    await admin
      .from('security_reports')
      .update({
        domain: collectionResult.data.zone_info.name,
        status: 'completed',
        score: scoreBreakdown.overall_score,
        grade: scoreBreakdown.overall_grade,
        data: auditReport,
        completed_at: new Date().toISOString(),
      })
      .eq('id', report.id);

    await admin
      .from('security_credit_transactions')
      .update({ report_id: report.id })
      .eq('account_id', account.id)
      .is('report_id', null)
      .order('created_at', { ascending: false })
      .limit(1);

    return c.json({
      success: true,
      report_id: report.id,
      tier,
      credits_charged: creditCost,
      report: auditReport,
    });
  } catch (err: any) {
    console.error('Audit failed:', err);

    const isCfAuth = err instanceof CfApiError && err.isAuthError;

    await admin
      .from('security_reports')
      .update({
        status: 'failed',
        data: { error: err.message || 'Audit failed', is_auth_error: isCfAuth },
      })
      .eq('id', report.id);

    await admin.rpc('add_security_credits', {
      p_account_id: account.id,
      p_amount: creditCost,
      p_description: `Refund: ${AUDIT_TIER_NAMES[tier].en} failed`,
      p_report_id: report.id,
    });

    await admin
      .from('security_reports')
      .update({ credits_charged: 0 })
      .eq('id', report.id);

    if (isCfAuth) {
      return c.json({
        error: 'Invalid API token',
        message: 'The API token was rejected by Cloudflare. Please verify your Zone ID and token permissions (Zone:Read, Analytics:Read, Firewall:Read, DNS:Read).',
        reportId: report.id,
        creditsRefunded: creditCost,
      }, 401);
    }

    return c.json({
      error: 'Audit failed',
      message: `The audit could not be completed. Credits have been refunded. Error: ${err.message || 'Unknown error'}`,
      reportId: report.id,
      creditsRefunded: creditCost,
    }, 500);
  }
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /history \u2014 User's audit history (enriched)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

audit.get('/history', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const limit = Math.min(parseInt(c.req.query('limit') || '20'), 50);
  const offset = parseInt(c.req.query('offset') || '0');

  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  const { data: rawReports, error, count } = await admin
    .from('security_reports')
    .select('id, domain, report_type, score, grade, status, credits_charged, created_at, completed_at, data', {
      count: 'exact',
    })
    .eq('account_id', account.id)
    .eq('report_type', 'audit')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  // Extract enriched fields from JSONB data, strip heavy data field
  const reports = (rawReports || []).map((r: any) => ({
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
    tier: r.data?.tier || null,
    cf_plan: r.data?.cf_plan || null,
    duration_ms: r.data?.duration_ms || null,
    collectors_run: r.data?.collectors_run ?? null,
    collectors_skipped: r.data?.collectors_skipped ?? null,
    collectors_warned: r.data?.collectors_warned ?? null,
    categories_count: r.data?.score?.categories?.length || 0,
    recommendations_count: r.data?.recommendations?.length || 0,
    analysis_period: r.data?.analysis_period || null,
    zone_id: r.data?.zone_id || null,
    // For failed reports
    error_message: r.status === 'failed' ? (r.data?.error || null) : null,
  }));

  if (error) {
    console.error('Failed to fetch audit history:', error);
    return c.json({ error: 'Failed to fetch audit history' }, 500);
  }

  return c.json({
    reports: reports || [],
    total: count || 0,
    limit,
    offset,
  });
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /:id \u2014 Retrieve a specific audit report
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

audit.get('/:id', async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('id');
  const admin = getAdminClient(c.env);

  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

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

export default audit;
