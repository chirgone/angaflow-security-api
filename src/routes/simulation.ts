/**
 * Simulation Routes
 * GET  /api/simulation/pre-check \u2014 Token permission pre-check (NO credit charge)
 * GET  /api/simulation/targets   \u2014 Discover proxied domains for target selection (NO credit charge)
 * POST /api/simulation/start     \u2014 Start an attack simulation (deducts 3500 credits)
 * GET  /api/simulation/:id       \u2014 Retrieve a simulation report by ID
 * GET  /api/simulation/history   \u2014 User's simulation history
 */

import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient } from '../services/supabase';
import { SIMULATION_CREDIT_COST } from '../types/simulation';
import { validateDomainSafety, normalizeDomainInput } from '../utils/url-safety';
import { getDNSRecords } from '../services/audit/cf-rest';

const simulation = new Hono<{ Bindings: Env; Variables: Variables }>();

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Helper: Tolerant CF API fetch
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

async function cfCheckPermission(path: string, token: string): Promise<any | null> {
  try {
    const resp = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    // Clear auth failures
    if (resp.status === 401 || resp.status === 403) return null;
    const text = await resp.text();
    try {
      const json = JSON.parse(text);
      if (json.success === false) {
        // Check for ANY auth-related error (not just code 10000)
        const hasAuthError = (json.errors || []).some((e: any) => {
          const code = e.code;
          const msg = (e.message || '').toLowerCase();
          // Code 10000 = generic auth error
          // Code 6003/6103 = invalid access token
          // Code 7003 = missing permission
          // Also check message patterns
          return (
            code === 10000 || code === 6003 || code === 6103 || code === 7003 ||
            /auth|unauthorized|forbidden|not authorized|permission|token/i.test(msg)
          );
        });
        return hasAuthError ? null : json;
      }
      return json;
    } catch {
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
    return json?.data?.viewer?.zones?.[0] ? json : null;
  } catch {
    return null;
  }
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /pre-check \u2014 Token Permission Pre-Check (NO credit charge)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

simulation.post('/pre-check', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const body = await c.req.json<{
    zone_id?: string;
    api_token?: string;
    account_id?: string;
  }>().catch(() => ({}));

  const { zone_id: zoneId, api_token: apiToken, account_id: accountId = '' } = body;

  if (!zoneId || !apiToken) {
    return c.json({ error: 'Missing required fields: zone_id, api_token' }, 400);
  }

  if (!/^[a-f0-9]{32}$/.test(zoneId)) {
    return c.json({ error: 'Invalid Zone ID format.' }, 400);
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

  // Verify zone + get info + auto-detect Cloudflare Account ID
  let zoneName = zoneId;
  let cfPlan = 'unknown';
  let zoneValid = false;
  let detectedCfAccountId = '';
  const zoneResult = await cfCheckPermission(`/zones/${zoneId}`, apiToken);
  if (zoneResult?.result) {
    zoneName = zoneResult.result.name || zoneId;
    cfPlan = zoneResult.result.plan?.name || 'unknown';
    zoneValid = true;
    // Auto-detect the Cloudflare Account ID from zone info
    detectedCfAccountId = zoneResult.result.account?.id || '';
  }

  // Use auto-detected CF Account ID (preferred) or user-provided one as fallback
  const cfAccountId = detectedCfAccountId || accountId;

  // Discover all 10 token permissions (same as audit/compliance)
  const permChecks: { name: string; test: Promise<any | null> }[] = [
    { name: 'Zone:Read', test: Promise.resolve(zoneResult) },
    { name: 'Analytics:Read', test: cfFetchGraphQLAnalytics(zoneId, apiToken) },
    { name: 'Firewall Services:Read', test: cfCheckPermission(`/zones/${zoneId}/firewall/access_rules/rules?per_page=1`, apiToken) },
    { name: 'DNS:Read', test: cfCheckPermission(`/zones/${zoneId}/dns_records?per_page=1`, apiToken) },
    { name: 'SSL and Certificates:Read', test: cfCheckPermission(`/zones/${zoneId}/ssl/certificate_packs?per_page=1`, apiToken) },
    { name: 'Logs:Read', test: cfCheckPermission(`/zones/${zoneId}/logs/received?start=2024-01-01T00:00:00Z&end=2024-01-01T00:01:00Z&count=1`, apiToken) },
    { name: 'Page Shield:Read', test: cfCheckPermission(`/zones/${zoneId}/page_shield/scripts?per_page=1`, apiToken) },
    { name: 'Health Checks:Read', test: cfCheckPermission(`/zones/${zoneId}/healthchecks`, apiToken) },
    // Account-scoped: always check if we have a CF account ID (auto-detected or provided)
    ...(cfAccountId ? [
      { name: 'Account Access: Audit Logs', test: cfCheckPermission(`/accounts/${cfAccountId}/audit_logs?per_page=1`, apiToken) },
      { name: 'Notifications:Read', test: cfCheckPermission(`/accounts/${cfAccountId}/alerting/v3/policies`, apiToken) },
    ] : []),
  ];

  const results = await Promise.all(permChecks.map(async (p) => ({ name: p.name, ok: (await p.test) !== null })));

  const permissions = {
    available: results.filter((r) => r.ok).map((r) => r.name),
    missing: results.filter((r) => !r.ok).map((r) => r.name),
  };
  // Zone:Read is checked via zoneResult already resolved above
  if (zoneValid && !permissions.available.includes('Zone:Read')) permissions.available.unshift('Zone:Read');

  const requiredPerms = ['Zone:Read', 'Firewall Services:Read'];
  const optionalPerms = ['DNS:Read', 'Analytics:Read', 'SSL and Certificates:Read', 'Logs:Read', 'Page Shield:Read', 'Health Checks:Read', 'Account Access: Audit Logs', 'Notifications:Read'];
  const missingRequired = requiredPerms.filter((p) => !permissions.available.includes(p));
  const missingOptional = optionalPerms.filter((p) => permissions.missing.includes(p));
  const canRun = missingRequired.length === 0;

  // Check domain reachability
  let domainReachable = false;
  try {
    const domainCheck = await fetch(`https://${zoneName}/`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(5000),
    });
    domainReachable = domainCheck.status < 600;
  } catch {
    domainReachable = false;
  }

  const creditCost = SIMULATION_CREDIT_COST;
  const insufficientCredits = account.credit_balance < creditCost;

  return c.json({
    can_run: canRun && !insufficientCredits,
    zone_info: {
      zone_id: zoneId,
      zone_name: zoneName,
      cf_plan: cfPlan,
      zone_valid: zoneValid,
      domain_reachable: domainReachable,
      cf_account_id: detectedCfAccountId || null,
    },
    permissions: {
      available: permissions.available,
      missing: permissions.missing,
      required: requiredPerms,
      optional: optionalPerms,
      missing_required: missingRequired,
      missing_optional: missingOptional,
    },
    credits: {
      required: creditCost,
      available: account.credit_balance,
      sufficient: !insufficientCredits,
    },
    blocked_reasons: [
      ...(missingRequired.length > 0 ? [`Missing required permissions: ${missingRequired.join(', ')}`] : []),
      ...(insufficientCredits ? [`Insufficient credits (need ${creditCost}, have ${account.credit_balance})`] : []),
      ...(!zoneValid ? ['Zone ID not found or token has no Zone:Read permission'] : []),
    ],
  });
});

// ════════════════════════════════════════════════════════════════════
// GET /targets — Discover Proxied Domains for Target Selection (NO credit charge)
// ════════════════════════════════════════════════════════════════════

simulation.get('/targets', async (c) => {
  const zoneId = c.req.query('zone_id');
  const apiToken = c.req.query('api_token');

  if (!zoneId || !apiToken) {
    return c.json({ error: 'Missing required query params: zone_id, api_token' }, 400);
  }

  try {
    // Fetch all DNS records from the zone
    const allRecords = await getDNSRecords(zoneId, apiToken);

    // Filter to only A, AAAA, CNAME records that are proxied (orange cloud)
    const relevantTypes = ['A', 'AAAA', 'CNAME'];
    const proxiedDomains = allRecords
      .filter((r) => relevantTypes.includes(r.type) && r.proxied)
      .map((r) => ({
        name: r.name,
        type: r.type,
        content: r.content,
        proxied: r.proxied,
      }));

    // Deduplicate by name (some zones may have multiple A records for same domain)
    const uniqueDomains = Array.from(
      new Map(proxiedDomains.map((d) => [d.name, d])).values(),
    );

    // Sort: apex first, then alphabetically
    const apexDomain = uniqueDomains.find((d) => !d.name.includes('.', d.name.indexOf('.') + 1));
    const subdomains = uniqueDomains.filter((d) => d !== apexDomain).sort((a, b) => a.name.localeCompare(b.name));
    const sorted = apexDomain ? [apexDomain, ...subdomains] : subdomains;

    return c.json({
      success: true,
      zone_id: zoneId,
      total_proxied: sorted.length,
      domains: sorted.map((d) => ({
        name: d.name,
        type: d.type,
        is_apex: d === apexDomain,
      })),
    });
  } catch (error: any) {
    console.error('[GET /targets] Error:', error);
    return c.json({
      error: 'Failed to fetch DNS records',
      details: error?.message || 'Unknown error',
    }, 500);
  }
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// POST /start \u2014 Run Attack Simulation
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

simulation.post('/start', async (c) => {
  const userId = c.get('userId');

  const body = await c.req.json<{
    zone_id?: string;
    api_token?: string;
    account_id?: string;
    domain?: string;
    domains?: string[];  // Multi-target support
  }>().catch(() => ({}));

  const { zone_id, api_token, account_id, domain, domains } = body;

  // Validate inputs (account_id optional — auto-detected from zone info)
  if (!zone_id || !api_token) {
    return c.json({ error: 'Missing required fields: zone_id, api_token' }, 400);
  }

  // Zone ID format validation (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(zone_id)) {
    return c.json({ error: 'Invalid Zone ID format. Expected a 32-character hexadecimal string.' }, 400);
  }

  // API token basic validation
  if (api_token.length < 20 || /\s/.test(api_token)) {
    return c.json({ error: 'Invalid API token format.' }, 400);
  }

  const creditCost = SIMULATION_CREDIT_COST;
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
      message: `Attack Simulation requires ${creditCost} credits. Your balance: ${account.credit_balance}.`,
      creditCost,
      currentBalance: account.credit_balance,
    }, 402);
  }

  // Deduct credits BEFORE running the simulation
  const { error: deductError } = await admin.rpc('deduct_security_credits', {
    p_account_id: account.id,
    p_amount: creditCost,
    p_description: `Attack Simulation: Zone ${zone_id}`,
    p_report_id: null,
  });

  if (deductError) {
    console.error('Credit deduction failed:', deductError);
    return c.json({ error: 'Failed to deduct credits. Please try again.' }, 500);
  }

  // Resolve zone_id to domain name AND auto-detect CF Account ID
  // so even failed reports display the real domain name
  let resolvedDomain: string = zone_id;
  let resolvedCfAccountId: string = account_id;
  try {
    const zoneInfo = await cfCheckPermission(`/zones/${zone_id}`, api_token);
    if (zoneInfo?.result?.name) {
      resolvedDomain = zoneInfo.result.name;
    }
    // Auto-detect Cloudflare Account ID from zone info
    if (zoneInfo?.result?.account?.id) {
      resolvedCfAccountId = zoneInfo.result.account.id;
    }
  } catch {
    // Fall back to zone_id if resolution fails
  }

  // SSRF protection: if user provided a domain, validate it
  if (domain) {
    const cleanDomain = normalizeDomainInput(domain);
    const safetyCheck = await validateDomainSafety(cleanDomain);
    if (!safetyCheck.safe) {
      console.error(`SSRF blocked: ${cleanDomain} - ${safetyCheck.reason}`);
      // Refund credits
      await admin.rpc('add_security_credits', {
        p_account_id: account.id,
        p_amount: creditCost,
        p_description: 'Refund: invalid domain',
        p_report_id: null,
      });
      return c.json({ error: 'Domain not accessible' }, 400);
    }
  }

  // Multi-target validation: validate domains array if provided
  let validatedDomains: string[] | undefined;
  if (domains && Array.isArray(domains)) {
    if (domains.length === 0) {
      return c.json({ error: 'domains array cannot be empty' }, 400);
    }
    if (domains.length > 5) {
      return c.json({ error: 'Maximum 5 targets allowed per simulation' }, 400);
    }
    
    // Validate each domain with SSRF protection
    for (const dom of domains) {
      const cleanDom = normalizeDomainInput(dom);
      const safetyCheck = await validateDomainSafety(cleanDom);
      if (!safetyCheck.safe) {
        console.error(`SSRF blocked domain in array: ${cleanDom} - ${safetyCheck.reason}`);
        // Refund credits
        await admin.rpc('add_security_credits', {
          p_account_id: account.id,
          p_amount: creditCost,
          p_description: 'Refund: invalid domain in targets',
          p_report_id: null,
        });
        return c.json({ error: `Domain not accessible: ${dom}` }, 400);
      }
    }
    validatedDomains = domains;
  }

  // Create report record (status: running)
  const { data: report, error: insertError } = await admin
    .from('security_reports')
    .insert({
      account_id: account.id,
      domain: resolvedDomain,
      report_type: 'simulation',
      status: 'running',
      credits_charged: creditCost,
    })
    .select('id')
    .single();

  if (insertError || !report) {
    console.error('Failed to create report:', insertError);
    // Refund credits
    await admin.rpc('add_security_credits', {
      p_account_id: account.id,
      p_amount: creditCost,
      p_description: 'Refund: failed to start Attack Simulation',
      p_report_id: null,
    });
    return c.json({ error: 'Failed to start simulation' }, 500);
  }

  // Link the credit transaction to the report
  await admin
    .from('security_credit_transactions')
    .update({ report_id: report.id })
    .eq('account_id', account.id)
    .is('report_id', null)
    .order('created_at', { ascending: false })
    .limit(1);

  // ================================================================
  // WORKFLOW ARCHITECTURE: Trigger durable multi-step simulation
  // ================================================================
  // Each phase runs as a separate Workflow step with its own 30s CPU
  // budget, solving the waitUntil() timeout that caused 100% failure.
  // The Workflow handles: Phase 1-3 execution, report assembly, DB
  // persist, and credit refund on failure -- all durably.
  // ================================================================

  try {
    await c.env.SIMULATION_WORKFLOW.create({
      id: report.id,
      params: {
        zoneId: zone_id,
        apiToken: api_token,
        accountId: resolvedCfAccountId,
        domain: domain || resolvedDomain,
        domains: validatedDomains,  // Multi-target support (optional)
        reportId: report.id,
        supabaseAccountId: account.id,
        creditCost,
      },
    });

    console.log(`[SIM ${report.id}] Workflow instance created successfully.`);
  } catch (wfErr: any) {
    console.error(`[SIM ${report.id}] Failed to create workflow:`, wfErr?.message || wfErr);

    // Workflow creation failed -- refund credits and mark report failed
    await Promise.all([
      admin
        .from('security_reports')
        .update({
          status: 'failed',
          credits_charged: 0,
          data: { error: 'Failed to start simulation workflow' },
        })
        .eq('id', report.id),
      admin.rpc('add_security_credits', {
        p_account_id: account.id,
        p_amount: creditCost,
        p_description: 'Refund: Simulation workflow failed to start',
        p_report_id: report.id,
      }),
    ]);

    return c.json({ error: 'Failed to start simulation. Credits refunded.' }, 500);
  }

  // Return IMMEDIATELY with the report ID. Frontend will poll GET /:id for status.
  const targetCount = validatedDomains?.length || 1;
  const estimatedTests = 76 + (Math.min(targetCount - 1, 5) * 15); // apex (76) + subs (15 each)
  
  return c.json({
    success: true,
    report_id: report.id,
    status: 'running',
    credits_charged: creditCost,
    new_balance: account.credit_balance - creditCost,
    targets: targetCount,
    estimated_tests: estimatedTests,
    message: `Simulation started${targetCount > 1 ? ` (${targetCount} targets, ~${estimatedTests} tests)` : ''}. Poll GET /api/simulation/:id for results.`,
  });
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /history \u2014 Simulation History
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

simulation.get('/history', async (c) => {
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
    .eq('report_type', 'simulation')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  // Extract key fields from JSONB data, strip heavy data field
  // If domain is still a 32-char hex zone_id, try to recover real domain from JSONB
  const reports = (rawReports || []).map((r: any) => {
    let domain = r.domain;
    const isZoneIdAsDomain = /^[a-f0-9]{32}$/.test(domain);
    if (isZoneIdAsDomain) {
      // Try to recover from JSONB: zone_name or domain fields
      domain = r.data?.zone_name || r.data?.domain || domain;
    }
    return {
    id: r.id,
    domain,
    report_type: r.report_type,
    zone_id: r.data?.zone_id || (isZoneIdAsDomain ? r.domain : null),
    score: r.score,
    grade: r.grade,
    risk_level: r.data?.risk_level || null,
    total_tests: r.data?.summary?.total_tests || 0,
    bypassed: r.data?.summary?.bypassed || 0,
    findings_count: r.data?.findings?.length || 0,
    duration_ms: r.data?.duration_ms || 0,
    status: r.status,
    credits_charged: r.credits_charged,
    created_at: r.created_at,
    completed_at: r.completed_at,
  };
  });

  if (error) {
    console.error('Failed to fetch simulation history:', error);
    return c.json({ error: 'Failed to fetch simulation history' }, 500);
  }

  return c.json({
    reports,
    total: count || 0,
    limit,
    offset,
  });
});

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GET /:id \u2014 Retrieve Simulation Report
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

simulation.get('/:id', async (c) => {
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

  // ================================================================
  // WORKFLOW STATUS CHECK: If report is still "running", check the
  // Workflow instance. The Workflow returns the report as its output
  // (to avoid subrequest limits), so we persist it here on first poll.
  // ================================================================
  if (report.status === 'running') {
    try {
      const instance = await c.env.SIMULATION_WORKFLOW.get(reportId);
      const wfStatus = await instance.status();

      if (wfStatus.status === 'complete' && wfStatus.output) {
        // Workflow completed! Save the report to DB.
        const simulationReport = wfStatus.output as any;
        console.log(`[SIM ${reportId}] Workflow complete. Persisting report (Score: ${simulationReport.overall_score})`);

        await admin
          .from('security_reports')
          .update({
            domain: simulationReport.zone_name || report.domain,
            status: 'completed',
            score: simulationReport.overall_score,
            grade: simulationReport.overall_grade,
            data: simulationReport,
            completed_at: new Date().toISOString(),
          })
          .eq('id', reportId);

        // Return the completed report
        return c.json({
          report: {
            ...report,
            status: 'completed',
            score: simulationReport.overall_score,
            grade: simulationReport.overall_grade,
            data: simulationReport,
            completed_at: new Date().toISOString(),
          },
        });
      }

      if (wfStatus.status === 'errored') {
        // Workflow failed -- mark report as failed and refund credits
        const errMsg = wfStatus.error?.message || 'Simulation workflow failed';
        console.log(`[SIM ${reportId}] Workflow errored: ${errMsg}. Cleaning up.`);

        await Promise.all([
          admin
            .from('security_reports')
            .update({
              status: 'failed',
              credits_charged: 0,
              completed_at: new Date().toISOString(),
              data: { error: errMsg },
            })
            .eq('id', reportId),
          admin.rpc('add_security_credits', {
            p_account_id: account.id,
            p_amount: report.credits_charged || SIMULATION_CREDIT_COST,
            p_description: 'Refund: Attack Simulation failed',
            p_payment_id: null,
          }),
        ]);

        return c.json({
          report: {
            ...report,
            status: 'failed',
            credits_charged: 0,
            data: { error: errMsg },
          },
        });
      }

      // Workflow still running/queued/waiting -- return current DB state
      // (status: running)
    } catch (wfErr: any) {
      // Workflow lookup failed (instance might not exist yet or API error).
      // Fall through to the stale-report check below.
      console.log(`[SIM ${reportId}] Workflow status check failed: ${wfErr?.message}`);
    }

    // Fallback: stale-report cleanup (>10 min running, workflow unreachable)
    const createdAt = new Date(report.created_at);
    const now = new Date();
    const ageMinutes = (now.getTime() - createdAt.getTime()) / 60000;

    if (ageMinutes > 10) {
      console.log(`[SIM ${reportId}] Stale running report detected (${ageMinutes.toFixed(1)} min old), marking as failed`);
      
      await Promise.all([
        admin
          .from('security_reports')
          .update({
            status: 'failed',
            credits_charged: 0,
            completed_at: new Date().toISOString(),
            data: {
              error: 'Simulation timed out (stuck in running state for >10 minutes)',
              zone_name: report.domain || 'unknown',
            },
          })
          .eq('id', reportId),
        admin.rpc('add_security_credits', {
          p_account_id: account.id,
          p_amount: report.credits_charged || SIMULATION_CREDIT_COST,
          p_description: `Refund: Simulation ${reportId} timed out`,
          p_payment_id: null,
        }),
      ]);

      const { data: updatedReport } = await admin
        .from('security_reports')
        .select('*')
        .eq('id', reportId)
        .single();

      return c.json({ report: updatedReport });
    }
  }

  return c.json({ report });
});

export default simulation;
