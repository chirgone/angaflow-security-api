/**
 * Compliance Routes
 * GET  /api/compliance/pre-check/:audit_id  \u2014 Token pre-check before running compliance
 * POST /api/compliance/run                  \u2014 Execute compliance engine (deducts credits)
 * GET  /api/compliance/:id                  \u2014 Retrieve a compliance report by ID
 * PATCH /api/compliance/checklist           \u2014 Update manual checklist entry
 */

import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { COMPLIANCE_COSTS } from '../types';
import { getAdminClient } from '../services/supabase';
import { discoverTokenPermissions, cfCheckPermission } from '../services/compliance/cf-compliance-collectors';
import { runComplianceEngine } from '../services/compliance/compliance-engine';
import { countControlsLimitedByPermissions } from '../services/compliance/controls';
import type {
  ComplianceFramework,
  ComplianceReport,
  ControlResult,
} from '../types/compliance';
import {
  COMPLIANCE_FRAMEWORKS,
  COMPLIANCE_CREDIT_COSTS,
  FRAMEWORK_INFO,
  calculateDirectComplianceCost,
  getDirectComplianceCostBreakdown,
} from '../types/compliance';
import type { AuditReport, AuditTier } from '../types/audit';
import { collectAuditData } from '../services/audit/collector';
import { CfApiError } from '../services/audit/cf-rest';

const compliance = new Hono<{ Bindings: Env; Variables: Variables }>();

// Minimum audit tier required for compliance
const VALID_AUDIT_TIERS: AuditTier[] = ['pro', 'complete'];

// Staleness threshold in days
const STALENESS_THRESHOLD_DAYS = 7;

// ════════════════════════════════════════════════════════════════════
// POST /pre-check/:audit_id — Token Pre-Check
// ════════════════════════════════════════════════════════════════════

compliance.post('/pre-check/:audit_id', async (c) => {
  const userId = c.get('userId');
  const auditId = c.req.param('audit_id');
  const admin = getAdminClient(c.env);

  // Parse body
  const body = await c.req.json<{
    api_token?: string;
    account_id?: string;
    frameworks?: ComplianceFramework[] | 'bundle';
  }>().catch(() => ({}));

  const { api_token: apiToken, account_id: accountId, frameworks: frameworksInput } = body;

  if (!apiToken || !accountId) {
    return c.json({ error: 'Missing required fields: api_token, account_id' }, 400);
  }

  // Parse frameworks
  let frameworks: ComplianceFramework[];
  if (!frameworksInput || frameworksInput === 'bundle') {
    frameworks = [...COMPLIANCE_FRAMEWORKS];
  } else if (Array.isArray(frameworksInput)) {
    frameworks = frameworksInput;
    const invalid = frameworks.filter((f) => !COMPLIANCE_FRAMEWORKS.includes(f));
    if (invalid.length > 0) {
      return c.json({ error: `Invalid frameworks: ${invalid.join(', ')}` }, 400);
    }
  } else {
    return c.json({ error: 'Invalid frameworks format' }, 400);
  }

  // Get user account
  const { data: account, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !account) {
    return c.json({ error: 'Account not found. Please set up your account first.' }, 404);
  }

  // Load source audit report
  const { data: auditReport, error: auditError } = await admin
    .from('security_reports')
    .select('id, data, status, report_type, account_id, created_at')
    .eq('id', auditId)
    .eq('account_id', account.id)
    .single();

  if (auditError || !auditReport) {
    return c.json({ error: 'Source audit report not found or does not belong to your account.' }, 404);
  }

  if (auditReport.report_type !== 'audit') {
    return c.json({ error: 'The specified report is not an audit report.' }, 400);
  }

  if (auditReport.status !== 'completed') {
    return c.json({ error: 'Source audit is not completed. Only completed audits can be used for compliance.' }, 400);
  }

  const auditData = auditReport.data as AuditReport;
  if (!auditData || !auditData.tier) {
    return c.json({ error: 'Source audit report data is missing or corrupt.' }, 400);
  }

  // Validate audit tier (must be Pro or Complete)
  if (!VALID_AUDIT_TIERS.includes(auditData.tier)) {
    return c.json({
      error: 'Insufficient audit tier',
      message: `Compliance requires a Pro or Complete audit. This audit is "${auditData.tier}". Please upgrade your audit first.`,
    }, 400);
  }

  // Calculate audit age
  const auditDate = new Date(auditReport.created_at);
  const ageDays = Math.floor((Date.now() - auditDate.getTime()) / (1000 * 60 * 60 * 24));
  const isStale = ageDays > STALENESS_THRESHOLD_DAYS;

  // Extract zone info from audit
  const zoneId = auditData.zone_id;
  const zoneName = auditData.zone_name;

  // ✅ CRITICAL: Validate token has permission for the audit's zone
  const zonePermissionCheck = await cfCheckPermission(`/zones/${zoneId}`, apiToken);
  if (!zonePermissionCheck) {
    return c.json({
      error: 'Token permission mismatch',
      message: `El token proporcionado no tiene permisos para la zona "${zoneName}" (${zoneId}). Este audit fue creado para esa zona. Por favor proporciona un token con permisos Zone:Read para esa zona, o selecciona un audit de una zona diferente.`,
      details: {
        audit_zone_id: zoneId,
        audit_zone_name: zoneName,
        audit_id: auditId,
        suggestion: 'Verifica que tu token tenga el permiso "Zone:Read" para esta zona específica.',
      },
    }, 403);
  }

  // Discover all token permissions
  const tokenPermissions = await discoverTokenPermissions(zoneId, accountId, apiToken);

  // Calculate controls limited by missing permissions
  const controlsLimited = countControlsLimitedByPermissions(frameworks, tokenPermissions.available);

  // Calculate credit cost
  const isBundle = frameworks.length === COMPLIANCE_FRAMEWORKS.length;
  let creditsRequired: number;
  if (isBundle) {
    creditsRequired = COMPLIANCE_CREDIT_COSTS.bundle;
  } else {
    creditsRequired = frameworks.reduce((sum, fw) => sum + COMPLIANCE_CREDIT_COSTS[fw], 0);
  }

  const insufficientCredits = account.credit_balance < creditsRequired;

  return c.json({
    can_run: !insufficientCredits,
    source_audit: {
      id: auditReport.id,
      tier: auditData.tier,
      zone_name: auditData.zone_name,
      age_days: ageDays,
      is_stale: isStale,
    },
    token_permissions: {
      available: tokenPermissions.available,
      missing: tokenPermissions.missing,
      controls_limited: controlsLimited,
    },
    credits_required: creditsRequired,
    credits_available: account.credit_balance,
    insufficient_credits: insufficientCredits,
  });
});

// ════════════════════════════════════════════════════════════════════
// POST /pre-check-direct — Validate Direct Compliance (No Audit Source)
// ════════════════════════════════════════════════════════════════════

compliance.post('/pre-check-direct', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  // Parse body
  const body = await c.req.json<{
    zone_id?: string;
    api_token?: string;
    account_id?: string;
    tier?: 'pro' | 'complete';
    frameworks?: ComplianceFramework[] | 'bundle' | 'bundle_8';
  }>().catch(() => ({}));

  const { zone_id: zoneId, api_token: apiToken, account_id: accountId, tier, frameworks: frameworksInput } = body;

  // Validate required fields
  if (!zoneId || !apiToken || !accountId || !tier) {
    return c.json({
      error: 'Missing required fields: zone_id, api_token, account_id, tier',
    }, 400);
  }

  // Validate zone ID format (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(zoneId)) {
    return c.json({
      error: 'Invalid Zone ID format. Expected a 32-character hexadecimal string.',
    }, 400);
  }

  // Validate API token
  if (apiToken.length < 20 || /\s/.test(apiToken)) {
    return c.json({ error: 'Invalid API token format.' }, 400);
  }

  // Validate account ID format (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(accountId)) {
    return c.json({
      error: 'Invalid Account ID format. Expected a 32-character hexadecimal string.',
    }, 400);
  }

  // Validate tier (only pro and complete supported for compliance)
  if (!['pro', 'complete'].includes(tier)) {
    return c.json({
      error: 'Invalid tier. Must be "pro" or "complete". Basic tier does not have sufficient data for compliance.',
    }, 400);
  }

  // Parse frameworks
  let frameworks: ComplianceFramework[];
  if (!frameworksInput || frameworksInput === 'bundle') {
    frameworks = COMPLIANCE_FRAMEWORKS.slice(0, 5); // Original 5-framework bundle
  } else if (frameworksInput === 'bundle_8') {
    frameworks = [...COMPLIANCE_FRAMEWORKS]; // All 8 frameworks
  } else if (Array.isArray(frameworksInput)) {
    frameworks = frameworksInput;
    const invalid = frameworks.filter((f) => !COMPLIANCE_FRAMEWORKS.includes(f));
    if (invalid.length > 0) {
      return c.json({ error: `Invalid frameworks: ${invalid.join(', ')}` }, 400);
    }
  } else {
    return c.json({ error: 'Invalid frameworks format' }, 400);
  }

  // Get user account
  const { data: account, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !account) {
    return c.json({ error: 'Account not found. Please set up your account first.' }, 404);
  }

  if (account.status === 'suspended') {
    return c.json({ error: 'Account is suspended.' }, 403);
  }

  // Validate token has permission for this zone
  const zonePermissionCheck = await cfCheckPermission(`/zones/${zoneId}`, apiToken);
  if (!zonePermissionCheck) {
    return c.json({
      error: 'Token permission denied',
      message: `El token proporcionado no tiene permisos para la zona ${zoneId}. Por favor verifica que tu token tenga el permiso "Zone:Read" para esta zona.`,
    }, 403);
  }

  // Discover all token permissions
  const tokenPermissions = await discoverTokenPermissions(zoneId, accountId, apiToken);

  // Calculate controls limited by missing permissions
  const controlsLimited = countControlsLimitedByPermissions(frameworks, tokenPermissions.available);

  // Calculate credit cost (with discount)
  const bundleType: 'bundle' | 'bundle_8' | undefined =
    frameworksInput === 'bundle_8' ? 'bundle_8' :
    frameworksInput === 'bundle' || frameworks.length === 5 ? 'bundle' :
    undefined;

  const creditsRequired = calculateDirectComplianceCost(tier, bundleType || frameworks);
  const costBreakdown = getDirectComplianceCostBreakdown(tier, bundleType || frameworks);

  const insufficientCredits = account.credit_balance < creditsRequired;

  return c.json({
    can_run: !insufficientCredits,
    mode: 'direct',
    tier,
    zone_id: zoneId,
    token_permissions: {
      available: tokenPermissions.available,
      missing: tokenPermissions.missing,
      controls_limited: controlsLimited,
    },
    cost_breakdown: {
      audit_tier: costBreakdown.audit_tier,
      audit_cost: costBreakdown.audit_cost,
      frameworks: costBreakdown.frameworks_label,
      compliance_cost: costBreakdown.compliance_cost,
      discount: costBreakdown.discount,
      total: costBreakdown.total,
    },
    credits_required: creditsRequired,
    credits_available: account.credit_balance,
    insufficient_credits: insufficientCredits,
  });
});

// ════════════════════════════════════════════════════════════════════
// POST /run — Execute Compliance Engine
// ════════════════════════════════════════════════════════════════════

compliance.post('/run', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const body: {
    source_audit_id?: string;
    frameworks?: (ComplianceFramework | 'bundle')[];
    zone_id?: string;
    api_token?: string;
    account_id?: string;
  } = await c.req.json().catch(() => ({}));

  const { source_audit_id, zone_id, api_token, account_id } = body;

  // Validate inputs
  if (!source_audit_id || !zone_id || !api_token || !account_id) {
    return c.json({
      error: 'Missing required fields: source_audit_id, zone_id, api_token, account_id',
    }, 400);
  }

  // Zone ID format validation (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(zone_id)) {
    return c.json({ error: 'Invalid Zone ID format. Expected a 32-character hexadecimal string.' }, 400);
  }

  // API token basic validation
  if (api_token.length < 20 || /\s/.test(api_token)) {
    return c.json({ error: 'Invalid API token format.' }, 400);
  }

  // Account ID format validation (32-char hex)
  if (!/^[a-f0-9]{32}$/.test(account_id)) {
    return c.json({ error: 'Invalid Account ID format. Expected a 32-character hexadecimal string.' }, 400);
  }

  // Parse frameworks
  let frameworks: ComplianceFramework[];
  const rawFrameworks = body.frameworks || [];
  if (rawFrameworks.length === 0 || rawFrameworks.includes('bundle')) {
    frameworks = [...COMPLIANCE_FRAMEWORKS];
  } else {
    frameworks = rawFrameworks.filter((f): f is ComplianceFramework =>
      COMPLIANCE_FRAMEWORKS.includes(f as ComplianceFramework),
    );
    if (frameworks.length === 0) {
      return c.json({ error: 'No valid frameworks specified.' }, 400);
    }
  }

  // Get user account
  const { data: userAccount, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !userAccount) {
    return c.json({ error: 'Account not found. Please set up your account first.' }, 404);
  }

  if (userAccount.status === 'suspended') {
    return c.json({ error: 'Account is suspended.' }, 403);
  }

  // Load source audit report
  const { data: auditReport, error: auditError } = await admin
    .from('security_reports')
    .select('id, data, status, report_type, account_id, created_at')
    .eq('id', source_audit_id)
    .eq('account_id', userAccount.id)
    .single();

  if (auditError || !auditReport) {
    return c.json({ error: 'Source audit report not found or does not belong to your account.' }, 404);
  }

  if (auditReport.report_type !== 'audit' || auditReport.status !== 'completed') {
    return c.json({ error: 'Source report must be a completed audit.' }, 400);
  }

  const auditData = auditReport.data as AuditReport;
  if (!auditData || !auditData.tier || !auditData.data) {
    return c.json({ error: 'Source audit report data is missing or corrupt.' }, 400);
  }

  // Validate audit tier
  if (!VALID_AUDIT_TIERS.includes(auditData.tier)) {
    return c.json({
      error: 'Insufficient audit tier',
      message: `Compliance requires a Pro or Complete audit. This audit is "${auditData.tier}".`,
    }, 400);
  }

  // Calculate credit cost
  const isBundle = frameworks.length === COMPLIANCE_FRAMEWORKS.length;
  let creditCost: number;
  if (isBundle) {
    creditCost = COMPLIANCE_CREDIT_COSTS.bundle;
  } else {
    creditCost = frameworks.reduce((sum, fw) => sum + COMPLIANCE_CREDIT_COSTS[fw], 0);
  }

  // Check credit balance
  if (userAccount.credit_balance < creditCost) {
    const fwNames = frameworks.map((fw) => FRAMEWORK_INFO[fw].name).join(', ');
    return c.json({
      error: 'Insufficient credits',
      message: `Compliance for ${fwNames} requires ${creditCost} credits. Your balance: ${userAccount.credit_balance}.`,
      credits_required: creditCost,
      credits_available: userAccount.credit_balance,
      frameworks,
    }, 402);
  }

  // Deduct credits BEFORE running the engine
  const fwLabel = isBundle ? 'Compliance Bundle (all 5 frameworks)' : `Compliance: ${frameworks.map((fw) => FRAMEWORK_INFO[fw].name).join(', ')}`;
  const { error: deductError } = await admin.rpc('deduct_security_credits', {
    p_account_id: userAccount.id,
    p_amount: creditCost,
    p_description: `${fwLabel}: Zone ${zone_id}`,
    p_report_id: null,
  });

  if (deductError) {
    console.error('Credit deduction failed:', deductError);
    return c.json({ error: 'Failed to deduct credits. Please try again.' }, 500);
  }

  // Create compliance report record (status: running)
  const { data: reportRecord, error: insertError } = await admin
    .from('security_reports')
    .insert({
      account_id: userAccount.id,
      domain: auditData.zone_name,
      report_type: 'compliance',
      status: 'running',
      credits_charged: creditCost,
      parent_report_id: source_audit_id,
    })
    .select('id')
    .single();

  if (insertError || !reportRecord) {
    console.error('Failed to create compliance report:', insertError);
    // Refund credits
    await admin.rpc('add_security_credits', {
      p_account_id: userAccount.id,
      p_amount: creditCost,
      p_description: `Refund: failed to start compliance report`,
      p_report_id: null,
    });
    return c.json({ error: 'Failed to start compliance report.' }, 500);
  }

  try {
    // Calculate audit age
    const auditDate = new Date(auditReport.created_at);
    const auditAgeDays = Math.floor((Date.now() - auditDate.getTime()) / (1000 * 60 * 60 * 24));

    // Discover token permissions
    const tokenPerms = await discoverTokenPermissions(zone_id, account_id, api_token);

    // Run the compliance engine
    const complianceReport = await runComplianceEngine({
      audit_data: auditData.data,
      audit_id: source_audit_id,
      audit_tier: auditData.tier,
      zone_name: auditData.zone_name,
      zone_id,
      api_token,
      account_id,
      frameworks,
      available_permissions: tokenPerms.available,
      audit_age_days: auditAgeDays,
      ai: c.env.AI, // Workers AI binding for recommendations
    });

    // Update report with results
    await admin
      .from('security_reports')
      .update({
        status: 'completed',
        score: complianceReport.compliance_score,
        grade: complianceReport.compliance_grade,
        data: complianceReport as any,
        completed_at: new Date().toISOString(),
      })
      .eq('id', reportRecord.id);

    // Link credit transaction to the report
    await admin
      .from('security_credit_transactions')
      .update({ report_id: reportRecord.id })
      .eq('account_id', userAccount.id)
      .is('report_id', null)
      .order('created_at', { ascending: false })
      .limit(1);

    return c.json({
      success: true,
      report_id: reportRecord.id,
      frameworks,
      credits_charged: creditCost,
      report: complianceReport,
    });
  } catch (err: any) {
    console.error('Compliance engine failed:', err);

    // Mark report as failed
    await admin
      .from('security_reports')
      .update({
        status: 'failed',
        data: {
          error: err.message || 'Compliance engine failed',
        },
      })
      .eq('id', reportRecord.id);

    // Refund credits on failure
    await admin.rpc('add_security_credits', {
      p_account_id: userAccount.id,
      p_amount: creditCost,
      p_description: `Refund: compliance report failed`,
      p_report_id: reportRecord.id,
    });

    // Update report to show 0 credits charged (refunded)
    await admin
      .from('security_reports')
      .update({ credits_charged: 0 })
      .eq('id', reportRecord.id);

    return c.json({
      error: 'Compliance engine failed',
      message: `The compliance analysis could not be completed. Credits have been refunded. Error: ${err.message || 'Unknown error'}`,
      report_id: reportRecord.id,
      credits_refunded: creditCost,
    }, 500);
  }
});

// ════════════════════════════════════════════════════════════════════
// POST /run-direct — Execute Direct Compliance (No Audit Source)
// Collects audit data fresh, then runs compliance engine
// ════════════════════════════════════════════════════════════════════

compliance.post('/run-direct', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const body = await c.req.json<{
    zone_id?: string;
    api_token?: string;
    account_id?: string;
    tier?: 'pro' | 'complete';
    frameworks?: ComplianceFramework[] | 'bundle' | 'bundle_8';
  }>().catch(() => ({}));

  const { zone_id: zoneId, api_token: apiToken, account_id: accountId, tier, frameworks: frameworksInput } = body;

  // Validate inputs
  if (!zoneId || !apiToken || !accountId || !tier) {
    return c.json({ error: 'Missing required fields: zone_id, api_token, account_id, tier' }, 400);
  }

  if (!/^[a-f0-9]{32}$/.test(zoneId)) {
    return c.json({ error: 'Invalid Zone ID format.' }, 400);
  }

  if (apiToken.length < 20 || /\s/.test(apiToken)) {
    return c.json({ error: 'Invalid API token format.' }, 400);
  }

  if (!/^[a-f0-9]{32}$/.test(accountId)) {
    return c.json({ error: 'Invalid Account ID format.' }, 400);
  }

  if (!['pro', 'complete'].includes(tier)) {
    return c.json({ error: 'Invalid tier. Must be "pro" or "complete".' }, 400);
  }

  // Parse frameworks
  let frameworks: ComplianceFramework[];
  if (!frameworksInput || frameworksInput === 'bundle') {
    frameworks = COMPLIANCE_FRAMEWORKS.slice(0, 5);
  } else if (frameworksInput === 'bundle_8') {
    frameworks = [...COMPLIANCE_FRAMEWORKS];
  } else if (Array.isArray(frameworksInput)) {
    frameworks = frameworksInput;
    const invalid = frameworks.filter((f) => !COMPLIANCE_FRAMEWORKS.includes(f));
    if (invalid.length > 0) {
      return c.json({ error: `Invalid frameworks: ${invalid.join(', ')}` }, 400);
    }
  } else {
    return c.json({ error: 'Invalid frameworks format' }, 400);
  }

  // Get user account
  const { data: userAccount, error: accountError } = await admin
    .from('security_accounts')
    .select('id, credit_balance, status')
    .eq('user_id', userId)
    .single();

  if (accountError || !userAccount) {
    return c.json({ error: 'Account not found.' }, 404);
  }

  if (userAccount.status === 'suspended') {
    return c.json({ error: 'Account is suspended.' }, 403);
  }

  // Calculate credit cost
  const bundleType: 'bundle' | 'bundle_8' | undefined =
    frameworksInput === 'bundle_8' ? 'bundle_8' :
    frameworksInput === 'bundle' || frameworks.length === 5 ? 'bundle' :
    undefined;

  const creditCost = calculateDirectComplianceCost(tier, bundleType || frameworks);

  // Check sufficient credits
  if (userAccount.credit_balance < creditCost) {
    const costBreakdown = getDirectComplianceCostBreakdown(tier, bundleType || frameworks);
    return c.json({
      error: 'Insufficient credits',
      message: `Direct compliance (${costBreakdown.audit_tier} + ${costBreakdown.frameworks_label}) requires ${creditCost} credits. Your balance: ${userAccount.credit_balance}.`,
      credits_required: creditCost,
      credits_available: userAccount.credit_balance,
    }, 402);
  }

  // Deduct credits
  const { error: deductError } = await admin.rpc('deduct_security_credits', {
    p_account_id: userAccount.id,
    p_amount: creditCost,
    p_description: `Direct Compliance: ${tier} + ${frameworks.length} framework(s)`,
    p_report_id: null,
  });

  if (deductError) {
    console.error('Credit deduction failed:', deductError);
    return c.json({ error: 'Failed to deduct credits.' }, 500);
  }

  // Create report record (status: running)
  const { data: report, error: insertError } = await admin
    .from('security_reports')
    .insert({
      account_id: userAccount.id,
      domain: zoneId, // Will be updated with zone_name later
      report_type: 'compliance',
      status: 'running',
      credits_charged: creditCost,
    })
    .select('id')
    .single();

  if (insertError || !report) {
    console.error('Failed to create report:', insertError);
    // Refund credits
    await admin.rpc('add_security_credits', {
      p_account_id: userAccount.id,
      p_amount: creditCost,
      p_description: `Refund: Direct compliance failed to start`,
      p_report_id: null,
    });
    return c.json({ error: 'Failed to start compliance.' }, 500);
  }

  try {
    // ══════════════════════════════════════════════════════════════
    // Step 1: Collect Audit Data (fresh)
    // ══════════════════════════════════════════════════════════════
    const auditTier: AuditTier = tier;
    const collectionResult = await collectAuditData(zoneId, apiToken, auditTier);
    const zoneName = collectionResult.data.zone_info.name;

    // Update domain with actual zone name
    await admin
      .from('security_reports')
      .update({ domain: zoneName })
      .eq('id', report.id);

    // ══════════════════════════════════════════════════════════════
    // Step 2: Discover Token Permissions
    // ══════════════════════════════════════════════════════════════
    const tokenPermissions = await discoverTokenPermissions(zoneId, accountId, apiToken);

    // ══════════════════════════════════════════════════════════════
    // Step 3: Run Compliance Engine
    // ══════════════════════════════════════════════════════════════
    const complianceReport = await runComplianceEngine({
      audit_data: collectionResult.data,
      audit_id: report.id, // Use compliance report ID as audit_id
      audit_tier: auditTier,
      zone_name: zoneName,
      zone_id: zoneId,
      api_token: apiToken,
      account_id: accountId,
      frameworks,
      available_permissions: tokenPermissions.available,
      audit_age_days: 0, // Fresh data
      ai: c.env.AI, // Workers AI binding for recommendations
    });

    // ══════════════════════════════════════════════════════════════
    // Step 4: Save Compliance Report
    // ══════════════════════════════════════════════════════════════
    await admin
      .from('security_reports')
      .update({
        status: 'completed',
        score: complianceReport.compliance_score,
        grade: complianceReport.compliance_grade,
        data: complianceReport as any,
        completed_at: new Date().toISOString(),
      })
      .eq('id', report.id);

    // Link credit transaction to report
    await admin
      .from('security_credit_transactions')
      .update({ report_id: report.id })
      .eq('account_id', userAccount.id)
      .is('report_id', null)
      .order('created_at', { ascending: false })
      .limit(1);

    return c.json({
      success: true,
      report_id: report.id,
      mode: 'direct',
      tier: auditTier,
      frameworks: complianceReport.frameworks,
      credits_charged: creditCost,
      report: complianceReport,
    });

  } catch (err: any) {
    console.error('Direct compliance failed:', err);

    const isCfAuth = err instanceof CfApiError && err.isAuthError;

    // Mark report as failed
    await admin
      .from('security_reports')
      .update({
        status: 'failed',
        data: {
          error: err.message || 'Direct compliance failed',
          is_auth_error: isCfAuth,
          mode: 'direct',
          tier,
        },
      })
      .eq('id', report.id);

    // Refund credits
    await admin.rpc('add_security_credits', {
      p_account_id: userAccount.id,
      p_amount: creditCost,
      p_description: `Refund: Direct compliance failed`,
      p_report_id: report.id,
    });

    // Zero out charged credits
    await admin
      .from('security_reports')
      .update({ credits_charged: 0 })
      .eq('id', report.id);

    return c.json({
      error: isCfAuth ? 'Cloudflare authentication error' : 'Compliance execution failed',
      message: err.message || 'An unexpected error occurred during compliance execution.',
      report_id: report.id,
      credits_refunded: creditCost,
    }, isCfAuth ? 401 : 500);
  }
});

// ════════════════════════════════════════════════════════════════════
// GET /history — User's compliance report history
// ════════════════════════════════════════════════════════════════════

compliance.get('/history', async (c) => {
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

  const { data: reports, error, count } = await admin
    .from('security_reports')
    .select('id, domain, report_type, score, grade, status, credits_charged, created_at, completed_at, parent_report_id, data', {
      count: 'exact',
    })
    .eq('account_id', account.id)
    .eq('report_type', 'compliance')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    console.error('Failed to fetch compliance history:', error);
    return c.json({ error: 'Failed to fetch compliance history' }, 500);
  }

  // Extract framework list and type from JSONB for display without sending full data
  const enriched = (reports || []).map((r: any) => {
    const d = r.data;
    const frameworks: string[] = d?.frameworks || [];
    const type: string = d?.is_bundle ? 'bundle' : 'individual';
    const frameworkScores: Record<string, { score: number; grade: string }> = {};
    if (Array.isArray(d?.framework_results)) {
      for (const fr of d.framework_results) {
        frameworkScores[fr.framework] = { score: fr.framework_score ?? 0, grade: fr.framework_grade ?? '?' };
      }
    }
    // Remove full data to keep response light
    const { data: _omit, ...rest } = r;
    return { ...rest, frameworks, type, framework_scores: frameworkScores };
  });

  return c.json({
    reports: enriched,
    total: count || 0,
    limit,
    offset,
  });
});

// ════════════════════════════════════════════════════════════════════
// GET /:id — Retrieve a compliance report
// ════════════════════════════════════════════════════════════════════

compliance.get('/:id', async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('id');
  const admin = getAdminClient(c.env);

  // Get user account
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
    .eq('report_type', 'compliance')
    .single();

  if (error || !report) {
    return c.json({ error: 'Compliance report not found' }, 404);
  }

  return c.json({ report });
});

// ════════════════════════════════════════════════════════════════════
// PATCH /checklist \u2014 Update manual checklist entry
// ════════════════════════════════════════════════════════════════════

compliance.patch('/checklist', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);

  const body: {
    report_id?: string;
    control_id?: string;
    framework?: ComplianceFramework;
    verified?: boolean;
    notes?: string;
  } = await c.req.json().catch(() => ({}));

  const { report_id, control_id, framework, verified, notes } = body;

  if (!report_id || !control_id || !framework || verified === undefined) {
    return c.json({
      error: 'Missing required fields: report_id, control_id, framework, verified',
    }, 400);
  }

  if (!COMPLIANCE_FRAMEWORKS.includes(framework)) {
    return c.json({ error: `Invalid framework: ${framework}` }, 400);
  }

  // Get user account
  const { data: account } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // Load the compliance report
  const { data: report, error: fetchError } = await admin
    .from('security_reports')
    .select('id, data, report_type, account_id')
    .eq('id', report_id)
    .eq('account_id', account.id)
    .eq('report_type', 'compliance')
    .single();

  if (fetchError || !report) {
    return c.json({ error: 'Compliance report not found' }, 404);
  }

  const reportData = report.data as ComplianceReport;
  if (!reportData || !reportData.framework_results) {
    return c.json({ error: 'Report data is missing or corrupt.' }, 400);
  }

  // Find the target framework result
  const fwResult = reportData.framework_results.find((fr) => fr.framework === framework);
  if (!fwResult) {
    return c.json({ error: `Framework "${framework}" not found in this compliance report.` }, 404);
  }

  // Find the target control within framework sections
  let controlFound = false;
  for (const section of fwResult.sections) {
    for (const ctrl of section.controls) {
      if (ctrl.control_id === control_id) {
        ctrl.manual_checklist = {
          verified,
          verified_by: userId,
          verified_at: new Date().toISOString(),
          notes: notes || ctrl.manual_checklist?.notes,
        };
        controlFound = true;
        break;
      }
    }
    if (controlFound) break;
  }

  if (!controlFound) {
    return c.json({
      error: `Control "${control_id}" not found in framework "${framework}".`,
    }, 404);
  }

  // Update the report data in the database
  const { error: updateError } = await admin
    .from('security_reports')
    .update({ data: reportData as any })
    .eq('id', report_id);

  if (updateError) {
    console.error('Failed to update manual checklist:', updateError);
    return c.json({ error: 'Failed to update checklist.' }, 500);
  }

  return c.json({
    success: true,
    control_id,
    framework,
    manual_checklist: {
      verified,
      verified_by: userId,
      verified_at: new Date().toISOString(),
      notes: notes || undefined,
    },
  });
});

export default compliance;
