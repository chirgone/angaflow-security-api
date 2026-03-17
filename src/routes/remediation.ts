/**
 * Anga AutoFix - Remediation Routes
 * 
 * POST /api/remediation/preview      - Preview available remediation actions (free)
 * POST /api/remediation/execute      - Execute remediation actions (charges credits)
 * GET  /api/remediation/history      - Get remediation execution history
 */

import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient } from '../services/supabase';
import { discoverTokenPermissions } from '../services/compliance/cf-compliance-collectors';
import { previewRemediation, executeRemediation, generateRemediationActions } from '../services/remediation/remediation-engine';
import { detectPlanTier } from '../types/audit';
import type { CloudflarePlanTier } from '../types/audit';
import type { ControlResult, ComplianceReport } from '../types/compliance';
import { REMEDIATION_CREDIT_COST, MAX_ACTIONS_PER_BATCH } from '../types/remediation';

const remediation = new Hono<{ Bindings: Env; Variables: Variables }>();

// ══════════════════════════════════════════════════════════════════
// POST /preview - Preview available remediation actions
// ══════════════════════════════════════════════════════════════════

remediation.post('/preview', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);
  
  // Parse request
  const body = await c.req.json<{
    report_id?: string;
    zone_id?: string;
    api_token?: string;
  }>();
  
  const { report_id, zone_id, api_token } = body;
  
  if (!report_id) {
    return c.json({ error: 'Missing report_id' }, 400);
  }
  
  // Fetch compliance report
  const { data: reportRecord, error: reportError } = await admin
    .from('security_reports')
    .select('id, account_id, domain, data, status')
    .eq('id', report_id)
    .eq('report_type', 'compliance')
    .single();
  
  if (reportError || !reportRecord) {
    return c.json({ error: 'Compliance report not found' }, 404);
  }
  
  // Verify user owns this report
  const { data: userAccount } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .eq('id', reportRecord.account_id)
    .single();
  
  if (!userAccount) {
    return c.json({ error: 'Unauthorized' }, 403);
  }
  
  const complianceReport = reportRecord.data as ComplianceReport;
  
  // Extract all controls from the report
  const allControls: ControlResult[] = [];
  for (const fw of complianceReport.framework_results || []) {
    for (const section of fw.sections || []) {
      allControls.push(...section.controls);
    }
  }
  
  // Use provided token or require one
  const token = api_token;
  if (!token) {
    return c.json({ error: 'API token required for remediation preview' }, 400);
  }
  
  // Discover token permissions
  const zoneId = zone_id || complianceReport.zone_id;
  const accountId = complianceReport.zone_id ? undefined : undefined; // TODO: Get from report
  const tokenPerms = await discoverTokenPermissions(zoneId, accountId || '', token);
  
  // Generate preview
  const preview = await previewRemediation(
    allControls,
    zoneId,
    complianceReport.zone_name,
    token,
    complianceReport.cf_plan,
    tokenPerms.available,
  );
  
  return c.json(preview);
});

// ══════════════════════════════════════════════════════════════════
// POST /execute - Execute selected remediation actions
// ══════════════════════════════════════════════════════════════════

remediation.post('/execute', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);
  
  // Parse request
  const body = await c.req.json<{
    report_id?: string;
    zone_id?: string;
    zone_name?: string;
    api_token?: string;
    action_ids?: string[];
    total_cost_confirmed?: number;
  }>();
  
  const { report_id, zone_id, zone_name, api_token, action_ids, total_cost_confirmed } = body;
  
  // Validate required fields
  if (!report_id || !api_token || !action_ids || action_ids.length === 0) {
    return c.json({ error: 'Missing required fields: report_id, api_token, action_ids' }, 400);
  }
  
  if (action_ids.length > MAX_ACTIONS_PER_BATCH) {
    return c.json({ error: `Maximum ${MAX_ACTIONS_PER_BATCH} actions per batch` }, 400);
  }
  
  // Fetch compliance report
  const { data: reportRecord, error: reportError } = await admin
    .from('security_reports')
    .select('id, account_id, domain, data, status')
    .eq('id', report_id)
    .eq('report_type', 'compliance')
    .single();
  
  if (reportError || !reportRecord) {
    return c.json({ error: 'Compliance report not found' }, 404);
  }
  
  // Get user account and verify ownership
  const { data: userAccount } = await admin
    .from('security_accounts')
    .select('id, credit_balance')
    .eq('user_id', userId)
    .eq('id', reportRecord.account_id)
    .single();
  
  if (!userAccount) {
    return c.json({ error: 'Unauthorized' }, 403);
  }
  
  const complianceReport = reportRecord.data as ComplianceReport;
  
  // Extract all controls
  const allControls: ControlResult[] = [];
  for (const fw of complianceReport.framework_results || []) {
    for (const section of fw.sections || []) {
      allControls.push(...section.controls);
    }
  }
  
  // Generate available actions
  const zoneId = zone_id || complianceReport.zone_id;
  const availableActions = generateRemediationActions(allControls, zoneId);
  
  // Validate requested actions exist
  const requestedActions = availableActions.filter(a => action_ids.includes(a.action_id));
  if (requestedActions.length === 0) {
    return c.json({ error: 'No valid actions found for the provided action_ids' }, 400);
  }
  
  // Calculate cost
  const totalCost = requestedActions.reduce((sum, a) => sum + a.credit_cost, 0);
  
  // Verify cost confirmation
  if (total_cost_confirmed !== totalCost) {
    return c.json({ 
      error: 'Cost mismatch', 
      expected_cost: totalCost,
      confirmed_cost: total_cost_confirmed,
    }, 400);
  }
  
  // Check sufficient credits
  if (userAccount.credit_balance < totalCost) {
    return c.json({
      error: 'Insufficient credits',
      credits_required: totalCost,
      credits_available: userAccount.credit_balance,
    }, 402);
  }
  
  // Deduct credits upfront
  const { error: deductError } = await admin.rpc('deduct_security_credits', {
    p_account_id: userAccount.id,
    p_amount: totalCost,
    p_description: `Anga AutoFix: ${requestedActions.length} action(s) on ${zone_name || complianceReport.zone_name}`,
    p_report_id: null,
  });
  
  if (deductError) {
    console.error('Credit deduction failed:', deductError);
    return c.json({ error: 'Failed to deduct credits' }, 500);
  }
  
  // Execute remediation
  const executionResult = await executeRemediation(
    {
      user_id: userId,
      account_id: userAccount.id,
      zone_id: zoneId,
      zone_name: zone_name || complianceReport.zone_name,
      api_token,
      action_ids,
      user_confirmed: true,
      total_cost_confirmed: totalCost,
    },
    availableActions,
  );
  
  // If any actions failed, process refunds
  if (executionResult.credits_refunded > 0) {
    await admin.rpc('add_security_credits', {
      p_account_id: userAccount.id,
      p_amount: executionResult.credits_refunded,
      p_description: `Anga AutoFix refund: ${executionResult.summary.failed} failed action(s)`,
    });
  }
  
  // Log execution to database
  await admin.from('remediation_logs').insert({
    execution_id: executionResult.execution_id,
    account_id: userAccount.id,
    zone_id: zoneId,
    zone_name: zone_name || complianceReport.zone_name,
    actions_executed: executionResult.summary.total,
    actions_succeeded: executionResult.summary.succeeded,
    actions_failed: executionResult.summary.failed,
    credits_charged: executionResult.credits_charged,
    credits_refunded: executionResult.credits_refunded,
    status: executionResult.summary.failed === 0 ? 'completed' : 
            executionResult.summary.succeeded > 0 ? 'partial' : 'failed',
    actions_json: JSON.stringify(requestedActions),
    results_json: JSON.stringify(executionResult.results),
    created_at: executionResult.started_at,
    completed_at: executionResult.completed_at,
  });
  
  return c.json(executionResult);
});

// ══════════════════════════════════════════════════════════════════
// GET /history - Get remediation execution history
// ══════════════════════════════════════════════════════════════════

remediation.get('/history', async (c) => {
  const userId = c.get('userId');
  const admin = getAdminClient(c.env);
  
  // Get user account
  const { data: userAccount } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();
  
  if (!userAccount) {
    return c.json({ error: 'Account not found' }, 404);
  }
  
  // Fetch remediation logs
  const { data: logs, error, count } = await admin
    .from('remediation_logs')
    .select('execution_id, zone_id, zone_name, actions_executed, actions_succeeded, actions_failed, credits_charged, credits_refunded, status, created_at, completed_at', { count: 'exact' })
    .eq('account_id', userAccount.id)
    .order('created_at', { ascending: false })
    .limit(50);
  
  if (error) {
    console.error('Failed to fetch remediation history:', error);
    return c.json({ error: 'Failed to fetch history' }, 500);
  }
  
  return c.json({ history: logs || [], total: count || 0 });
});

// ══════════════════════════════════════════════════════════════════
// GET /execution/:id - Get details of a specific execution
// ══════════════════════════════════════════════════════════════════

remediation.get('/execution/:id', async (c) => {
  const userId = c.get('userId');
  const executionId = c.req.param('id');
  const admin = getAdminClient(c.env);
  
  // Get user account
  const { data: userAccount } = await admin
    .from('security_accounts')
    .select('id')
    .eq('user_id', userId)
    .single();
  
  if (!userAccount) {
    return c.json({ error: 'Account not found' }, 404);
  }
  
  // Fetch specific execution
  const { data: log, error } = await admin
    .from('remediation_logs')
    .select('*')
    .eq('execution_id', executionId)
    .eq('account_id', userAccount.id)
    .single();
  
  if (error || !log) {
    return c.json({ error: 'Execution not found' }, 404);
  }
  
  return c.json({
    execution_id: log.execution_id,
    zone_id: log.zone_id,
    zone_name: log.zone_name,
    actions_executed: log.actions_executed,
    actions_succeeded: log.actions_succeeded,
    actions_failed: log.actions_failed,
    credits_charged: log.credits_charged,
    credits_refunded: log.credits_refunded,
    status: log.status,
    actions: JSON.parse(log.actions_json || '[]'),
    results: JSON.parse(log.results_json || '[]'),
    created_at: log.created_at,
    completed_at: log.completed_at,
  });
});

export default remediation;
