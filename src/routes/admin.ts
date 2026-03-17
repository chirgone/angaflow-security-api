import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient } from '../services/supabase';

const admin = new Hono<{ Bindings: Env; Variables: Variables }>();

// ============================================================
// GET /api/admin/stats — KPIs principales
// ============================================================
admin.get('/stats', async (c) => {
  const db = getAdminClient(c.env);

  const [users, payments, credits, subscriptions, reports] = await Promise.all([
    // Total users
    db.from('security_accounts').select('*', { count: 'exact', head: true }),
    // Total revenue (approved payments)
    db.from('security_payment_logs').select('amount').eq('status', 'approved'),
    // Total credits sold
    db.from('security_credit_transactions').select('total_credits').eq('type', 'recharge'),
    // Active subscriptions
    db.from('security_subscriptions').select('*', { count: 'exact', head: true }).eq('status', 'active'),
    // Total reports
    db.from('security_reports').select('*', { count: 'exact', head: true }),
  ]);

  const totalRevenue = (payments.data || []).reduce(
    (sum, p) => sum + (parseFloat(p.amount) || 0), 0
  );

  const totalCreditsSold = (credits.data || []).reduce(
    (sum, t) => sum + (parseFloat(t.total_credits) || 0), 0
  );

  return c.json({
    total_users: users.count || 0,
    total_revenue_mxn: totalRevenue,
    total_credits_sold: totalCreditsSold,
    active_subscriptions: subscriptions.count || 0,
    total_reports: reports.count || 0,
  });
});

// ============================================================
// GET /api/admin/users — Lista paginada de usuarios
// ============================================================
admin.get('/users', async (c) => {
  const db = getAdminClient(c.env);
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');

  const { data, count, error } = await db
    .from('security_accounts')
    .select('id, user_id, email, display_name, plan_type, credit_balance, free_scans_used, first_reload_bonus_claimed, status, created_at', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    return c.json({ error: 'Failed to fetch users' }, 500);
  }

  return c.json({
    users: (data || []).map((u) => ({
      ...u,
      credit_balance: parseFloat(u.credit_balance),
    })),
    total: count || 0,
    limit,
    offset,
  });
});

// ============================================================
// GET /api/admin/payments — Detalle de pagos MercadoPago
// ============================================================
admin.get('/payments', async (c) => {
  const db = getAdminClient(c.env);
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');

  const { data, count, error } = await db
    .from('security_payment_logs')
    .select('*', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    return c.json({ error: 'Failed to fetch payments' }, 500);
  }

  const totalRevenue = (data || [])
    .filter((p) => p.status === 'approved')
    .reduce((sum, p) => sum + (parseFloat(p.amount) || 0), 0);

  return c.json({
    payments: data || [],
    total: count || 0,
    total_revenue_mxn: totalRevenue,
    limit,
    offset,
  });
});

// ============================================================
// GET /api/admin/credits — Resumen de creditos
// ============================================================
admin.get('/credits', async (c) => {
  const db = getAdminClient(c.env);

  const { data: transactions } = await db
    .from('security_credit_transactions')
    .select('type, total_credits, amount, bonus, created_at')
    .order('created_at', { ascending: false });

  const txs = transactions || [];

  const summary = {
    total_recharged: 0,
    total_bonuses: 0,
    total_deducted: 0,
    total_refunded: 0,
    recharge_count: 0,
    deduction_count: 0,
  };

  for (const tx of txs) {
    const credits = parseFloat(tx.total_credits) || 0;
    switch (tx.type) {
      case 'recharge':
        summary.total_recharged += credits;
        summary.recharge_count++;
        break;
      case 'bonus':
        summary.total_bonuses += credits;
        break;
      case 'deduction':
        summary.total_deducted += credits;
        summary.deduction_count++;
        break;
      case 'refund':
        summary.total_refunded += credits;
        break;
    }
  }

  return c.json({ summary, recent_transactions: txs.slice(0, 50) });
});

// ============================================================
// GET /api/admin/subscriptions — Suscripciones por plan
// ============================================================
admin.get('/subscriptions', async (c) => {
  const db = getAdminClient(c.env);

  const { data, error } = await db
    .from('security_subscriptions')
    .select('*, security_accounts!inner(email)')
    .order('created_at', { ascending: false });

  if (error) {
    return c.json({ error: 'Failed to fetch subscriptions' }, 500);
  }

  const subs = data || [];
  const active = subs.filter((s) => s.status === 'active');

  const byPlan: Record<string, number> = {};
  for (const s of active) {
    byPlan[s.plan_id] = (byPlan[s.plan_id] || 0) + 1;
  }

  return c.json({
    subscriptions: subs,
    active_count: active.length,
    by_plan: byPlan,
  });
});

// ============================================================
// GET /api/admin/reports — Reportes generados
// ============================================================
admin.get('/reports', async (c) => {
  const db = getAdminClient(c.env);
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');

  const { data, count, error } = await db
    .from('security_reports')
    .select('*, security_accounts!inner(email)', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    return c.json({ error: 'Failed to fetch reports' }, 500);
  }

  // Count by type
  const { data: allReports } = await db
    .from('security_reports')
    .select('report_type');

  const byType: Record<string, number> = {};
  for (const r of allReports || []) {
    byType[r.report_type] = (byType[r.report_type] || 0) + 1;
  }

  return c.json({
    reports: data || [],
    total: count || 0,
    by_type: byType,
    limit,
    offset,
  });
});

// ============================================================
// GET /api/admin/activity — Feed de actividad reciente
// ============================================================
admin.get('/activity', async (c) => {
  const db = getAdminClient(c.env);

  // Fetch recent events from multiple tables in parallel
  const [recentUsers, recentPayments, recentReports, recentTransactions] = await Promise.all([
    db.from('security_accounts')
      .select('id, email, created_at')
      .order('created_at', { ascending: false })
      .limit(15),
    db.from('security_payment_logs')
      .select('id, payment_id, status, amount, currency, payer_email, payment_type, created_at')
      .order('created_at', { ascending: false })
      .limit(15),
    db.from('security_reports')
      .select('id, domain, report_type, score, grade, status, created_at, security_accounts!inner(email)')
      .order('created_at', { ascending: false })
      .limit(15),
    db.from('security_credit_transactions')
      .select('id, type, total_credits, description, created_at, security_accounts!inner(email)')
      .order('created_at', { ascending: false })
      .limit(15),
  ]);

  // Merge into a single feed sorted by created_at
  const feed: Array<{
    type: string;
    description: string;
    email?: string;
    amount?: string;
    created_at: string;
  }> = [];

  for (const u of recentUsers.data || []) {
    feed.push({
      type: 'user_registered',
      description: `Nuevo usuario: ${u.email}`,
      email: u.email,
      created_at: u.created_at,
    });
  }

  for (const p of recentPayments.data || []) {
    feed.push({
      type: 'payment',
      description: `Pago ${p.status}: $${p.amount} ${p.currency} (${p.payment_type || 'unknown'})`,
      email: p.payer_email || undefined,
      amount: p.amount,
      created_at: p.created_at,
    });
  }

  for (const r of recentReports.data || []) {
    const email = (r as any).security_accounts?.email;
    feed.push({
      type: 'report',
      description: `Reporte ${r.report_type} para ${r.domain} — ${r.grade || r.status}`,
      email,
      created_at: r.created_at,
    });
  }

  for (const t of recentTransactions.data || []) {
    const email = (t as any).security_accounts?.email;
    feed.push({
      type: `credit_${t.type}`,
      description: `${t.description || t.type}: ${parseFloat(t.total_credits).toLocaleString()} créditos`,
      email,
      amount: t.total_credits,
      created_at: t.created_at,
    });
  }

  // Sort by date descending and take top 50
  feed.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return c.json({ activity: feed.slice(0, 50) });
});

/**
 * GET /api/admin/leads
 * List all contact leads with filtering
 */
admin.get('/leads', async (c) => {
  const supabase = getAdminClient(c.env);
  
  // Query params
  const status = c.req.query('status'); // filter by status
  const limit = parseInt(c.req.query('limit') || '50');
  const offset = parseInt(c.req.query('offset') || '0');

  // Base query
  let query = supabase
    .from('security_leads')
    .select('*', { count: 'exact' })
    .order('created_at', { ascending: false });

  // Apply status filter if provided
  if (status && status !== 'all') {
    query = query.eq('status', status);
  }

  // Pagination
  query = query.range(offset, offset + limit - 1);

  const { data: leads, error, count } = await query;

  if (error) {
    console.error('Failed to fetch leads:', error);
    return c.json({ error: 'Failed to fetch leads' }, 500);
  }

  // Calculate stats
  const { data: stats } = await supabase
    .from('security_leads')
    .select('status, domain_uses_cloudflare');

  const statusCounts = {
    new: 0,
    contacted: 0,
    qualified: 0,
    closed: 0,
    discarded: 0,
  };

  let cloudflareCount = 0;
  let totalLeads = 0;

  if (stats) {
    totalLeads = stats.length;
    stats.forEach((lead: any) => {
      if (lead.status) statusCounts[lead.status as keyof typeof statusCounts]++;
      if (lead.domain_uses_cloudflare) cloudflareCount++;
    });
  }

  return c.json({
    leads: leads || [],
    total: count || 0,
    stats: {
      total: totalLeads,
      by_status: statusCounts,
      cloudflare_percentage: totalLeads > 0 ? Math.round((cloudflareCount / totalLeads) * 100) : 0,
    },
  });
});

/**
 * PATCH /api/admin/leads/:id
 * Update lead status or notes
 */
admin.patch('/leads/:id', async (c) => {
  const supabase = getAdminClient(c.env);
  const leadId = c.req.param('id');
  const body = await c.req.json();

  // Validate update fields
  const allowedFields = ['status', 'notes'];
  const updates: any = {};

  for (const field of allowedFields) {
    if (body[field] !== undefined) {
      updates[field] = body[field];
    }
  }

  if (Object.keys(updates).length === 0) {
    return c.json({ error: 'No valid fields to update' }, 400);
  }

  // Validate status if provided
  if (updates.status) {
    const validStatuses = ['new', 'contacted', 'qualified', 'closed', 'discarded'];
    if (!validStatuses.includes(updates.status)) {
      return c.json({ error: 'Invalid status value' }, 400);
    }
  }

  const { data: lead, error } = await supabase
    .from('security_leads')
    .update(updates)
    .eq('id', leadId)
    .select()
    .single();

  if (error) {
    console.error('Failed to update lead:', error);
    return c.json({ error: 'Failed to update lead' }, 500);
  }

  return c.json({ lead });
});

// ============================================================
// GET /api/admin/users/:id/audit — Auditoría completa de créditos por usuario
// ============================================================
admin.get('/users/:id/audit', async (c) => {
  const db = getAdminClient(c.env);
  const accountId = c.req.param('id');

  // 1. Obtener cuenta del usuario
  const { data: account, error: accountError } = await db
    .from('security_accounts')
    .select('id, user_id, email, display_name, plan_type, credit_balance, free_scans_used, status, created_at')
    .eq('id', accountId)
    .single();

  if (accountError || !account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  // 2. Consultar las 3 fuentes en paralelo
  const [txResult, payResult, reportResult] = await Promise.all([
    // Todas las transacciones de crédito, sin límite
    db
      .from('security_credit_transactions')
      .select('id, type, total_credits, amount, bonus, description, report_id, created_at')
      .eq('account_id', accountId)
      .order('created_at', { ascending: false }),

    // Pagos de MercadoPago vinculados a esta cuenta
    db
      .from('security_payment_logs')
      .select('id, payment_id, status, amount, currency, payer_email, payment_type, metadata, created_at')
      .eq('external_reference', accountId)
      .order('created_at', { ascending: false }),

    // Reportes generados por esta cuenta
    db
      .from('security_reports')
      .select('id, type, domain, credits_charged, created_at')
      .eq('account_id', accountId)
      .order('created_at', { ascending: false }),
  ]);

  const transactions = txResult.data || [];
  const payments = payResult.data || [];
  const reports = reportResult.data || [];

  // 3. Calcular resumen
  const summary = {
    total_recharged: 0,
    total_bonuses: 0,
    total_spent: 0,
    total_refunded: 0,
    total_paid_mxn: 0,
    payment_count: payments.filter((p: any) => p.status === 'approved').length,
  };

  for (const tx of transactions) {
    const credits = parseFloat(tx.total_credits) || 0;
    switch (tx.type) {
      case 'recharge': summary.total_recharged += credits; break;
      case 'bonus':    summary.total_bonuses   += credits; break;
      case 'deduction':summary.total_spent     += credits; break;
      case 'refund':   summary.total_refunded  += credits; break;
    }
  }

  for (const p of payments) {
    if (p.status === 'approved') {
      summary.total_paid_mxn += parseFloat(p.amount) || 0;
    }
  }

  return c.json({
    account: {
      ...account,
      credit_balance: parseFloat(account.credit_balance),
    },
    transactions: transactions.map((tx: any) => ({
      ...tx,
      total_credits: parseFloat(tx.total_credits) || 0,
      amount: tx.amount ? parseFloat(tx.amount) : null,
    })),
    payments,
    reports: reports.map((r: any) => ({
      ...r,
      credits_charged: parseFloat(r.credits_charged) || 0,
    })),
    summary,
  });
});

export default admin;
