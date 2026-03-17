import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient, getOrCreateSecurityAccount } from '../services/supabase';

const account = new Hono<{ Bindings: Env; Variables: Variables }>();

// GET /api/account — Get current user's security account
account.get('/', async (c) => {
  const user = c.get('user');
  const adminClient = getAdminClient(c.env);

  const securityAccount = await getOrCreateSecurityAccount(
    adminClient,
    user.id,
    user.email || ''
  );

  // Get active subscription if any
  const { data: subscription } = await adminClient
    .from('security_subscriptions')
    .select('*')
    .eq('account_id', securityAccount.id)
    .eq('status', 'active')
    .single();

  // Get recent reports count
  const { count: reportCount } = await adminClient
    .from('security_reports')
    .select('*', { count: 'exact', head: true })
    .eq('account_id', securityAccount.id);

  return c.json({
    account: {
      id: securityAccount.id,
      email: securityAccount.email,
      display_name: securityAccount.display_name,
      plan_type: securityAccount.plan_type,
      credit_balance: parseFloat(securityAccount.credit_balance),
      free_scans_used: securityAccount.free_scans_used,
      first_reload_bonus_claimed: securityAccount.first_reload_bonus_claimed,
      status: securityAccount.status,
      created_at: securityAccount.created_at,
    },
    subscription: subscription || null,
    report_count: reportCount || 0,
  });
});

// POST /api/account — Create security account (called on first login)
account.post('/', async (c) => {
  const user = c.get('user');
  const adminClient = getAdminClient(c.env);

  const securityAccount = await getOrCreateSecurityAccount(
    adminClient,
    user.id,
    user.email || ''
  );

  return c.json({ account: securityAccount }, 201);
});

// PATCH /api/account — Update display name
account.patch('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{ display_name?: string }>();
  const adminClient = getAdminClient(c.env);

  const { data, error } = await adminClient
    .from('security_accounts')
    .update({ display_name: body.display_name })
    .eq('user_id', user.id)
    .select()
    .single();

  if (error) {
    return c.json({ error: 'Failed to update account' }, 500);
  }

  return c.json({ account: data });
});

export default account;
