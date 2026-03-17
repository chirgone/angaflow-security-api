import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { getAdminClient } from '../services/supabase';

const credits = new Hono<{ Bindings: Env; Variables: Variables }>();

// GET /api/credits/balance — Get current credit balance
credits.get('/balance', async (c) => {
  const user = c.get('user');
  const adminClient = getAdminClient(c.env);

  const { data: account, error } = await adminClient
    .from('security_accounts')
    .select('credit_balance, free_scans_used, first_reload_bonus_claimed')
    .eq('user_id', user.id)
    .single();

  if (error || !account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  return c.json({
    credit_balance: parseFloat(account.credit_balance),
    free_scans_used: account.free_scans_used,
    first_reload_bonus_available: !account.first_reload_bonus_claimed,
  });
});

// GET /api/credits/transactions — List credit transaction history
credits.get('/transactions', async (c) => {
  const user = c.get('user');
  const adminClient = getAdminClient(c.env);

  // Get account ID
  const { data: account } = await adminClient
    .from('security_accounts')
    .select('id')
    .eq('user_id', user.id)
    .single();

  if (!account) {
    return c.json({ error: 'Account not found' }, 404);
  }

  const limit = parseInt(c.req.query('limit') || '20');
  const offset = parseInt(c.req.query('offset') || '0');

  const { data: transactions, error, count } = await adminClient
    .from('security_credit_transactions')
    .select('*', { count: 'exact' })
    .eq('account_id', account.id)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    return c.json({ error: 'Failed to fetch transactions' }, 500);
  }

  return c.json({
    transactions: transactions || [],
    total: count || 0,
    limit,
    offset,
  });
});

export default credits;
