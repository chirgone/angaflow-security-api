import { Context, Next } from 'hono';
import type { Env, Variables } from '../types';
import { getSupabaseClient, getAdminClient } from '../services/supabase';

/**
 * Auth middleware: validates Supabase JWT token and checks account status.
 * Sets c.set('user') and c.set('userId') for downstream handlers.
 */
export async function authMiddleware(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  next: Next
) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid authorization header' }, 401);
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    // Validate token with Supabase (use admin client to bypass email confirmation check)
    const adminAuth = getAdminClient(c.env);
    const { data: { user }, error } = await adminAuth.auth.getUser(token);

    if (error || !user) {
      return c.json({ error: 'Invalid or expired token' }, 401);
    }

    // Check security account status (using admin client to bypass RLS)
    const adminClient = getAdminClient(c.env);
    const { data: account } = await adminClient
      .from('security_accounts')
      .select('status')
      .eq('user_id', user.id)
      .single();

    // If account exists and is suspended, block access
    if (account?.status === 'suspended') {
      return c.json({ error: 'Account is suspended' }, 403);
    }

    // Set user context for downstream handlers
    c.set('user', { id: user.id, email: user.email });
    c.set('userId', user.id);

    await next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return c.json({ error: 'Authentication failed' }, 401);
  }
}
