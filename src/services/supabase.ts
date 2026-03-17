import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Env } from '../types';

/**
 * Get a Supabase client.
 * - With userToken: uses anon key + Bearer token (RLS-scoped to user)
 * - Without userToken: uses service_role key (full admin access)
 */
export function getSupabaseClient(env: Env, userToken?: string): SupabaseClient {
  if (userToken) {
    return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
      global: {
        headers: { Authorization: `Bearer ${userToken}` },
      },
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }

  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

/**
 * Get admin Supabase client (service role — bypasses RLS)
 */
export function getAdminClient(env: Env): SupabaseClient {
  return getSupabaseClient(env);
}

/**
 * Get or create a security account for a user
 */
export async function getOrCreateSecurityAccount(
  adminClient: SupabaseClient,
  userId: string,
  email: string
) {
  // Try to find existing account
  const { data: existing } = await adminClient
    .from('security_accounts')
    .select('*')
    .eq('user_id', userId)
    .single();

  if (existing) return existing;

  // Create new account
  const { data: created, error } = await adminClient
    .from('security_accounts')
    .insert({
      user_id: userId,
      email: email,
      plan_type: 'free',
      credit_balance: 0,
      free_scans_used: 0,
      status: 'active',
    })
    .select()
    .single();

  if (error) throw new Error(`Failed to create security account: ${error.message}`);
  return created;
}
