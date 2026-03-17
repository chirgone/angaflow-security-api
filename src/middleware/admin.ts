import { Context, Next } from 'hono';
import type { Env, Variables } from '../types';

const ADMIN_EMAIL = 'jose301184@gmail.com';

/**
 * Admin middleware: must be used AFTER authMiddleware.
 * Checks that the authenticated user's email matches the admin email.
 */
export async function adminMiddleware(
  c: Context<{ Bindings: Env; Variables: Variables }>,
  next: Next
) {
  const user = c.get('user');

  if (!user || user.email !== ADMIN_EMAIL) {
    return c.json({ error: 'Forbidden: admin access only' }, 403);
  }

  await next();
}
