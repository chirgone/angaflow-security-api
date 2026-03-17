import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import type { Env, Variables } from './types';
import { authMiddleware } from './middleware/auth';
import { adminMiddleware } from './middleware/admin';
import { getAdminClient } from './services/supabase';

// Routes
import health from './routes/health';
import account from './routes/account';
import credits from './routes/credits';
import payments from './routes/payments';
import admin from './routes/admin';
import scan from './routes/scan';
import audit from './routes/audit';
import compliance from './routes/compliance';
import simulation from './routes/simulation';
import ai from './routes/ai';
import leads from './routes/leads';
import remediation from './routes/remediation';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// ============================================================
// Middleware
// ============================================================

// Custom logger with token redaction
app.use('*', async (c, next) => {
  const start = Date.now();
  const method = c.req.method;
  let path = c.req.path;
  
  // Redact sensitive query parameters
  const url = new URL(c.req.url);
  if (url.searchParams.has('api_token')) {
    url.searchParams.set('api_token', '[REDACTED]');
  }
  if (url.search) {
    path = `${url.pathname}${url.search}`;
  }
  
  await next();
  
  const elapsed = Date.now() - start;
  console.log(`${method} ${path} ${c.res.status} ${elapsed}ms`);
});

app.use('*', prettyJSON());

// CORS: Allow configured origin + project-specific Pages previews + angaflow.com subdomains
app.use(
  '*',
  cors({
    origin: (origin, c) => {
      const env = c.env as Env;
      
      // No wildcard fallback - reject requests without origin
      if (!origin) return env.CORS_ORIGIN;

      const allowedPatterns = [
        env.CORS_ORIGIN,
        // Only allow our specific Cloudflare Pages project
        /^https:\/\/angaflow-security.*\.pages\.dev$/,
        /^https:\/\/.*\.angaflow\.com$/,
        /^https:\/\/angaflow\.com$/,
      ];
      
      // Localhost only in development
      if (env.ENVIRONMENT !== 'production') {
        allowedPatterns.push(/^http:\/\/localhost:\d+$/);
      }

      for (const pattern of allowedPatterns) {
        if (typeof pattern === 'string' && origin === pattern) return origin;
        if (pattern instanceof RegExp && pattern.test(origin)) return origin;
      }

      // Reject unknown origins
      return env.CORS_ORIGIN;
    },
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
  })
);

// ============================================================
// Public routes (no auth required)
// ============================================================

app.route('/api/health', health);

// ============================================================
// POST /api/auth/register — Secure registration via Admin API
// - Creates user pre-confirmed (no emails sent)
// - Rate limited by IP (5 registrations per hour)
// - Rejects suspicious/temporary email domains
// - Creates security_account automatically
// ============================================================

// In-memory rate limiter (resets on worker restart, good enough for CF Workers)
const registerRateLimits = new Map<string, { count: number; resetAt: number }>();

// Disposable/temporary email domains to reject
const BLOCKED_EMAIL_DOMAINS = new Set([
  // Disposable email services
  'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.net',
  'guerrillamail.org', 'guerrillamail.de', 'grr.la', 'guerrillamailblock.com',
  'mailinator.com', 'mailinator2.com', 'maildrop.cc', 'dispostable.com',
  'yopmail.com', 'yopmail.fr', 'yopmail.net', 'cool.fr.nf', 'jetable.fr.nf',
  'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj', 'speed.1s.fr',
  'throwaway.email', 'trashmail.com', 'trashmail.me', 'trashmail.net',
  'sharklasers.com', 'guerrillamail.info', 'grr.la', 'guerrillamail.biz',
  '10minutemail.com', '10minutemail.net', 'minutemail.com',
  'tempail.com', 'tempr.email', 'temp-mail.io', 'tempmailo.com',
  'emailondeck.com', 'mailnesia.com', 'mailtothis.com',
  'mohmal.com', 'burnermail.io', 'inboxkitten.com',
  'mailsac.com', 'mailnull.com', 'mailexpire.com', 'discard.email',
  'fakeinbox.com', 'fakemail.fr', 'mailcatch.com', 'mailforspam.com',
  'harakirimail.com', 'mytrashmail.com', 'throwam.com',
  'getnada.com', 'nada.email', 'anonbox.net',
  'bugmenot.com', 'spamgourmet.com', 'spamfree24.org',
  'mailhazard.com', 'mailhazard.us', 'mailquack.com',
  'objectmail.com', 'proxymail.eu', 'rcpt.at',
  'trash-mail.at', 'trashmail.io', 'wegwerfmail.de', 'wegwerfmail.net',
  'emailfake.com', 'crazymailing.com', 'mailtemp.info',
  'tempinbox.com', 'tempmailaddress.com', 'tmpmail.net', 'tmpmail.org',
  'emkei.cz', 'anonymbox.com', 'courrieltemporaire.com',
  'incognitomail.org', 'incognitomail.com', 'dropmail.me',
  'getairmail.com', 'tmail.ws', 'mailseal.de',
  // Generic suspicious TLDs / patterns
  'example.com', 'test.com', 'localhost', 'invalid',
]);

function isEmailSuspicious(email: string): string | null {
  const lower = email.toLowerCase().trim();

  // Basic format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(lower)) return 'Invalid email format';

  const [localPart, domain] = lower.split('@');

  // Check blocked domains
  if (BLOCKED_EMAIL_DOMAINS.has(domain)) return 'Disposable email addresses are not allowed';

  // Check for suspicious patterns in domain
  if (domain.includes('temp') || domain.includes('trash') || domain.includes('disposable') || domain.includes('fakein') || domain.includes('throwaway')) {
    return 'Suspicious email domain detected';
  }

  // Local part checks
  if (localPart.length > 64) return 'Invalid email format';
  if (localPart.startsWith('.') || localPart.endsWith('.')) return 'Invalid email format';

  // Domain must have valid TLD (at least 2 chars)
  const tld = domain.split('.').pop() || '';
  if (tld.length < 2) return 'Invalid email domain';

  return null; // Email is OK
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const limit = registerRateLimits.get(ip);

  // Clean up expired entries periodically
  if (registerRateLimits.size > 10000) {
    for (const [key, val] of registerRateLimits) {
      if (val.resetAt < now) registerRateLimits.delete(key);
    }
  }

  if (!limit || limit.resetAt < now) {
    // New window: 5 registrations per hour
    registerRateLimits.set(ip, { count: 1, resetAt: now + 3600000 });
    return true;
  }

  if (limit.count >= 5) return false; // Rate limited

  limit.count++;
  return true;
}

app.post('/api/auth/register', async (c) => {
  try {
    const { email, password } = await c.req.json<{ email: string; password: string }>();

    if (!email || !password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }

    // 1. Rate limit by IP (5 registrations per IP per hour)
    const clientIp = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown';
    if (!checkRateLimit(clientIp)) {
      console.warn(`⚠️ Registration rate limited for IP: ${clientIp}`);
      return c.json({ error: 'Too many registration attempts. Please try again later.' }, 429);
    }

    // 2. Validate email (reject suspicious/temp emails)
    const emailIssue = isEmailSuspicious(email);
    if (emailIssue) {
      return c.json({ error: emailIssue }, 400);
    }

    // 3. Validate password
    if (password.length < 8) {
      return c.json({ error: 'Password must be at least 8 characters' }, 400);
    }

    const supabaseUrl = c.env.SUPABASE_URL;
    const serviceRoleKey = c.env.SUPABASE_SERVICE_ROLE_KEY;

    // 4. Create user with Admin API (pre-confirmed, no email sent)
    const createRes = await fetch(`${supabaseUrl}/auth/v1/admin/users`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${serviceRoleKey}`,
        'apikey': serviceRoleKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.toLowerCase().trim(),
        password,
        email_confirm: true, // Pre-confirmed, no verification email
      }),
    });

    if (!createRes.ok) {
      const errBody = await createRes.json().catch(() => ({})) as any;
      const msg = errBody?.msg || errBody?.message || errBody?.error || 'Registration failed';

      // Handle duplicate user
      if (createRes.status === 422 || msg.toLowerCase().includes('already')) {
        return c.json({ error: 'An account with this email already exists' }, 409);
      }

      console.error('Admin user creation failed:', msg);
      return c.json({ error: msg }, createRes.status);
    }

    const newUser = await createRes.json() as any;
    const userId = newUser.id;

    if (!userId) {
      return c.json({ error: 'Failed to create user' }, 500);
    }

    // 5. Create security_account automatically
    const adminClient = getAdminClient(c.env);
    try {
      const { getOrCreateSecurityAccount } = await import('./services/supabase');
      await getOrCreateSecurityAccount(adminClient, userId, email.toLowerCase().trim());
    } catch (accErr: any) {
      console.error('Security account creation failed (non-blocking):', accErr?.message);
      // Non-blocking: account will be created on first dashboard visit via /api/account
    }

    // 6. Generate session token via signInWithPassword (through GoTrue API)
    const signInRes = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'apikey': c.env.SUPABASE_ANON_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email.toLowerCase().trim(),
        password,
      }),
    });

    if (!signInRes.ok) {
      // User created but couldn't sign in - still a success, they can login manually
      console.warn('Auto sign-in after registration failed');
      return c.json({
        success: true,
        user_id: userId,
        session: null,
        message: 'Account created. Please sign in.',
      });
    }

    const session = await signInRes.json();

    console.log(`✅ New user registered: ${email} (IP: ${clientIp})`);

    return c.json({
      success: true,
      user_id: userId,
      session, // Contains access_token, refresh_token, etc.
    });
  } catch (err: any) {
    console.error('Registration error:', err);
    return c.json({ error: err?.message || 'Registration failed' }, 500);
  }
});

// Payment webhook + public key are public (no auth)
// Mount payments BEFORE auth middleware for public endpoints
app.route('/api/payments', payments);

// Leads endpoint is public (no auth required)
app.route('/api/leads', leads);

// ============================================================
// Protected routes (auth required)
// ============================================================

app.use('/api/account/*', authMiddleware);
app.use('/api/credits/*', authMiddleware);
app.use('/api/scan/*', authMiddleware);
app.use('/api/audit/*', authMiddleware);
app.use('/api/compliance/*', authMiddleware);
app.use('/api/simulation/*', authMiddleware);
app.use('/api/ai/*', authMiddleware);
app.use('/api/remediation/*', authMiddleware);
app.use('/api/admin/*', authMiddleware);
app.use('/api/admin/*', adminMiddleware);

app.route('/api/account', account);
app.route('/api/credits', credits);
app.route('/api/scan', scan);
app.route('/api/audit', audit);
app.route('/api/compliance', compliance);
app.route('/api/simulation', simulation);
app.route('/api/ai', ai);
app.route('/api/remediation', remediation);
app.route('/api/admin', admin);

// ============================================================
// 404 handler
// ============================================================

app.notFound((c) => {
  return c.json({ error: 'Not found', path: c.req.path }, 404);
});

// ============================================================
// Error handler
// ============================================================

app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json(
    {
      error: 'Internal server error',
      message: c.env.ENVIRONMENT === 'development' ? err.message : undefined,
    },
    500
  );
});

// Export the Workflow class so Cloudflare can instantiate it
export { SimulationWorkflow } from './workflows/simulation-workflow';

export default app;
