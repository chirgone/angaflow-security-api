/**
 * Leads API Routes
 * 
 * Public endpoint for contact form submission from landing page
 * Validates domain ownership via DNS checks
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { createClient } from '@supabase/supabase-js';
import { Env } from '../types';

const app = new Hono<{ Bindings: Env }>();

// Request validation schema
const LeadSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  company: z.string().optional(),
  domain: z.string().min(3, 'Domain is required').regex(/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/, 'Invalid domain format'),
  message: z.string().min(10, 'Message must be at least 10 characters'),
  ownership_confirmed: z.boolean().refine(val => val === true, 'You must confirm domain ownership'),
});

/**
 * Validate domain DNS
 * Checks if domain exists and uses Cloudflare nameservers
 */
async function validateDomain(domain: string): Promise<{
  exists: boolean;
  usesCloudflare: boolean;
}> {
  try {
    // DNS lookup using cloudflare-workers DNS over HTTPS
    const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=NS`, {
      headers: { 'Accept': 'application/dns-json' },
    });

    if (!dnsResponse.ok) {
      return { exists: false, usesCloudflare: false };
    }

    const dnsData: any = await dnsResponse.json();
    
    // Check if domain has NS records (exists)
    const exists = dnsData.Answer && dnsData.Answer.length > 0;
    
    // Check if any nameserver contains 'cloudflare.com'
    const usesCloudflare = exists && dnsData.Answer.some((record: any) => 
      record.data && record.data.toLowerCase().includes('cloudflare.com')
    );

    return { exists, usesCloudflare };
  } catch (error) {
    console.error('DNS validation error:', error);
    return { exists: false, usesCloudflare: false };
  }
}

/**
 * POST /api/leads
 * Public endpoint - no auth required
 * Submit a contact lead from landing page
 */
app.post('/', async (c) => {
  try {
    // Parse and validate request body
    const body = await c.req.json();
    const validatedData = LeadSchema.parse(body);

    // Validate domain via DNS
    const { exists, usesCloudflare } = await validateDomain(validatedData.domain);

    // Create Supabase client
    const supabase = createClient(
      c.env.SUPABASE_URL,
      c.env.SUPABASE_SERVICE_ROLE_KEY
    );

    // Check if user already has an account (optional link)
    const { data: existingUser } = await supabase
      .from('security_accounts')
      .select('id')
      .eq('email', validatedData.email)
      .single();

    // Insert lead into database
    const { data: lead, error } = await supabase
      .from('security_leads')
      .insert({
        name: validatedData.name,
        email: validatedData.email,
        company: validatedData.company || null,
        domain: validatedData.domain,
        message: validatedData.message,
        ownership_confirmed: validatedData.ownership_confirmed,
        domain_exists: exists,
        domain_uses_cloudflare: usesCloudflare,
        user_id: existingUser?.id || null,
        status: 'new',
      })
      .select()
      .single();

    if (error) {
      console.error('Database error:', error);
      return c.json({ error: 'Failed to save lead' }, 500);
    }

    // TODO: Send notification to admin (WhatsApp/Email)
    // For now, just log it
    console.log('New lead received:', {
      id: lead.id,
      email: validatedData.email,
      domain: validatedData.domain,
      usesCloudflare,
    });

    return c.json({
      success: true,
      message: 'Thank you! We will contact you soon.',
      lead_id: lead.id,
    }, 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Validation failed',
        details: error.errors,
      }, 400);
    }

    console.error('Lead submission error:', error);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

export default app;
