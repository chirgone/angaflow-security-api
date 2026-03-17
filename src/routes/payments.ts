import { Hono } from 'hono';
import type { Env, Variables } from '../types';
import { CREDIT_PACKAGES, SUBSCRIPTION_PLANS } from '../types';
import type { CreditPackageId, SubscriptionPlanId } from '../types';
import { getAdminClient } from '../services/supabase';
import { authMiddleware } from '../middleware/auth';

const payments = new Hono<{ Bindings: Env; Variables: Variables }>();

// Auth required only for create-checkout
payments.use('/create-checkout', authMiddleware);

// ============================================================
// HMAC-SHA256 Webhook Signature Validation (same as cfdi-invoicing)
// ============================================================
async function validateWebhookSignature(
  secret: string,
  dataId: string,
  requestId: string,
  ts: string,
  signature: string
): Promise<boolean> {
  try {
    const template = `id:${dataId};request-id:${requestId};ts:${ts};`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signatureBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(template));
    const computedSignature = Array.from(new Uint8Array(signatureBytes))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    
    // Timing-safe comparison to prevent timing attacks
    const encoder2 = new TextEncoder();
    const computedBytes = encoder2.encode(computedSignature);
    const signatureBytes2 = encoder2.encode(signature);
    
    if (computedBytes.length !== signatureBytes2.length) {
      return false;
    }
    
    return crypto.subtle.timingSafeEqual(computedBytes, signatureBytes2);
  } catch {
    return false;
  }
}

// ============================================================
// GET /api/payments/public-key — Expose MP public key to frontend
// ============================================================
payments.get('/public-key', async (c) => {
  return c.json({ public_key: c.env.MERCADOPAGO_PUBLIC_KEY });
});

// ============================================================
// POST /api/payments/create-checkout — Create MercadoPago preference
// ============================================================
payments.post('/create-checkout', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    type: 'credit_recharge' | 'subscription';
    package_id?: CreditPackageId;
    plan_id?: SubscriptionPlanId;
  }>();

  const adminClient = getAdminClient(c.env);

  // Get security account
  const { data: account } = await adminClient
    .from('security_accounts')
    .select('id, email')
    .eq('user_id', user.id)
    .single();

  if (!account) {
    return c.json({ error: 'Security account not found' }, 404);
  }

  // Check if this is user's first purchase (for launch promo)
  const { data: previousPurchases } = await adminClient
    .from('security_payment_logs')
    .select('id')
    .eq('external_reference', account.id)
    .eq('status', 'approved')
    .limit(1);

  const isFirstPurchase = !previousPurchases || previousPurchases.length === 0;

  const frontendUrl = c.env.FRONTEND_URL;
  let title: string;
  let unitPrice: number;
  let metadata: Record<string, string>;

  if (body.type === 'credit_recharge') {
    if (!body.package_id || !(body.package_id in CREDIT_PACKAGES)) {
      return c.json({ error: 'Invalid package_id' }, 400);
    }
    const pkg = CREDIT_PACKAGES[body.package_id];
    
    // Apply first-purchase promo for Starter package (50% off: $749 instead of $1,499)
    if (body.package_id === 'starter' && isFirstPurchase) {
      title = `Anga Security - ${pkg.credits.toLocaleString()} Créditos (${pkg.name}) - Oferta de Lanzamiento`;
      unitPrice = 749;
    } else {
      title = `Anga Security - ${pkg.credits.toLocaleString()} Créditos (${pkg.name})`;
      unitPrice = pkg.price;
    }
    
    metadata = {
      product: 'security',  // Critical for Router routing
      type: 'credit_recharge',
      package_id: body.package_id,
      account_id: account.id,
      credits: String(pkg.credits),
      is_promo: body.package_id === 'starter' && isFirstPurchase ? 'true' : 'false',
    };
  } else if (body.type === 'subscription') {
    if (!body.plan_id || !(body.plan_id in SUBSCRIPTION_PLANS)) {
      return c.json({ error: 'Invalid plan_id' }, 400);
    }
    const plan = SUBSCRIPTION_PLANS[body.plan_id];
    title = `Anga Security - Plan ${plan.name} (Mensual)`;
    unitPrice = plan.price;
    metadata = {
      type: 'subscription',
      plan_id: body.plan_id,
      account_id: account.id,
    };
  } else {
    return c.json({ error: 'Invalid payment type' }, 400);
  }

  const preference = {
    items: [
      {
        title,
        quantity: 1,
        unit_price: unitPrice,
        currency_id: 'MXN',
      },
    ],
    payer: {
      email: account.email,
    },
    back_urls: {
      success: `${frontendUrl}/es/pago/exito`,
      failure: `${frontendUrl}/es/pago/cancelado`,
      pending: `${frontendUrl}/es/pago/exito`,
    },
    auto_return: 'approved',
    external_reference: account.id,
    metadata,
    notification_url: 'https://webhooks.angaflow.com/mercadopago',
    statement_descriptor: 'ANGA SECURITY',
  };

  // Create preference via MercadoPago API
  const mpResponse = await fetch('https://api.mercadopago.com/checkout/preferences', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${c.env.MERCADOPAGO_ACCESS_TOKEN}`,
    },
    body: JSON.stringify(preference),
  });

  if (!mpResponse.ok) {
    const errorData = await mpResponse.text();
    console.error('MercadoPago error:', errorData);
    return c.json({ error: 'Failed to create payment preference' }, 500);
  }

  const mpData = (await mpResponse.json()) as {
    id: string;
    init_point: string;
    sandbox_init_point: string;
  };

  const checkoutUrl =
    c.env.ENVIRONMENT === 'production' ? mpData.init_point : mpData.sandbox_init_point;

  return c.json({
    preference_id: mpData.id,
    checkout_url: checkoutUrl,
  });
});

// ============================================================
// GET /api/payments/webhooks/mercadopago — MP webhook verification
// ============================================================
payments.get('/webhooks/mercadopago', async (c) => {
  return c.text('OK', 200);
});

// ============================================================
// POST /api/payments/webhooks/internal — Internal webhook from Router
// (Receives pre-validated webhooks from angaflow-webhook-router)
// ============================================================
payments.post('/webhooks/internal', async (c) => {
  try {
    // Validate internal auth header (prevents unauthorized calls)
    const authHeader = c.req.header('X-Internal-Auth');
    const internalSecret = c.env.INTERNAL_WEBHOOK_SECRET || '';
    
    if (!internalSecret || authHeader !== internalSecret) {
      console.error('❌ Unauthorized internal webhook call');
      return c.text('Unauthorized', 401);
    }
    
    console.log('✅ Internal webhook authenticated');
    
    // Parse payload (includes both notification and full payment from Router)
    const body = await c.req.json<{
      notification?: any;
      payment?: any;
    }>();
    
    // Validate we have payment data
    if (!body.payment) {
      console.error('❌ No payment data in internal webhook');
      return c.text('Missing payment data', 400);
    }
    
    const payment = body.payment;
    
    // Validate payment type
    if (body.notification?.type !== 'payment' || !payment.id) {
      console.log('⏭️ Skipping non-payment notification');
      return c.text('OK', 200);
    }
    
    console.log(`🔔 Internal webhook for payment: ${payment.id}`);
    
    const adminClient = getAdminClient(c.env);
    
    // Idempotency check: don't process same payment twice
    const { data: existingLog } = await adminClient
      .from('security_payment_logs')
      .select('id')
      .eq('payment_id', String(payment.id))
      .eq('status', 'approved')
      .single();
    
    if (existingLog) {
      console.log(`⏭️ Payment ${payment.id} already processed, skipping`);
      return c.text('OK', 200);
    }
    
    // Log the payment (with idempotency at DB level)
    const { error: insertError } = await adminClient
      .from('security_payment_logs')
      .insert({
        payment_id: String(payment.id),
        status: payment.status,
        status_detail: payment.status_detail,
        amount: payment.transaction_amount,
        currency: payment.currency_id,
        payer_email: payment.payer?.email,
        external_reference: payment.external_reference,
        payment_type: payment.metadata?.type || 'credit_recharge',
        metadata: payment.metadata,
        raw_data: payment,
      });
    
    if (insertError) {
      console.log(`⏭️ Payment ${payment.id} already logged (concurrent webhook), skipping`);
      return c.text('OK', 200);
    }
    
    // Only process approved payments
    if (payment.status !== 'approved') {
      console.log(`📋 Payment ${payment.id} status: ${payment.status}, not processing credits`);
      return c.text('OK', 200);
    }
    
    const accountId = payment.metadata?.account_id || payment.external_reference;
    const paymentType = payment.metadata?.type;
    
    if (paymentType === 'credit_recharge') {
      const packageId = payment.metadata?.package_id as CreditPackageId | undefined;
      
      if (!packageId || !(packageId in CREDIT_PACKAGES)) {
        console.error(`❌ Invalid or missing package_id: ${packageId}`);
        return c.text('Invalid package', 400);
      }
      
      const expectedPackage = CREDIT_PACKAGES[packageId];
      
      // Check if this was a promo purchase (first purchase gets 50% off on Starter)
      const isPromo = payment.metadata?.is_promo === 'true';
      const expectedPrice = (packageId === 'starter' && isPromo) ? 749 : expectedPackage.price;
      
      // Validate transaction amount
      if (payment.transaction_amount < expectedPrice) {
        console.error(
          `❌ Payment amount ${payment.transaction_amount} less than expected ${expectedPrice}`
        );
        return c.text('Invalid payment amount', 400);
      }
      
      const creditsFromMetadata = parseInt(payment.metadata?.credits || '0', 10);
      const creditsFromPackage = expectedPackage.credits;
      const creditsAmount = creditsFromMetadata || creditsFromPackage;
      
      if (!creditsAmount || creditsAmount <= 0) {
        console.error('❌ Invalid credits amount');
        return c.text('Invalid credits', 400);
      }
      
      const { data: result, error } = await adminClient.rpc('add_security_credits', {
        p_account_id: accountId,
        p_amount: creditsAmount,
        p_payment_id: String(payment.id),
        p_description: `Credit recharge - ${packageId} (${creditsAmount} credits)`,
      });
      
      if (error) {
        console.error('❌ Failed to add credits:', error);
        return c.text('Failed to process payment', 500);
      }
      
      console.log(`✅ Credits added for account ${accountId}:`, result);
    }
    // Note: subscription handling removed (not enabled per user request)
    
    return c.text('OK', 200);
  } catch (err) {
    console.error('❌ Internal webhook processing error:', err);
    return c.text('Internal error', 500);
  }
});

// ============================================================
// POST /api/payments/webhooks/mercadopago — MP webhook handler
// ============================================================
payments.post('/webhooks/mercadopago', async (c) => {
  try {
    const body = await c.req.json<{
      action?: string;
      type?: string;
      data?: { id?: string };
    }>();

    // Only process payment notifications
    if (body.type !== 'payment' || !body.data?.id) {
      return c.text('OK', 200);
    }

    const paymentId = body.data.id;

    // Validate HMAC signature
    const xSignature = c.req.header('x-signature') || '';
    const xRequestId = c.req.header('x-request-id') || '';
    const signatureParts: Record<string, string> = {};
    xSignature.split(',').forEach((part) => {
      const [key, value] = part.split('=');
      if (key && value) signatureParts[key.trim()] = value.trim();
    });

    const ts = signatureParts['ts'] || '';
    const hash = signatureParts['v1'] || '';

    // Fail-closed: reject if signature validation not possible
    if (!c.env.MERCADOPAGO_WEBHOOK_SECRET) {
      console.error('Webhook secret not configured');
      return c.text('Server configuration error', 500);
    }

    if (!xSignature || !xRequestId) {
      console.error('Missing required signature headers');
      return c.text('Missing signature headers', 401);
    }

    if (!ts || !hash) {
      console.error('Missing signature components (ts or v1)');
      return c.text('Invalid signature format', 401);
    }

    const isValid = await validateWebhookSignature(
      c.env.MERCADOPAGO_WEBHOOK_SECRET,
      paymentId,
      xRequestId,
      ts,
      hash
    );
    
    if (!isValid) {
      console.error('Invalid webhook signature');
      return c.text('Invalid signature', 401);
    }

    // Fetch payment details from MercadoPago
    const paymentResponse = await fetch(
      `https://api.mercadopago.com/v1/payments/${paymentId}`,
      {
        headers: { Authorization: `Bearer ${c.env.MERCADOPAGO_ACCESS_TOKEN}` },
      }
    );

    if (!paymentResponse.ok) {
      console.error('Failed to fetch payment:', paymentResponse.status);
      return c.text('Failed to fetch payment', 500);
    }

    const payment = (await paymentResponse.json()) as {
      id: number;
      status: string;
      status_detail: string;
      transaction_amount: number;
      currency_id: string;
      payer: { email: string };
      external_reference: string;
      metadata: {
        type: string;
        package_id?: string;
        plan_id?: string;
        account_id: string;
        credits?: string;
      };
    };

    const adminClient = getAdminClient(c.env);

    // Idempotency check: don't process same payment twice
    const { data: existingLog } = await adminClient
      .from('security_payment_logs')
      .select('id')
      .eq('payment_id', String(payment.id))
      .eq('status', 'approved')
      .single();

    if (existingLog) {
      console.log(`Payment ${payment.id} already processed, skipping`);
      return c.text('OK', 200);
    }

    // Log the payment (with ON CONFLICT DO NOTHING for idempotency at DB level)
    const { error: insertError } = await adminClient
      .from('security_payment_logs')
      .insert({
        payment_id: String(payment.id),
        status: payment.status,
        status_detail: payment.status_detail,
        amount: payment.transaction_amount,
        currency: payment.currency_id,
        payer_email: payment.payer?.email,
        external_reference: payment.external_reference,
        payment_type: payment.metadata?.type || 'credit_recharge',
        metadata: payment.metadata,
        raw_data: payment,
      });

    // If insert failed due to duplicate, it means another webhook already processed it
    if (insertError) {
      console.log(`Payment ${payment.id} already logged (concurrent webhook), skipping`);
      return c.text('OK', 200);
    }

    // Only process approved payments
    if (payment.status !== 'approved') {
      console.log(`Payment ${payment.id} status: ${payment.status}, not processing`);
      return c.text('OK', 200);
    }

    const accountId = payment.metadata?.account_id || payment.external_reference;
    const paymentType = payment.metadata?.type;

    if (paymentType === 'credit_recharge') {
      // Add credits to account — use metadata.credits (actual credit count),
      // NOT transaction_amount (which is the MXN price)
      const packageId = payment.metadata?.package_id as CreditPackageId | undefined;
      
      if (!packageId || !(packageId in CREDIT_PACKAGES)) {
        console.error(`Invalid or missing package_id: ${packageId}`);
        return c.text('Invalid package', 400);
      }

      const expectedPackage = CREDIT_PACKAGES[packageId];
      
      // Check if this was a promo purchase (first purchase gets 50% off on Starter)
      const isPromo = payment.metadata?.is_promo === 'true';
      const expectedPrice = (packageId === 'starter' && isPromo) ? 749 : expectedPackage.price;
      
      // Validate transaction amount matches expected price
      if (payment.transaction_amount < expectedPrice) {
        console.error(
          `Payment amount ${payment.transaction_amount} less than expected ${expectedPrice} for package ${packageId}`
        );
        return c.text('Invalid payment amount', 400);
      }

      const creditsFromMetadata = parseInt(payment.metadata?.credits || '0', 10);
      const creditsFromPackage = expectedPackage.credits;
      
      // Use metadata credits if present, otherwise package credits (NO fallback to transaction_amount)
      const creditsAmount = creditsFromMetadata || creditsFromPackage;
      
      if (!creditsAmount || creditsAmount <= 0) {
        console.error('Invalid credits amount');
        return c.text('Invalid credits', 400);
      }

      const { data: result, error } = await adminClient.rpc('add_security_credits', {
        p_account_id: accountId,
        p_amount: creditsAmount,
        p_payment_id: String(payment.id),
        p_description: `Credit recharge - ${packageId || 'custom'} (${creditsAmount} credits)`,
      });

      if (error) {
        console.error('Failed to add credits:', error);
        return c.text('Failed to process payment', 500);
      }

      console.log(`Credits added for account ${accountId}:`, result);
    } else if (paymentType === 'subscription') {
      // Activate or renew subscription
      const planId = payment.metadata?.plan_id as SubscriptionPlanId | undefined;
      
      if (!planId || !(planId in SUBSCRIPTION_PLANS)) {
        console.error(`Invalid or missing plan_id: ${planId}`);
        return c.text('Invalid plan', 400);
      }

      const expectedPlan = SUBSCRIPTION_PLANS[planId];
      
      // Validate transaction amount matches expected price
      if (payment.transaction_amount < expectedPlan.price) {
        console.error(
          `Payment amount ${payment.transaction_amount} less than expected ${expectedPlan.price} for plan ${planId}`
        );
        return c.text('Invalid payment amount', 400);
      }

      const now = new Date();
      const expiresAt = new Date(now);
      expiresAt.setMonth(expiresAt.getMonth() + 1);

      // Upsert subscription
      await adminClient
        .from('security_subscriptions')
        .upsert(
          {
            account_id: accountId,
            plan_id: planId,
            status: 'active',
            payment_id: String(payment.id),
            started_at: now.toISOString(),
            expires_at: expiresAt.toISOString(),
            next_billing_date: expiresAt.toISOString(),
          },
          { onConflict: 'account_id' }
        );

      console.log(`Subscription ${planId} activated for account ${accountId}`);
    }

    return c.text('OK', 200);
  } catch (err) {
    console.error('Webhook processing error:', err);
    return c.text('Internal error', 500);
  }
});

export default payments;
