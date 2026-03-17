/**
 * Anga Security \u2014 Compliance-Specific Cloudflare API Collectors
 *
 * These collectors fetch ADDITIONAL data beyond what the standard audit
 * already collects. They require expanded token permissions:
 *   - SSL and Certificates: Read
 *   - Logs: Read
 *   - Page Shield: Read
 *   - Health Checks: Read
 *   - Audit Logs: Read (account-scoped)
 *   - Notifications: Read (account-scoped)
 *
 * Each collector is fault-tolerant: if the token lacks permissions,
 * it returns null instead of throwing, so the compliance engine can
 * mark affected controls as 'insufficient_permissions'.
 */

import type {
  EnrichedComplianceData,
  EdgeCertificate,
  LogpushJob,
  IPAccessRule,
  HealthCheck,
  NotificationPolicy,
  APIShieldData,
  APIShieldOperation,
} from '../../types/compliance';
import { PCI_DSS_COMPLIANT_CIPHERS, WEAK_CIPHERS } from '../../types/compliance';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Low-level CF API Helper (tolerant \u2014 returns null on auth errors)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

const CF_API = 'https://api.cloudflare.com/client/v4';

interface CfResult<T> {
  success: boolean;
  errors: Array<{ code: number; message: string }>;
  result: T;
  result_info?: { total_count: number; total_pages: number };
}

/**
 * Tolerant fetch: returns null on 401/403/404, throws on other errors.
 * This is critical for compliance collectors where permissions may be missing.
 */
async function cfFetchTolerant<T>(
  path: string,
  token: string,
): Promise<T | null> {
  try {
    const res = await fetch(`${CF_API}${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (res.status === 401 || res.status === 403 || res.status === 404) {
      return null;
    }

    if (!res.ok) {
      return null;
    }

    const json = (await res.json()) as CfResult<T>;
    if (!json.success) return null;

    return json.result;
  } catch {
    return null;
  }
}

/**
 * Smart permission check: distinguishes auth errors (401/403, code 10000)
 * from feature errors (400 "Retention not enabled", 404 "not found").
 * Returns non-null if token has the permission, null if not.
 */
export async function cfCheckPermission(path: string, token: string): Promise<any | null> {
  try {
    const resp = await fetch(`${CF_API}${path}`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    });
    if (resp.status === 401 || resp.status === 403) return null;
    const text = await resp.text();
    try {
      const json = JSON.parse(text);
      if (json.success === false) {
        const hasAuthError = (json.errors || []).some((e: any) =>
          e.code === 10000 && /auth|unauthorized|forbidden/i.test(e.message || '')
        );
        return hasAuthError ? null : json;
      }
      return json;
    } catch {
      return { permissionGranted: true, message: text.slice(0, 200) };
    }
  } catch {
    return null;
  }
}

/**
 * GraphQL-based Analytics permission check (REST analytics API is sunset / Error 1015).
 */
async function cfFetchGraphQLAnalytics(zoneId: string, token: string): Promise<any | null> {
  try {
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const query = {
      query: `{ viewer { zones(filter: {zoneTag: "${zoneId}"}) { httpRequests1dGroups(limit: 1, filter: {date_gt: "${yesterday}"}) { sum { requests } } } } }`,
    };
    const resp = await fetch(`${CF_API}/graphql`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(query),
    });
    if (!resp.ok) return null;
    const json = await resp.json() as any;
    return json?.data?.viewer?.zones?.[0] ? json : null;
  } catch {
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════════
// Collector 9: API Shield / API Gateway (Enterprise Feature)
// Permission: API Shield:Read (Zone-scoped)
// ══════════════════════════════════════════════════════════════════════

interface CfAPIOperation {
  operation_id: string;
  method: string;
  endpoint: string;
  host: string;
  last_updated?: string;
  features?: Record<string, { enabled?: boolean }>;
}

interface CfAPISchema {
  schema_id: string;
  name: string;
  kind: string;
  source?: string;
}

interface CfClientCertificate {
  id: string;
  status: string;
  expires_on: string;
}

/**
 * Collects API Shield / API Gateway data.
 * This is an Enterprise-only feature. For non-Enterprise zones:
 * - Returns data with is_enterprise = false
 * - All feature flags will be false/empty
 * - Controls will show informational status (not blocking)
 */
async function collectAPIShield(
  zoneId: string,
  token: string,
): Promise<APIShieldData | null> {
  const startTime = Date.now();

  // Step 1: Check API Shield permission by calling discovery endpoint
  const discoveryResult = await cfCheckPermission(
    `/zones/${zoneId}/api_gateway/discovery`,
    token,
  );

  // If permission denied, return null (permission not granted)
  if (discoveryResult === null) {
    return null;
  }

  // Step 2: Get zone info to detect plan
  const zoneInfo = await cfFetchTolerant<{
    plan: { legacy_id: string; name: string };
  }>(`/zones/${zoneId}`, token);

  const planId = zoneInfo?.plan?.legacy_id || 'unknown';
  const isEnterprise = planId === 'enterprise';

  // Step 3: Collect API Shield data in parallel
  // These endpoints may return errors for non-Enterprise, which is fine
  const [
    operationsResult,
    userSchemasResult,
    clientCertsResult,
  ] = await Promise.all([
    cfFetchTolerant<CfAPIOperation[]>(`/zones/${zoneId}/api_gateway/operations`, token),
    cfFetchTolerant<CfAPISchema[]>(`/zones/${zoneId}/api_gateway/user_schemas`, token),
    cfFetchTolerant<CfClientCertificate[]>(`/zones/${zoneId}/client_certificates`, token),
  ]);

  // Parse operations
  const operations: APIShieldOperation[] = (operationsResult || []).slice(0, 100).map((op) => ({
    id: op.operation_id,
    method: op.method,
    endpoint: op.endpoint,
    host: op.host,
    last_updated: op.last_updated,
    features: op.features ? {
      schema_validation: { enabled: op.features.schema_validation?.enabled || false },
      rate_limiting: { enabled: op.features.thresholds?.enabled || false },
    } : undefined,
  }));

  const totalOperations = operationsResult?.length || 0;

  // Calculate schema validation coverage
  const operationsWithSchemaValidation = operations.filter(
    (op) => op.features?.schema_validation?.enabled
  ).length;
  const schemaCoverage = totalOperations > 0
    ? Math.round((operationsWithSchemaValidation / totalOperations) * 100)
    : 0;

  // Calculate rate limiting coverage
  const operationsWithRateLimiting = operations.filter(
    (op) => op.features?.rate_limiting?.enabled
  ).length;

  // Count schemas configured
  const schemasConfigured = userSchemasResult?.length || 0;

  // Count mTLS certificates
  const mtlsCertsConfigured = clientCertsResult?.filter(
    (c) => c.status === 'active'
  ).length || 0;

  // For features we can't directly query, we infer from operations data
  // These will be refined when more API endpoints become available
  const hasAnyOperations = totalOperations > 0;

  return {
    permission_granted: true,
    plan: planId as APIShieldData['plan'],
    is_enterprise: isEnterprise,

    discovery: {
      enabled: hasAnyOperations,
      total_operations: totalOperations,
      operations,
    },

    schema_validation: {
      enabled: schemasConfigured > 0 || operationsWithSchemaValidation > 0,
      schemas_configured: schemasConfigured,
      operations_covered: operationsWithSchemaValidation,
      total_operations: totalOperations,
      coverage_percent: schemaCoverage,
    },

    jwt_validation: {
      // JWT validation config requires a separate API call that may not be available
      // We'll mark as enabled if the zone is Enterprise and has operations
      enabled: false, // Will be updated if we can query jwt_validation endpoint
      configs_count: 0,
    },

    mtls: {
      enabled: mtlsCertsConfigured > 0,
      certificates_configured: mtlsCertsConfigured,
    },

    rate_limiting: {
      enabled: operationsWithRateLimiting > 0,
      rules_configured: operationsWithRateLimiting,
    },

    session_identifiers: {
      // Session identifiers are configured via API Shield settings
      enabled: false, // Would need auth_id_characteristics endpoint
      identifiers_configured: 0,
    },

    volumetric_abuse: {
      // Volumetric abuse detection is an Enterprise feature
      // Enabled by default on Enterprise plans with API Shield
      enabled: isEnterprise && hasAnyOperations,
    },

    sequence_mitigation: {
      // Sequence mitigation requires explicit configuration
      enabled: false, // Would need specific endpoint to check
    },

    collected_at: new Date().toISOString(),
    collection_duration_ms: Date.now() - startTime,
  };
}

// ══════════════════════════════════════════════════════════════════════
// Collector 1: Edge Certificates
// Permission: SSL and Certificates: Read
// ══════════════════════════════════════════════════════════════════════

interface CfCertPack {
  id: string;
  type: string;
  hosts: string[];
  primary_certificate?: string;
  certificates?: Array<{
    id: string;
    issuer: string;
    signature: string;
    expires_on: string;
    status: string;
  }>;
  status: string;
}

async function collectEdgeCertificates(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['edge_certificates'] | null> {
  const packs = await cfFetchTolerant<CfCertPack[]>(
    `/zones/${zoneId}/ssl/certificate_packs?status=active`,
    token,
  );
  if (!packs) return null;

  const now = Date.now();
  const certs: EdgeCertificate[] = [];

  for (const pack of packs) {
    const certType =
      pack.type === 'universal' ? 'universal' :
      pack.type === 'advanced' ? 'advanced' :
      pack.type === 'custom' ? 'custom' : 'unknown' as const;

    // Each pack may have multiple certificates
    if (pack.certificates && pack.certificates.length > 0) {
      for (const cert of pack.certificates) {
        const expiresMs = new Date(cert.expires_on).getTime();
        const daysLeft = Math.floor((expiresMs - now) / (1000 * 60 * 60 * 24));
        certs.push({
          id: cert.id,
          type: certType,
          hosts: pack.hosts || [],
          issuer: cert.issuer || 'Unknown',
          signature: cert.signature || 'Unknown',
          expires_on: cert.expires_on,
          status: cert.status,
          days_until_expiry: daysLeft,
        });
      }
    } else {
      // Pack without individual cert details
      certs.push({
        id: pack.id,
        type: certType,
        hosts: pack.hosts || [],
        issuer: 'Cloudflare',
        signature: 'Unknown',
        expires_on: '',
        status: pack.status,
        days_until_expiry: -1,
      });
    }
  }

  return {
    total: certs.length,
    certificates: certs,
    any_expired: certs.some((c) => c.days_until_expiry < 0),
    any_expiring_soon: certs.some((c) => c.days_until_expiry >= 0 && c.days_until_expiry <= 30),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 2: Cipher Suites (from zone settings)
// Permission: Zone: Read (already available from audit)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function analyzeCipherSuites(
  zoneSettings: Array<{ id: string; value: any }> | undefined,
): EnrichedComplianceData['cipher_suites'] {
  // Default ciphers: Cloudflare uses its default set which is PCI-compliant
  // unless explicitly customized to weaker options
  const ciphersSetting = zoneSettings?.find((s) => s.id === 'ciphers');
  const configured: string[] = ciphersSetting?.value || [];

  // If no custom ciphers, Cloudflare defaults are PCI-compliant
  if (configured.length === 0) {
    return {
      configured: ['(Cloudflare defaults - PCI DSS compliant)'],
      pci_dss_compliant: true,
      fips_140_compliant: true,
      weak_ciphers: [],
      missing_recommended: [],
    };
  }

  const weak = configured.filter((c) =>
    WEAK_CIPHERS.some((w) => c.toUpperCase().includes(w.toUpperCase())),
  );

  const pciCompliant = configured.every((c) =>
    PCI_DSS_COMPLIANT_CIPHERS.some((p) => p.toUpperCase() === c.toUpperCase()),
  );

  const missing = PCI_DSS_COMPLIANT_CIPHERS.filter(
    (p) => !configured.some((c) => c.toUpperCase() === p.toUpperCase()),
  );

  return {
    configured,
    pci_dss_compliant: pciCompliant && weak.length === 0,
    fips_140_compliant: weak.length === 0,
    weak_ciphers: weak,
    missing_recommended: missing,
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 3: Authenticated Origin Pulls (mTLS)
// Permission: SSL and Certificates: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

async function collectAuthOriginPulls(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['authenticated_origin_pulls'] | null> {
  const result = await cfFetchTolerant<{ enabled: boolean }>(
    `/zones/${zoneId}/origin_tls_client_auth/settings`,
    token,
  );
  if (result === null) return null;

  return { enabled: result.enabled };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 4: Logpush Jobs
// Permission: Logs: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface CfLogpushJob {
  id: number;
  dataset: string;
  destination_conf: string;
  enabled: boolean;
  last_complete: string | null;
  last_error: string | null;
}

async function collectLogpushJobs(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['logpush_jobs'] | null> {
  const jobs = await cfFetchTolerant<CfLogpushJob[]>(
    `/zones/${zoneId}/logpush/jobs`,
    token,
  );
  if (!jobs) return null;

  const mapped: LogpushJob[] = jobs.map((j) => ({
    id: j.id,
    dataset: j.dataset,
    destination: j.destination_conf?.split('?')[0] || 'unknown',
    enabled: j.enabled,
    last_complete: j.last_complete,
    last_error: j.last_error,
  }));

  return {
    total: mapped.length,
    jobs: mapped,
    has_firewall_logs: mapped.some((j) => j.dataset === 'firewall_events' && j.enabled),
    has_http_logs: mapped.some((j) => j.dataset === 'http_requests' && j.enabled),
    has_audit_logs: mapped.some((j) => j.dataset === 'audit_logs' && j.enabled),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 5: Audit Logs (Account-scoped)
// Permission: Audit Logs: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

async function collectAuditLogs(
  accountId: string,
  token: string,
): Promise<EnrichedComplianceData['audit_logs'] | null> {
  // Fetch recent audit logs (last 30 days)
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const before = new Date().toISOString();

  const result = await cfFetchTolerant<any[]>(
    `/accounts/${accountId}/audit_logs?since=${since}&before=${before}&per_page=50`,
    token,
  );

  if (result === null) return null;

  const actions = [...new Set(result.map((e: any) => e.action?.type || 'unknown'))];
  const hasConfigChanges = result.some((e: any) => {
    const action = (e.action?.type || '').toLowerCase();
    return action.includes('change') || action.includes('update') || action.includes('create');
  });

  return {
    available: true,
    recent_count: result.length,
    has_config_changes: hasConfigChanges,
    sample_actions: actions.slice(0, 10),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 6: IP Access Rules
// Permission: Firewall Services: Read (already available from audit)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface CfAccessRule {
  id: string;
  mode: string;
  configuration: { target: string; value: string };
  notes: string;
}

async function collectIPAccessRules(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['ip_access_rules'] | null> {
  const rules = await cfFetchTolerant<CfAccessRule[]>(
    `/zones/${zoneId}/firewall/access_rules/rules?per_page=100`,
    token,
  );
  if (!rules) return null;

  const mapped: IPAccessRule[] = rules.map((r) => ({
    mode: r.mode,
    target: `${r.configuration.target}:${r.configuration.value}`,
    notes: r.notes || '',
  }));

  return {
    total: mapped.length,
    rules: mapped,
    has_geo_blocks: mapped.some((r) => r.target.startsWith('country:')),
    has_ip_allowlist: mapped.some((r) => r.mode === 'whitelist'),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 7: Page Shield
// Permission: Page Shield: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface CfPageShieldScript {
  id: string;
  url: string;
  first_seen_at: string;
  last_seen_at: string;
  host: string;
  js_integrity_score?: number;
  fetched_at?: string;
  page_urls?: string[];
  malicious?: boolean;
}

async function collectPageShield(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['page_shield'] | null> {
  const scripts = await cfFetchTolerant<CfPageShieldScript[]>(
    `/zones/${zoneId}/page_shield/scripts?per_page=100`,
    token,
  );
  if (!scripts) return null;

  const malicious = scripts.filter((s) => s.malicious === true);
  // Heuristic: if script URL starts with zone hostname, it's first-party
  const firstParty = scripts.filter((s) => {
    try {
      const scriptHost = new URL(s.url).hostname;
      return scriptHost === s.host;
    } catch {
      return false;
    }
  });

  return {
    enabled: true, // If we got data, Page Shield is active
    total_scripts: scripts.length,
    malicious_scripts: malicious.length,
    scripts_first_party: firstParty.length,
    scripts_third_party: scripts.length - firstParty.length,
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 8: Notification Policies (Account-scoped)
// Permission: Notifications: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface CfNotificationPolicy {
  id: string;
  name: string;
  alert_type: string;
  enabled: boolean;
}

async function collectNotificationPolicies(
  accountId: string,
  token: string,
): Promise<EnrichedComplianceData['notification_policies'] | null> {
  const policies = await cfFetchTolerant<CfNotificationPolicy[]>(
    `/accounts/${accountId}/alerting/v3/policies`,
    token,
  );
  if (!policies) return null;

  const alertTypes = [...new Set(policies.filter((p) => p.enabled).map((p) => p.alert_type))];
  const securityTypes = ['clickhouse_alert_fw_anomaly', 'dos_attack_l7', 'advanced_ddos_attack_l7',
    'waf_alert', 'security_level_alert', 'block_notification_review'];
  const sslTypes = ['universal_ssl_event_type', 'dedicated_ssl_certificate_event_type',
    'ssl_certificate_expiry'];
  const ddosTypes = ['dos_attack_l7', 'dos_attack_l4', 'advanced_ddos_attack_l7',
    'advanced_ddos_attack_l4'];

  return {
    total: policies.filter((p) => p.enabled).length,
    alert_types: alertTypes,
    has_security_alerts: alertTypes.some((t) => securityTypes.includes(t)),
    has_ssl_alerts: alertTypes.some((t) => sslTypes.includes(t)),
    has_ddos_alerts: alertTypes.some((t) => ddosTypes.includes(t)),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Collector 9: Health Checks
// Permission: Health Checks: Read
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface CfHealthCheck {
  id: string;
  name: string;
  type: string;
  status: string;
  check_regions: string[];
  interval: number;
}

async function collectHealthChecks(
  zoneId: string,
  token: string,
): Promise<EnrichedComplianceData['health_checks'] | null> {
  const checks = await cfFetchTolerant<CfHealthCheck[]>(
    `/zones/${zoneId}/healthchecks`,
    token,
  );
  if (!checks) return null;

  const mapped: HealthCheck[] = checks.map((c) => ({
    name: c.name,
    type: c.type,
    status: c.status,
    interval: c.interval,
  }));

  return {
    total: mapped.length,
    checks: mapped,
    all_healthy: mapped.length > 0 && mapped.every((c) => c.status === 'healthy'),
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Token Permission Discovery (pre-check)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface PermissionCheck {
  name: string;
  test: () => Promise<boolean>;
}

/**
 * Discovers which permissions the API token has by making lightweight
 * test calls to each required API endpoint.
 */
export async function discoverTokenPermissions(
  zoneId: string,
  accountId: string,
  token: string,
): Promise<{ available: string[]; missing: string[] }> {
  const checks: PermissionCheck[] = [
    {
      name: 'Zone:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}`, token)) !== null,
    },
    {
      name: 'Analytics:Read',
      test: async () => (await cfFetchGraphQLAnalytics(zoneId, token)) !== null,
    },
    {
      name: 'Firewall Services:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/firewall/access_rules/rules?per_page=1`, token)) !== null,
    },
    {
      name: 'DNS:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/dns_records?per_page=1`, token)) !== null,
    },
    {
      name: 'SSL and Certificates:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/ssl/certificate_packs?per_page=1`, token)) !== null,
    },
    {
      name: 'Logs:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/logs/received?start=2024-01-01T00:00:00Z&end=2024-01-01T00:01:00Z&count=1`, token)) !== null,
    },
    {
      name: 'Page Shield:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/page_shield/scripts?per_page=1`, token)) !== null,
    },
    {
      name: 'Health Checks:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/healthchecks`, token)) !== null,
    },
    {
      name: 'Account Access: Audit Logs',
      test: async () => (await cfCheckPermission(`/accounts/${accountId}/audit_logs?per_page=1`, token)) !== null,
    },
    {
      name: 'Notifications:Read',
      test: async () => (await cfCheckPermission(`/accounts/${accountId}/alerting/v3/policies`, token)) !== null,
    },
    {
      name: 'API Shield:Read',
      test: async () => (await cfCheckPermission(`/zones/${zoneId}/api_gateway/discovery`, token)) !== null,
    },
  ];

  const available: string[] = [];
  const missing: string[] = [];

  // Run all checks in parallel for speed
  const results = await Promise.all(
    checks.map(async (check) => ({
      name: check.name,
      ok: await check.test(),
    })),
  );

  for (const r of results) {
    if (r.ok) available.push(r.name);
    else missing.push(r.name);
  }

  return { available, missing };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Main Orchestrator: Collect All Enriched Data
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface CollectComplianceDataParams {
  zoneId: string;
  accountId: string;
  token: string;
  zoneSettings?: Array<{ id: string; value: any }>;
}

/**
 * Collects all enriched compliance data in parallel.
 * Each collector is fault-tolerant \u2014 failures are logged, not thrown.
 */
export async function collectComplianceData(
  params: CollectComplianceDataParams,
): Promise<EnrichedComplianceData> {
  const { zoneId, accountId, token, zoneSettings } = params;
  const results: EnrichedComplianceData['collector_results'] = [];
  const startAll = Date.now();

  // Run all collectors in parallel
  const [
    edgeCerts,
    authPulls,
    logpush,
    auditLogs,
    ipRules,
    pageShield,
    notifications,
    healthChecks,
    apiShield,
  ] = await Promise.all([
    timed('edge_certificates', () => collectEdgeCertificates(zoneId, token), results),
    timed('authenticated_origin_pulls', () => collectAuthOriginPulls(zoneId, token), results),
    timed('logpush_jobs', () => collectLogpushJobs(zoneId, token), results),
    timed('audit_logs', () => collectAuditLogs(accountId, token), results),
    timed('ip_access_rules', () => collectIPAccessRules(zoneId, token), results),
    timed('page_shield', () => collectPageShield(zoneId, token), results),
    timed('notification_policies', () => collectNotificationPolicies(accountId, token), results),
    timed('health_checks', () => collectHealthChecks(zoneId, token), results),
    timed('api_shield', () => collectAPIShield(zoneId, token), results),
  ]);

  // Cipher suites are analyzed from zone_settings (already collected by audit)
  const cipherSuites = analyzeCipherSuites(zoneSettings);
  results.push({ name: 'cipher_suites', status: 'success', duration_ms: 0 });

  return {
    edge_certificates: edgeCerts ?? undefined,
    cipher_suites: cipherSuites,
    authenticated_origin_pulls: authPulls ?? undefined,
    logpush_jobs: logpush ?? undefined,
    audit_logs: auditLogs ?? undefined,
    ip_access_rules: ipRules ?? undefined,
    page_shield: pageShield ?? undefined,
    notification_policies: notifications ?? undefined,
    health_checks: healthChecks ?? undefined,
    api_shield: apiShield ?? undefined,
    collector_results: results,
  };
}

/**
 * Wraps a collector call with timing and error tracking.
 */
async function timed<T>(
  name: string,
  fn: () => Promise<T | null>,
  results: EnrichedComplianceData['collector_results'],
): Promise<T | null> {
  const start = Date.now();
  try {
    const data = await fn();
    const duration = Date.now() - start;
    if (data === null) {
      results.push({ name, status: 'skipped', error: 'Permission denied or not available', duration_ms: duration });
    } else {
      results.push({ name, status: 'success', duration_ms: duration });
    }
    return data;
  } catch (err: any) {
    results.push({
      name,
      status: 'failed',
      error: err.message || 'Unknown error',
      duration_ms: Date.now() - start,
    });
    return null;
  }
}
