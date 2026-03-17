/**
 * Anga Security \u2014 Attack Simulator Phase 1: Intelligence Gathering
 *
 * Reuses the existing CF REST API collectors to map the complete defense posture.
 * This data informs Phase 2 payload selection (e.g., OWASP paranoia level determines
 * which payloads to test, custom rule expressions determine bypass vectors).
 */

import { getZoneInfo, getZoneSettings, getZoneRulesets, getDNSSummary, CfApiError } from '../audit/cf-rest';
import type { SecurityIntelligence } from '../../types/simulation';
import type { CloudflarePlanTier } from '../../types/audit';

// -------- helpers --------

function settingValue(settings: Array<{ id: string; value: unknown }>, key: string): unknown {
  return settings.find((s) => s.id === key)?.value ?? null;
}

function settingBool(settings: Array<{ id: string; value: unknown }>, key: string): boolean {
  const v = settingValue(settings, key);
  return v === 'on' || v === true;
}

function settingStr(settings: Array<{ id: string; value: unknown }>, key: string): string {
  const v = settingValue(settings, key);
  return typeof v === 'string' ? v : '';
}

async function safeCall<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    // Log the error but don't re-throw — simulation should degrade
    // gracefully when individual collectors fail (even on 403).
    // Only Zone:Read is truly fatal, and that's checked before this.
    console.warn('[safeCall] Collector failed, using fallback:', err instanceof CfApiError ? `${err.status} ${err.path}` : (err as Error)?.message);
    return fallback;
  }
}

// -------- IP Access Rules (paginated) --------

const CF_API = 'https://api.cloudflare.com/client/v4';

async function getIPAccessRules(
  zoneId: string,
  token: string,
): Promise<Array<{ mode: string; value: string; notes: string }>> {
  try {
    const res = await fetch(`${CF_API}/zones/${zoneId}/firewall/access_rules/rules?per_page=100`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const json = (await res.json()) as { success: boolean; result: Array<{ mode: string; configuration: { value: string }; notes: string }> };
    if (!json.success) return [];
    return (json.result || []).map((r) => ({
      mode: r.mode,
      value: r.configuration?.value || '',
      notes: r.notes || '',
    }));
  } catch {
    return [];
  }
}

// -------- OWASP Parsing --------

interface OWASPConfig {
  enabled: boolean;
  paranoia_level: number | null;
  score_threshold: string | null;
  action: string | null;
}

function parseOWASPConfig(rulesets: Array<{ phase?: string; rules?: Array<{ action?: string; action_parameters?: { id?: string; overrides?: unknown }; description?: string }> }>): OWASPConfig {
  const result: OWASPConfig = { enabled: false, paranoia_level: null, score_threshold: null, action: null };

  for (const rs of rulesets) {
    if (rs.phase !== 'http_request_firewall_managed') continue;
    for (const rule of rs.rules || []) {
      const ap = rule.action_parameters as { id?: string; overrides?: { rules?: Array<{ id: string; enabled?: boolean; action?: string; score_threshold?: string }>; categories?: Array<{ category: string; enabled?: boolean }> } } | undefined;
      if (!ap?.id) continue;

      // OWASP Core Ruleset ID ends with c25d2f1f
      const isOWASP = ap.id.endsWith('c25d2f1f') ||
        (rule.description || '').toLowerCase().includes('owasp');

      if (isOWASP) {
        result.enabled = true;
        result.action = rule.action || 'managed_challenge';

        // Parse overrides for paranoia level
        const cats = ap.overrides?.categories || [];
        let maxDisabled = 0;
        for (const cat of cats) {
          if (cat.enabled === false) {
            const m = cat.category.match(/paranoia-level-(\d)/);
            if (m) maxDisabled = Math.max(maxDisabled, parseInt(m[1], 10));
          }
        }
        // If PL3 and PL4 are disabled, paranoia is PL2
        result.paranoia_level = maxDisabled > 0 ? maxDisabled - 1 : 1;

        // Parse score threshold from rule overrides
        const ruleOverrides = ap.overrides?.rules || [];
        for (const ro of ruleOverrides) {
          if (ro.score_threshold) result.score_threshold = ro.score_threshold;
        }
        if (!result.score_threshold) result.score_threshold = 'medium'; // default
      }
    }
  }

  return result;
}

// -------- Custom Rules Parsing --------

interface ParsedCustomRule {
  id: string;
  description: string;
  expression: string;
  action: string;
  enabled: boolean;
}

function parseCustomRules(rulesets: Array<{ phase?: string; rules?: Array<{ id?: string; description?: string; expression?: string; action?: string; enabled?: boolean }> }>): ParsedCustomRule[] {
  const rules: ParsedCustomRule[] = [];
  for (const rs of rulesets) {
    if (rs.phase !== 'http_request_firewall_custom') continue;
    for (const rule of rs.rules || []) {
      if (rule.expression) {
        rules.push({
          id: rule.id || '',
          description: rule.description || '',
          expression: rule.expression,
          action: rule.action || 'block',
          enabled: rule.enabled !== false,
        });
      }
    }
  }
  return rules;
}

// -------- Rate Limit Parsing --------

interface ParsedRateLimit {
  id: string;
  description: string;
  expression: string;
  period: number;
  requests_per_period: number;
  mitigation_timeout: number;
  action: string;
}

function parseRateLimits(rulesets: Array<{ phase?: string; rules?: Array<Record<string, unknown>> }>): ParsedRateLimit[] {
  const rules: ParsedRateLimit[] = [];
  for (const rs of rulesets) {
    if (rs.phase !== 'http_ratelimit') continue;
    for (const rule of rs.rules || []) {
      const rl = rule.ratelimit as { period?: number; requests_per_period?: number; mitigation_timeout?: number } | undefined;
      rules.push({
        id: (rule.id as string) || '',
        description: (rule.description as string) || '',
        expression: (rule.expression as string) || '',
        period: rl?.period || 60,
        requests_per_period: rl?.requests_per_period || 100,
        mitigation_timeout: rl?.mitigation_timeout || 60,
        action: (rule.action as string) || 'block',
      });
    }
  }
  return rules;
}

// -------- Bot Management Detection --------

function detectBotManagement(
  settings: Array<{ id: string; value: unknown }>,
  customRules: ParsedCustomRule[],
): SecurityIntelligence['bot_management'] {
  const bm = settingValue(settings, 'bot_management') as { enable_js?: boolean } | null;
  const sbfm = settingValue(settings, 'security_header') as { strict_transport_security?: { enabled?: boolean } } | null;

  // Check if any custom rule references cf.bot_management.score
  const botScoreRules = customRules.some(
    (r) => r.expression.includes('cf.bot_management.score') || r.expression.includes('cf.bot_management.verified_bot'),
  );

  return {
    enabled: bm != null && typeof bm === 'object',
    sbfm_enabled: settingBool(settings, 'browser_check'),
    js_detection_enabled: bm != null && typeof bm === 'object' && (bm as { enable_js?: boolean }).enable_js === true,
    bot_score_rules: botScoreRules,
  };
}

// -------- Discover API / Auth Paths from custom rules --------

function discoverPaths(customRules: ParsedCustomRule[]): { api_paths: string[]; auth_paths: string[] } {
  const apiPaths = new Set<string>();
  const authPaths = new Set<string>();
  const apiPatterns = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'];
  const authPatterns = ['/login', '/signin', '/auth', '/token', '/oauth', '/register', '/signup'];

  for (const rule of customRules) {
    const expr = rule.expression.toLowerCase();
    // Extract path literals from expressions like: http.request.uri.path contains "/admin"
    const pathMatches = expr.match(/(?:uri\.path|uri)\s+(?:contains|eq|matches)\s+"([^"]+)"/g) || [];
    for (const pm of pathMatches) {
      const val = pm.match(/"([^"]+)"/)?.[1] || '';
      if (apiPatterns.some((p) => val.includes(p))) apiPaths.add(val);
      if (authPatterns.some((p) => val.includes(p))) authPaths.add(val);
    }
  }

  // Always include common defaults
  apiPaths.add('/api/');
  authPaths.add('/login');
  authPaths.add('/wp-login.php');

  return { api_paths: [...apiPaths], auth_paths: [...authPaths] };
}

// ════════════════════════════════════════════════════════════════════
// Main Export: Gather Intelligence
// ════════════════════════════════════════════════════════════════════

export async function gatherIntelligence(
  zoneId: string,
  apiToken: string,
): Promise<SecurityIntelligence> {
  // ---- Parallel fetch of all CF API data ----
  const [zoneInfo, zoneSettings, rulesets, dnsSummary, ipRules] = await Promise.all([
    getZoneInfo(zoneId, apiToken),
    getZoneSettings(zoneId, apiToken),
    safeCall(() => getZoneRulesets(zoneId, apiToken), []),
    safeCall(() => getDNSSummary(zoneId, apiToken), {
      total_records: 0,
      proxied_count: 0,
      dns_only_count: 0,
      record_types: {},
      dnssec_enabled: false,
    }),
    getIPAccessRules(zoneId, apiToken),
  ]);

  // ---- Parse the data ----
  const plan = (zoneInfo.plan?.legacy_id || 'free') as CloudflarePlanTier;
  const owaspConfig = parseOWASPConfig(rulesets as Array<Record<string, unknown>>);
  const customRules = parseCustomRules(rulesets as Array<Record<string, unknown>>);
  const rateLimits = parseRateLimits(rulesets as Array<Record<string, unknown>>);
  const botMgmt = detectBotManagement(zoneSettings as Array<{ id: string; value: unknown }>, customRules);
  const { api_paths, auth_paths } = discoverPaths(customRules);

  // Check for attack score rules
  const attackScoreRules = customRules.some(
    (r) => r.expression.includes('cf.waf.score') || r.expression.includes('cf.waf.score.'),
  );

  // Check leaked credentials detection
  const leakedCreds = customRules.some(
    (r) => r.expression.includes('cf.waf.credential_check'),
  );

  // HSTS parsing
  const hstsHeader = settingValue(zoneSettings as Array<{ id: string; value: unknown }>, 'security_header') as {
    strict_transport_security?: {
      enabled?: boolean;
      max_age?: number;
      include_subdomains?: boolean;
      preload?: boolean;
    };
  } | null;
  const hsts = hstsHeader?.strict_transport_security;

  // Count managed rules
  let managedRuleCount = 0;
  for (const rs of rulesets as Array<{ phase?: string; rules?: Array<Record<string, unknown>> }>) {
    if (rs.phase === 'http_request_firewall_managed') {
      managedRuleCount += (rs.rules || []).length;
    }
  }

  return {
    zone_name: zoneInfo.name,
    cf_plan: plan,
    waf: {
      managed_rules_enabled: managedRuleCount > 0,
      cf_managed_ruleset: (rulesets as Array<{ phase?: string; rules?: Array<{ action_parameters?: { id?: string } }> }>).some((rs) =>
        rs.phase === 'http_request_firewall_managed' &&
        (rs.rules || []).some((r) => {
          const id = r.action_parameters?.id || '';
          return id.endsWith('6179ae15') || id.includes('efb7b8c9'); // CF Managed Ruleset IDs
        }),
      ),
      owasp_enabled: owaspConfig.enabled,
      owasp_paranoia_level: owaspConfig.paranoia_level,
      owasp_score_threshold: owaspConfig.score_threshold,
      owasp_action: owaspConfig.action,
      attack_score_rules: attackScoreRules,
      managed_rule_count: managedRuleCount,
    },
    custom_rules: {
      total: customRules.length,
      rules: customRules,
    },
    rate_limits: {
      total: rateLimits.length,
      rules: rateLimits,
    },
    bot_management: botMgmt,
    ssl_tls: {
      ssl_mode: settingStr(zoneSettings as Array<{ id: string; value: unknown }>, 'ssl'),
      min_tls_version: settingStr(zoneSettings as Array<{ id: string; value: unknown }>, 'min_tls_version'),
      tls_1_3: settingStr(zoneSettings as Array<{ id: string; value: unknown }>, 'tls_1_3'),
      always_use_https: settingBool(zoneSettings as Array<{ id: string; value: unknown }>, 'always_use_https'),
      hsts_enabled: hsts?.enabled || false,
      hsts_max_age: hsts?.max_age || 0,
      hsts_include_subdomains: hsts?.include_subdomains || false,
      hsts_preload: hsts?.preload || false,
    },
    security: {
      security_level: settingStr(zoneSettings as Array<{ id: string; value: unknown }>, 'security_level'),
      browser_check: settingBool(zoneSettings as Array<{ id: string; value: unknown }>, 'browser_check'),
      challenge_ttl: Number(settingValue(zoneSettings as Array<{ id: string; value: unknown }>, 'challenge_ttl')) || 1800,
      privacy_pass: settingBool(zoneSettings as Array<{ id: string; value: unknown }>, 'privacy_pass'),
      leaked_credentials_enabled: leakedCreds,
      cache_deception_armor: false, // Requires cache rules API, approximated
      hotlink_protection: settingBool(zoneSettings as Array<{ id: string; value: unknown }>, 'hotlink_protection'),
      email_obfuscation: settingBool(zoneSettings as Array<{ id: string; value: unknown }>, 'email_address_obfuscation'),
    },
    dns: {
      total_records: dnsSummary.total_records,
      proxied_records: dnsSummary.proxied_count,
      unproxied_records: dnsSummary.dns_only_count,
      dnssec_active: dnsSummary.dnssec_enabled,
    },
    ip_access_rules: ipRules,
    api_paths,
    auth_paths,
  };
}
