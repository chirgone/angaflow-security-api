/**
 * Anga Security \u2014 Attack Simulator Phase 2: Active Probing
 *
 * Executes 75+ attack payloads against the target domain via HTTP.
 * Analyzes Cloudflare-specific response headers (cf-mitigated, cf-ray,
 * cf-cache-status) to determine whether attacks were blocked, challenged,
 * or bypassed.
 *
 * Uses conservative rate limiting: 10-20 request bursts max.
 * All requests come from Cloudflare Workers outbound IPs.
 */

import type {
  AttackTestResult,
  AttackOutcome,
  AttackModuleId,
  SecurityIntelligence,
} from '../../types/simulation';
import type { PayloadDefinition } from './payloads';
import { STATIC_PAYLOADS, buildCustomRuleBypassPayloads } from './payloads';

// ════════════════════════════════════════════════════════════════════
// HTTP Client
// ════════════════════════════════════════════════════════════════════

const SCANNER_UA = 'AngaSecurity/1.0 (+https://angaflow.com; attack-simulator)';
const DEFAULT_TIMEOUT = 5_000; // Reduced from 10s to 5s to stay within Worker limits
const GLOBAL_PHASE2_TIMEOUT = 15_000; // Hard ceiling for all attacks (need room for Phase 1+3+DB)

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': SCANNER_UA,
        ...(options.headers || {}),
      },
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

// ════════════════════════════════════════════════════════════════════
// Response Analysis
// ════════════════════════════════════════════════════════════════════

interface AnalyzedResponse {
  status_code: number;
  response_time_ms: number;
  headers: Record<string, string>;
  cf_mitigated: boolean;
  cf_ray: string | null;
  cf_cache_status: string | null;
  body_preview: string;
  challenge_type: AttackTestResult['response']['challenge_type'];
  outcome: AttackOutcome;
}

function getHeader(headers: Headers, name: string): string | null {
  return headers.get(name);
}

function detectChallengeType(
  headers: Headers,
  bodyPreview: string,
): AttackTestResult['response']['challenge_type'] {
  // Primary detection: cf-mitigated header
  if (getHeader(headers, 'cf-mitigated') === 'challenge') {
    // Try to detect specific challenge type from body
    if (bodyPreview.includes('/cdn-cgi/challenge-platform/')) {
      if (bodyPreview.includes('managed')) return 'managed_challenge';
      if (bodyPreview.includes('jschallenge') || bodyPreview.includes('js_challenge')) return 'js_challenge';
      return 'managed_challenge'; // default for cf-mitigated
    }
    return 'managed_challenge';
  }

  // Secondary: check content-type is HTML when it shouldn't be (challenge page served)
  const ct = getHeader(headers, 'content-type') || '';
  if (ct.includes('text/html') && bodyPreview.includes('challenge-platform')) {
    return 'managed_challenge';
  }

  return 'none';
}

function determineOutcome(
  statusCode: number,
  cfMitigated: boolean,
  challengeType: AttackTestResult['response']['challenge_type'],
): AttackOutcome {
  // Blocked: 403 without challenge
  if (statusCode === 403 && !cfMitigated) return 'blocked';
  // Blocked: explicit 403 with server: cloudflare
  if (statusCode === 403) return 'blocked';
  // Challenged: cf-mitigated header present
  if (cfMitigated || challengeType !== 'none') return 'challenged';
  // Rate limited
  if (statusCode === 429) return 'blocked';
  // Blocked by DDoS
  if (statusCode === 503 || statusCode === 520 || statusCode === 521 || statusCode === 522) return 'blocked';
  // Success = bypassed (attack reached origin or was served normally)
  if (statusCode >= 200 && statusCode < 400) return 'bypassed';
  // 4xx other than 403/429 could be normal (404 etc.) - count as bypassed if WAF didn't catch
  if (statusCode === 404 || statusCode === 405) return 'bypassed';
  // 5xx = error on origin but still passed through CF
  if (statusCode >= 500) return 'bypassed';
  return 'error';
}

async function analyzeResponse(startTime: number, res: Response): Promise<AnalyzedResponse> {
  const elapsed = Date.now() - startTime;
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => { headers[k] = v; });

  // Read body preview (first 500 chars)
  let bodyPreview = '';
  try {
    const text = await res.text();
    bodyPreview = text.substring(0, 500);
  } catch {
    bodyPreview = '(unable to read body)';
  }

  const cfMitigated = getHeader(res.headers, 'cf-mitigated') === 'challenge';
  const cfRay = getHeader(res.headers, 'cf-ray');
  const cfCacheStatus = getHeader(res.headers, 'cf-cache-status');
  const challengeType = detectChallengeType(res.headers, bodyPreview);
  const outcome = determineOutcome(res.status, cfMitigated, challengeType);

  return {
    status_code: res.status,
    response_time_ms: elapsed,
    headers,
    cf_mitigated: cfMitigated,
    cf_ray: cfRay,
    cf_cache_status: cfCacheStatus,
    body_preview: bodyPreview,
    challenge_type: challengeType,
    outcome,
  };
}

// ════════════════════════════════════════════════════════════════════
// Single Test Execution
// ════════════════════════════════════════════════════════════════════

async function executeTest(
  domain: string,
  payload: PayloadDefinition,
  isHTTP: boolean,
): Promise<AttackTestResult> {
  const protocol = isHTTP ? 'http' : 'https';
  const url = `${protocol}://${domain}${payload.request.path}`;

  const reqHeaders: Record<string, string> = { ...(payload.request.headers || {}) };
  // Don't override User-Agent if payload specifies one
  if (!reqHeaders['User-Agent'] && !reqHeaders['user-agent']) {
    reqHeaders['User-Agent'] = SCANNER_UA;
  }

  const startTime = Date.now();

  try {
    const options: RequestInit = {
      method: payload.request.method,
      headers: reqHeaders,
      redirect: 'manual',
    };

    if (payload.request.body && ['POST', 'PUT', 'PATCH'].includes(payload.request.method)) {
      options.body = payload.request.body;
    }

    const res = await fetchWithTimeout(url, options);
    const analyzed = await analyzeResponse(startTime, res);

    return {
      test_id: payload.id,
      module: payload.module,
      name: payload.name,
      description: payload.description,
      outcome: analyzed.outcome,
      severity: payload.severity,
      request: {
        method: payload.request.method,
        url,
        headers: reqHeaders,
        body: payload.request.body,
      },
      response: {
        status_code: analyzed.status_code,
        response_time_ms: analyzed.response_time_ms,
        headers: analyzed.headers,
        cf_mitigated: analyzed.cf_mitigated,
        cf_ray: analyzed.cf_ray,
        cf_cache_status: analyzed.cf_cache_status,
        body_preview: analyzed.body_preview,
        challenge_type: analyzed.challenge_type,
      },
      correlation: {
        rule_id: null,
        rule_description: null,
        security_source: null,
        action: null,
        owasp_score: null,
        bot_score: null,
        waf_attack_score: null,
      },
      recommendation: analyzed.outcome === 'bypassed' ? payload.recommendation : null,
      linked_finding_id: analyzed.outcome === 'bypassed' ? payload.finding_id : null,
    };
  } catch (err) {
    return {
      test_id: payload.id,
      module: payload.module,
      name: payload.name,
      description: payload.description,
      outcome: 'error',
      severity: payload.severity,
      request: {
        method: payload.request.method,
        url,
        headers: reqHeaders,
        body: payload.request.body,
      },
      response: {
        status_code: 0,
        response_time_ms: Date.now() - startTime,
        headers: {},
        cf_mitigated: false,
        cf_ray: null,
        cf_cache_status: null,
        body_preview: `Error: ${err instanceof Error ? err.message : 'Unknown'}`,
        challenge_type: 'none',
      },
      correlation: {
        rule_id: null,
        rule_description: null,
        security_source: null,
        action: null,
        owasp_score: null,
        bot_score: null,
        waf_attack_score: null,
      },
      recommendation: null,
      linked_finding_id: null,
    };
  }
}

// ��═══════════════════════════════════════════════════════════════════
// Rate Limit Burst Testing (special handling)
// ════════════════════════════════════════════════════════════════════

async function executeRateLimitBurst(
  domain: string,
  payload: PayloadDefinition,
  burstSize: number,
): Promise<AttackTestResult> {
  const url = `https://${domain}${payload.request.path}`;
  const startTime = Date.now();

  // Fire burst in PARALLEL - that's the point of burst testing
  const promises = Array.from({ length: burstSize }, () =>
    fetchWithTimeout(url, {
      method: payload.request.method,
      headers: payload.request.headers || {},
      body: payload.request.body,
      redirect: 'manual',
    }, 4000).then(async (res) => {
      const mitigated = res.headers.get('cf-mitigated') === 'challenge';
      await res.text().catch(() => {}); // drain body
      return { status: res.status, cfMitigated: mitigated };
    }).catch(() => ({ status: 0, cfMitigated: false }))
  );

  const results = await Promise.all(promises);
  const elapsed = Date.now() - startTime;
  const blocked = results.filter((r) => r.status === 429 || r.status === 403 || r.cfMitigated).length;
  const outcome: AttackOutcome = blocked > 0 ? 'blocked' : 'bypassed';

  return {
    test_id: payload.id,
    module: payload.module,
    name: payload.name,
    description: payload.description,
    outcome,
    severity: payload.severity,
    request: {
      method: payload.request.method,
      url,
      headers: payload.request.headers || {},
      body: payload.request.body,
    },
    response: {
      status_code: results[results.length - 1]?.status || 0,
      response_time_ms: elapsed,
      headers: {},
      cf_mitigated: results.some((r) => r.cfMitigated),
      cf_ray: null,
      cf_cache_status: null,
      body_preview: `Burst: ${burstSize} requests in ${elapsed}ms. Blocked: ${blocked}/${burstSize}`,
      challenge_type: results.some((r) => r.cfMitigated) ? 'managed_challenge' : 'none',
    },
    correlation: {
      rule_id: null, rule_description: null, security_source: null,
      action: null, owasp_score: null, bot_score: null, waf_attack_score: null,
    },
    recommendation: outcome === 'bypassed' ? payload.recommendation : null,
    linked_finding_id: outcome === 'bypassed' ? payload.finding_id : null,
  };
}

// ════════════════════════════════════════════════════════════════════
// SSL/TLS Tests (special handling - check config rather than attack)
// ════════════════════════════════════════════════════════════════════

function evaluateSSLTest(
  payload: PayloadDefinition,
  intel: SecurityIntelligence,
): AttackTestResult {
  let outcome: AttackOutcome = 'blocked'; // default = good config
  let bodyPreview = '';

  switch (payload.id) {
    case 'SIM-T045': // HTTP redirect
      outcome = intel.ssl_tls.always_use_https ? 'blocked' : 'bypassed';
      bodyPreview = `Always Use HTTPS: ${intel.ssl_tls.always_use_https}`;
      break;
    case 'SIM-T046': // HSTS
      outcome = intel.ssl_tls.hsts_enabled ? 'blocked' : 'bypassed';
      bodyPreview = `HSTS: ${intel.ssl_tls.hsts_enabled}, max-age: ${intel.ssl_tls.hsts_max_age}`;
      break;
    case 'SIM-T047': // HSTS includeSubDomains
      outcome = intel.ssl_tls.hsts_include_subdomains ? 'blocked' : 'bypassed';
      bodyPreview = `includeSubDomains: ${intel.ssl_tls.hsts_include_subdomains}`;
      break;
    case 'SIM-T048': // TLS 1.0/1.1
      outcome = (intel.ssl_tls.min_tls_version === '1.2' || intel.ssl_tls.min_tls_version === '1.3') ? 'blocked' : 'bypassed';
      bodyPreview = `Min TLS: ${intel.ssl_tls.min_tls_version}`;
      break;
    case 'SIM-T049': // TLS 1.3
      outcome = (intel.ssl_tls.tls_1_3 === 'on' || intel.ssl_tls.tls_1_3 === 'zrt') ? 'blocked' : 'bypassed';
      bodyPreview = `TLS 1.3: ${intel.ssl_tls.tls_1_3}`;
      break;
    case 'SIM-T050': // SSL mode
      outcome = (intel.ssl_tls.ssl_mode === 'strict' || intel.ssl_tls.ssl_mode === 'full') ? 'blocked' : 'bypassed';
      bodyPreview = `SSL Mode: ${intel.ssl_tls.ssl_mode}`;
      break;
    case 'SIM-T051': // Opportunistic Encryption - info only
      outcome = 'blocked'; // Not critical
      bodyPreview = 'Opportunistic Encryption check (informational)';
      break;
    case 'SIM-T052': // HTTPS redirect timing - info only
      outcome = intel.ssl_tls.always_use_https ? 'blocked' : 'bypassed';
      bodyPreview = `Redirect: ${intel.ssl_tls.always_use_https ? 'configured' : 'not configured'}`;
      break;
  }

  return {
    test_id: payload.id,
    module: payload.module,
    name: payload.name,
    description: payload.description,
    outcome,
    severity: payload.severity,
    request: { method: 'GET', url: `config-check://${payload.id}`, headers: {} },
    response: {
      status_code: 0,
      response_time_ms: 0,
      headers: {},
      cf_mitigated: false,
      cf_ray: null,
      cf_cache_status: null,
      body_preview: bodyPreview,
      challenge_type: 'none',
    },
    correlation: {
      rule_id: null, rule_description: null, security_source: null,
      action: null, owasp_score: null, bot_score: null, waf_attack_score: null,
    },
    recommendation: outcome === 'bypassed' ? payload.recommendation : null,
    linked_finding_id: outcome === 'bypassed' ? payload.finding_id : null,
  };
}

// ════════════════════════════════════════════════════════════════════
// Main Export: Execute All Attacks
// ════════════════════════════════════════════════════════════════════

export async function executeAttacks(
  domain: string,
  intelligence: SecurityIntelligence,
  modules?: AttackModuleId[],
): Promise<AttackTestResult[]> {
  const results: AttackTestResult[] = [];
  const globalStart = Date.now();

  // Build all payloads (static + dynamic custom rule bypass)
  const dynamicPayloads = buildCustomRuleBypassPayloads(intelligence.custom_rules.rules);
  const allPayloads = [...STATIC_PAYLOADS, ...dynamicPayloads];

  // Filter by modules if specified
  const filteredPayloads = modules
    ? allPayloads.filter((p) => modules.includes(p.module))
    : allPayloads;

  // Group by module for ordered execution
  const moduleGroups = new Map<string, PayloadDefinition[]>();
  for (const p of filteredPayloads) {
    const group = moduleGroups.get(p.module) || [];
    group.push(p);
    moduleGroups.set(p.module, group);
  }

  // Helper: check if we've exceeded the global timeout
  const isTimedOut = () => (Date.now() - globalStart) > GLOBAL_PHASE2_TIMEOUT;

  // Execute config-only modules INSTANTLY (no HTTP)
  for (const [module, payloads] of moduleGroups) {
    if (module === 'ssl_tls') {
      for (const payload of payloads) {
        results.push(evaluateSSLTest(payload, intelligence));
      }
    }
  }

  // Separate HTTP modules from config-only
  const httpModules: [string, PayloadDefinition[]][] = [];
  for (const [module, payloads] of moduleGroups) {
    if (module !== 'ssl_tls') httpModules.push([module, payloads]);
  }

  // Execute HTTP modules with global timeout awareness
  for (const [module, payloads] of httpModules) {
    if (isTimedOut()) {
      // Mark remaining tests as errors due to timeout
      for (const p of payloads) {
        results.push(buildTimeoutResult(p, domain));
      }
      continue;
    }

    if (module === 'rate_limit') {
      // Rate limit tests: parallel bursts
      for (const payload of payloads) {
        if (isTimedOut()) { results.push(buildTimeoutResult(payload, domain)); continue; }
        const burstSize = payload.id === 'SIM-T017' ? 10 : payload.id === 'SIM-T014' ? 8 : 6;
        const result = await executeRateLimitBurst(domain, payload, burstSize);
        results.push(result);
        // Minimal delay between burst tests (bursts are already parallel)
        if (!isTimedOut()) await sleep(200);
      }
    } else if (module === 'challenge_analysis') {
      // Challenge tests: mix of HTTP probes and config checks
      const httpTests: PayloadDefinition[] = [];
      for (const payload of payloads) {
        if (['SIM-T073', 'SIM-T074', 'SIM-T076'].includes(payload.id)) {
          results.push(evaluateChallengeConfigTest(payload, intelligence));
        } else {
          httpTests.push(payload);
        }
      }
      // Run HTTP challenge tests in one batch
      if (httpTests.length > 0 && !isTimedOut()) {
        const batchResults = await Promise.all(
          httpTests.map((p) => executeTest(domain, p, false)),
        );
        results.push(...batchResults);
      }
    } else {
      // Standard modules: larger batches, shorter delays
      const batchSize = 8; // Increased from 5 to 8
      for (let i = 0; i < payloads.length; i += batchSize) {
        if (isTimedOut()) {
          for (const p of payloads.slice(i)) results.push(buildTimeoutResult(p, domain));
          break;
        }
        const batch = payloads.slice(i, i + batchSize);
        const batchResults = await Promise.all(
          batch.map((p) => executeTest(domain, p, false)),
        );
        results.push(...batchResults);
        // Minimal delay between batches
        if (i + batchSize < payloads.length && !isTimedOut()) await sleep(100);
      }
    }
  }

  // Post-process recommendations: rewrite "Enable X" to "Review/tune X" when the feature IS active
  for (const r of results) {
    if (!r.recommendation?.action) continue;
    const action = r.recommendation.action;
    // WAF Managed Ruleset: if already enabled, don't say "Enable"
    if (intelligence.waf.cf_managed_ruleset) {
      if (typeof action.es === 'string' && /habilitar.*managed\s*ruleset/i.test(action.es)) {
        action.es = action.es.replace(/habilitar/gi, 'Revisar configuración de').replace(/y OWASP Core Ruleset/i, '— verificar que las reglas estén en modo "Block"');
      }
      if (typeof action.en === 'string' && /enable.*managed\s*ruleset/i.test(action.en)) {
        action.en = action.en.replace(/enable/gi, 'Review configuration of').replace(/and OWASP Core Ruleset/i, '— verify rules are in "Block" mode');
      }
    }
    // OWASP: if already enabled, say "tune" not "enable"
    if (intelligence.waf.owasp_enabled) {
      if (typeof action.es === 'string' && /habilitar.*owasp/i.test(action.es)) {
        action.es = action.es.replace(/habilitar/gi, 'Aumentar el nivel de paranoia de');
      }
      if (typeof action.en === 'string' && /enable.*owasp/i.test(action.en)) {
        action.en = action.en.replace(/enable/gi, 'Increase paranoia level of');
      }
    }
    // Bot Management: if SBFM is active
    if (intelligence.bot_management.sbfm_enabled || intelligence.bot_management.enabled) {
      if (typeof action.es === 'string' && /activar.*bot/i.test(action.es)) {
        action.es = action.es.replace(/activar/gi, 'Ajustar configuración de');
      }
      if (typeof action.en === 'string' && /enable.*bot/i.test(action.en)) {
        action.en = action.en.replace(/enable/gi, 'Tune configuration of');
      }
    }
  }

  return results;
}

/** Build a timeout placeholder result for tests that couldn't run */
function buildTimeoutResult(payload: PayloadDefinition, domain: string): AttackTestResult {
  return {
    test_id: payload.id,
    module: payload.module,
    name: payload.name,
    description: payload.description,
    outcome: 'error',
    severity: payload.severity,
    request: { method: payload.request.method, url: `https://${domain}${payload.request.path}`, headers: {} },
    response: {
      status_code: 0,
      response_time_ms: 0,
      headers: {},
      cf_mitigated: false,
      cf_ray: null,
      cf_cache_status: null,
      body_preview: 'Skipped: global timeout reached',
      challenge_type: 'none',
    },
    correlation: {
      rule_id: null, rule_description: null, security_source: null,
      action: null, owasp_score: null, bot_score: null, waf_attack_score: null,
    },
    recommendation: null,
    linked_finding_id: null,
  };
}

// ════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function evaluateChallengeConfigTest(
  payload: PayloadDefinition,
  intel: SecurityIntelligence,
): AttackTestResult {
  let outcome: AttackOutcome = 'blocked';
  let bodyPreview = '';

  switch (payload.id) {
    case 'SIM-T073': // Challenge Passage TTL
      outcome = intel.security.challenge_ttl <= 1800 ? 'blocked' : 'bypassed';
      bodyPreview = `Challenge TTL: ${intel.security.challenge_ttl}s`;
      break;
    case 'SIM-T074': // Under Attack Mode
      outcome = intel.security.security_level === 'under_attack' ? 'challenged' : 'blocked';
      bodyPreview = `Security Level: ${intel.security.security_level}. Under Attack: ${intel.security.security_level === 'under_attack'}`;
      break;
    case 'SIM-T076': // Privacy Pass
      outcome = intel.security.privacy_pass ? 'blocked' : 'bypassed';
      bodyPreview = `Privacy Pass: ${intel.security.privacy_pass}`;
      break;
  }

  return {
    test_id: payload.id,
    module: payload.module,
    name: payload.name,
    description: payload.description,
    outcome,
    severity: payload.severity,
    request: { method: 'GET', url: `config-check://${payload.id}`, headers: {} },
    response: {
      status_code: 0, response_time_ms: 0, headers: {},
      cf_mitigated: false, cf_ray: null, cf_cache_status: null,
      body_preview: bodyPreview, challenge_type: 'none',
    },
    correlation: {
      rule_id: null, rule_description: null, security_source: null,
      action: null, owasp_score: null, bot_score: null, waf_attack_score: null,
    },
    recommendation: outcome === 'bypassed' ? payload.recommendation : null,
    linked_finding_id: outcome === 'bypassed' ? payload.finding_id : null,
  };
}
