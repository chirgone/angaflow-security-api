/**
 * Anga Security \u2014 Attack Simulator Phase 3: Post-Simulation Correlation
 *
 * Queries Cloudflare GraphQL `firewallEventsAdaptive` to get ground truth on
 * which CF security system caught each attack. Enriches test results with:
 *   - rule_id: which managed/custom rule matched
 *   - rule_description: human-readable description
 *   - security_source: waf, firewallCustom, rateLimit, botManagement, l7ddos
 *   - action: block, challenge, js_challenge, managed_challenge, log
 *   - owasp_score: anomaly score (if OWASP ruleset triggered)
 *   - bot_score: CF bot score assigned
 *   - waf_attack_score: ML-based attack score (Enterprise)
 *
 * Uses a narrow time window (last 15 minutes) to match our simulation requests
 * by cf-ray ID or by path+method+timestamp heuristic.
 */

import type { AttackTestResult, SecuritySourceKey } from '../../types/simulation';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// GraphQL Client (copied pattern from cf-graphql.ts)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

const GQL_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql';

interface GQLResponse {
  data?: {
    viewer?: {
      zones?: Array<Record<string, unknown>>;
    };
  };
  errors?: Array<{ message: string; path?: string[] }>;
}

class GqlCorrelationError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(`GraphQL Correlation ${status}: ${detail}`);
    this.name = 'GqlCorrelationError';
  }
}

async function gqlFetch(
  query: string,
  variables: Record<string, unknown>,
  token: string,
): Promise<Record<string, unknown>> {
  const res = await fetch(GQL_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(8000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '(no body)');
    throw new GqlCorrelationError(res.status, text);
  }

  const json = (await res.json()) as GQLResponse;

  if (json.errors?.length) {
    const errMsg = json.errors.map((e) => e.message).join('; ');
    throw new GqlCorrelationError(200, errMsg);
  }

  const zones = json.data?.viewer?.zones;
  if (!zones || zones.length === 0) return {};

  return zones[0];
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Firewall Events Query
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Query to fetch individual firewall events (not grouped).
 * firewallEventsAdaptive returns raw events with full detail:
 *   - rayName: matches cf-ray response header (without datacenter suffix)
 *   - source: which CF system caught it (waf, firewallCustom, rateLimit, etc.)
 *   - action: what CF did (block, challenge, log, etc.)
 *   - ruleId: the specific rule that matched
 *   - description: rule description
 *   - clientRequestPath, clientRequestHTTPMethodName: for matching
 *   - botScore: CF bot score
 *   - wafAttackScore: ML attack score (Enterprise)
 */
const FIREWALL_EVENTS_QUERY = `
query SimulationFirewallEvents($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      events: firewallEventsAdaptive(
        limit: 500
        orderBy: [datetime_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        rayName
        source
        action
        ruleId
        description
        clientRequestPath
        clientRequestHTTPMethodName
        datetime
        clientIP
        userAgent
        botScore
      }
    }
  }
}`;

/**
 * Grouped query: aggregate by source + action for defense attribution donut chart.
 */
const FIREWALL_EVENTS_GROUPED_QUERY = `
query SimulationFirewallEventsGrouped($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      bySource: firewallEventsAdaptiveGroups(
        limit: 50
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions {
          source
          action
        }
      }
      byRule: firewallEventsAdaptiveGroups(
        limit: 50
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions {
          ruleId
          description
          action
        }
      }
    }
  }
}`;

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Types for raw GraphQL event data
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

interface FirewallEvent {
  rayName: string;
  source: string;
  action: string;
  ruleId: string;
  description: string;
  clientRequestPath: string;
  clientRequestHTTPMethodName: string;
  datetime: string;
  clientIP: string;
  userAgent: string;
  botScore: number | null;
}

interface FirewallEventGroup {
  count: number;
  dimensions: {
    source?: string;
    action?: string;
    ruleId?: string;
    description?: string;
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Event Matching Logic
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Extract the ray ID prefix from a cf-ray header value.
 * CF-Ray format: "8f1234abcdef-LAX" \u2192 we want "8f1234abcdef"
 * GraphQL rayName is the full ray without datacenter suffix.
 */
function extractRayPrefix(cfRayHeader: string | null): string | null {
  if (!cfRayHeader) return null;
  const parts = cfRayHeader.split('-');
  return parts[0] || null;
}

/**
 * Extract path from a full URL for matching.
 */
function extractPath(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    // If URL parsing fails, try to extract path manually
    const match = url.match(/https?:\/\/[^/]+(\/[^#]*)/);
    return match ? match[1] : '/';
  }
}

/**
 * Match firewall events to test results using two strategies:
 *   1. Primary: Match by cf-ray ID (most accurate)
 *   2. Fallback: Match by path + method (for tests where cf-ray wasn't captured)
 */
function matchEventToTest(
  event: FirewallEvent,
  tests: AttackTestResult[],
  rayIndex: Map<string, AttackTestResult>,
  pathIndex: Map<string, AttackTestResult[]>,
): AttackTestResult | null {
  // Strategy 1: Ray ID match
  if (event.rayName) {
    const match = rayIndex.get(event.rayName);
    if (match) return match;
  }

  // Strategy 2: Path + method match
  const path = event.clientRequestPath || '';
  const method = event.clientRequestHTTPMethodName || '';
  const key = `${method}:${path}`;
  const candidates = pathIndex.get(key);
  if (candidates && candidates.length > 0) {
    // Return the first unmatched candidate
    return candidates[0];
  }

  return null;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Source Mapping
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Map CF GraphQL `source` field to our SecuritySourceKey for the donut chart.
 *
 * CF sources: waf, firewallCustom, firewallManaged, rateLimit,
 *   botManagement, l7ddos, sanitycheck, zoneLockdown, uaBlock,
 *   ipReputation, accessRules, apiShield
 */
export function mapCfSourceToKey(cfSource: string): SecuritySourceKey {
  switch (cfSource.toLowerCase()) {
    case 'waf':
    case 'firewallmanaged':
      return 'waf_managed';
    case 'firewallcustom':
    case 'zonelockdown':
    case 'uablock':
    case 'accessrules':
    case 'ipreputation':
      return 'firewall_custom';
    case 'ratelimit':
      return 'rate_limit';
    case 'botmanagement':
    case 'botfight':
      return 'bot_management';
    case 'l7ddos':
    case 'sanitycheck':
      return 'ddos_protection';
    default:
      // Unknown source \u2014 default to waf_managed if blocked, not_blocked otherwise
      return 'waf_managed';
  }
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Main Export: Correlate Results
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface CorrelationResult {
  /** Enriched test results with correlation data */
  tests: AttackTestResult[];
  /** Total firewall events found in the time window */
  total_events: number;
  /** Events successfully matched to our tests */
  matched_events: number;
}

/**
 * Phase 3: Query Cloudflare firewall events and correlate with our simulation
 * test results to get ground truth on which CF system caught each attack.
 *
 * @param zoneId - Cloudflare zone ID
 * @param token - CF API token with Analytics:Read
 * @param tests - Attack test results from Phase 2
 * @param simulationStartTime - ISO timestamp when simulation started
 */
export async function correlateFirewallEvents(
  zoneId: string,
  token: string,
  tests: AttackTestResult[],
  simulationStartTime: string,
): Promise<CorrelationResult> {
  // Build time window: from simulation start to now + 2 min buffer
  const start = simulationStartTime;
  const end = new Date(Date.now() + 2 * 60 * 1000).toISOString();

  let events: FirewallEvent[] = [];
  let totalEvents = 0;
  let matchedEvents = 0;

  try {
    // Fetch raw firewall events
    const data = await gqlFetch(
      FIREWALL_EVENTS_QUERY,
      { zoneTag: zoneId, start, end },
      token,
    );

    events = (data.events as FirewallEvent[]) || [];
    totalEvents = events.length;
  } catch (err) {
    // If GraphQL fails (permission issue, etc.), return tests unmodified
    // The simulation still has value from Phase 2 HTTP analysis
    console.error('Correlation GraphQL failed:', err instanceof Error ? err.message : 'Unknown');
    return { tests, total_events: 0, matched_events: 0 };
  }

  if (events.length === 0) {
    return { tests, total_events: 0, matched_events: 0 };
  }

  // Build indexes for matching

  // Index 1: ray ID \u2192 test
  const rayIndex = new Map<string, AttackTestResult>();
  for (const test of tests) {
    const rayPrefix = extractRayPrefix(test.response.cf_ray);
    if (rayPrefix) {
      rayIndex.set(rayPrefix, test);
    }
  }

  // Index 2: method:path \u2192 tests[] (multiple tests may share same path)
  const pathIndex = new Map<string, AttackTestResult[]>();
  for (const test of tests) {
    // Skip config-check tests (no real HTTP request)
    if (test.request.url.startsWith('config-check://')) continue;

    const path = extractPath(test.request.url);
    const key = `${test.request.method}:${path}`;
    const list = pathIndex.get(key) || [];
    list.push(test);
    pathIndex.set(key, list);
  }

  // Track which tests have been matched to avoid double-matching
  const matchedTestIds = new Set<string>();

  // Correlate events to tests
  for (const event of events) {
    const test = matchEventToTest(event, tests, rayIndex, pathIndex);
    if (!test || matchedTestIds.has(test.test_id)) continue;

    matchedTestIds.add(test.test_id);
    matchedEvents++;

    // Enrich test correlation data
    test.correlation = {
      rule_id: event.ruleId || null,
      rule_description: event.description || null,
      security_source: event.source || null,
      action: event.action || null,
      owasp_score: null, // Not directly in event; could be inferred from ruleId
      bot_score: event.botScore ?? null,
      waf_attack_score: null, // Available in Enterprise; not in standard events
    };

    // Update outcome based on ground truth from CF events
    // CF says it blocked/challenged \u2192 trust CF over our HTTP analysis
    if (event.action === 'block' || event.action === 'drop') {
      test.outcome = 'blocked';
      test.recommendation = null;
      test.linked_finding_id = null;
    } else if (
      event.action === 'challenge' ||
      event.action === 'managed_challenge' ||
      event.action === 'js_challenge'
    ) {
      test.outcome = 'challenged';
      test.recommendation = null;
      test.linked_finding_id = null;
    }
    // If CF logged it (action: 'log') but didn't block, keep original outcome
  }

  return { tests, total_events: totalEvents, matched_events: matchedEvents };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Defense Attribution Builder
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

import { DEFENSE_SOURCE_META, type DefenseAttribution } from '../../types/simulation';

/**
 * Build the Defense Layer Attribution data for the donut chart.
 * Groups tests by which CF security system blocked them, plus "Not Blocked".
 */
export function buildDefenseAttribution(tests: AttackTestResult[]): DefenseAttribution[] {
  const buckets = new Map<SecuritySourceKey, string[]>();

  // Initialize all buckets
  for (const key of Object.keys(DEFENSE_SOURCE_META) as SecuritySourceKey[]) {
    buckets.set(key, []);
  }

  for (const test of tests) {
    if (test.outcome === 'bypassed' || test.outcome === 'error') {
      buckets.get('not_blocked')!.push(test.test_id);
    } else if (test.correlation.security_source) {
      // Use ground truth from GraphQL
      const sourceKey = mapCfSourceToKey(test.correlation.security_source);
      buckets.get(sourceKey)!.push(test.test_id);
    } else {
      // No correlation data \u2014 infer from module type
      const inferred = inferSourceFromModule(test);
      buckets.get(inferred)!.push(test.test_id);
    }
  }

  // Build attribution array, filtering empty buckets (except not_blocked)
  const result: DefenseAttribution[] = [];
  for (const [key, testIds] of buckets) {
    if (testIds.length === 0 && key !== 'not_blocked') continue;
    const meta = DEFENSE_SOURCE_META[key];
    result.push({
      source: key,
      label: meta.label,
      count: testIds.length,
      color: meta.color,
      test_ids: testIds,
    });
  }

  return result;
}

/**
 * If we don't have GraphQL correlation data for a blocked/challenged test,
 * infer the likely CF security source from the module type.
 */
function inferSourceFromModule(test: AttackTestResult): SecuritySourceKey {
  switch (test.module) {
    case 'waf_bypass':
    case 'api_security':
      return 'waf_managed';
    case 'custom_rule_bypass':
    case 'ip_geo_access':
      return 'firewall_custom';
    case 'rate_limit':
      return 'rate_limit';
    case 'bot_evasion':
      return 'bot_management';
    case 'ssl_tls':
    case 'cache_poisoning':
    case 'challenge_analysis':
      return 'waf_managed';
    default:
      return 'waf_managed';
  }
}
