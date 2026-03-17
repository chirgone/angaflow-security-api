/**
 * Anga Security — Tier-Aware Audit Collector Orchestrator
 *
 * Key improvements over sentinel:
 *   - Uses COLLECTOR_REGISTRY to dynamically determine what runs
 *   - Named collector dispatch (no brittle index-based result mapping)
 *   - Clean separation between tier gates (not purchased) and plan gates (CF plan too low)
 *   - Returns analysis_period for report metadata
 *   - zone_info is fetched first (required), then plan is determined, then all others run in parallel
 */

import type {
  AuditTier,
  CloudflarePlanTier,
  CollectedData,
  CollectorName,
  CollectorWarning,
  SkippedCollector,
} from '../../types/audit';

import {
  getCollectorsForTierAndPlan,
  detectPlanTier,
  EMPTY_SETTINGS,
  EMPTY_RULESETS,
  EMPTY_DNS,
  EMPTY_BOT_SCORES,
  EMPTY_WAF_EVENTS,
  EMPTY_CACHE,
  EMPTY_TRAFFIC,
  EMPTY_BOT_ASNS,
  EMPTY_HISTOGRAM,
  EMPTY_ENGINES,
  EMPTY_JA3,
  EMPTY_JA4,
  EMPTY_METHODS,
  EMPTY_TRAFFIC_TS,
  EMPTY_WAF_TS,
  EMPTY_ATTACKER_IPS,
} from '../../types/audit';

import { getZoneInfo, getZoneSettings, getZoneRulesets, getDNSSummary } from './cf-rest';
import {
  getBotScores,
  getWAFEvents,
  getCacheAnalytics,
  getTrafficAnalytics,
  getHTTPMethods,
  getWAFTimeSeries,
  getTopAttackerIPs,
  getBotASNs,
  getTrafficTimeSeries,
  getBotScoreHistogram,
  getDetectionEngines,
  getJA3Fingerprints,
  getJA4Fingerprints,
} from './cf-graphql';

// ════════════════════════════════════════════════════════════════════
// Safe Execution Wrapper
// ════════════════════════════════════════════════════════════════════

interface SafeResult<T> {
  data: T;
  warning?: CollectorWarning;
}

async function safe<T>(
  name: string,
  fn: () => Promise<T>,
  fallback: T,
): Promise<SafeResult<T>> {
  try {
    const data = await fn();
    return { data };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[collector/${name}] ${message}`);

    let reason = message;
    if (/9109|Unauthorized|403|401/.test(message)) {
      reason = 'API token lacks required permission. Verify token scopes.';
    } else if (/404/.test(message)) {
      reason = 'Endpoint not found — feature may not be available on this plan.';
    } else if (/429/.test(message)) {
      reason = 'Rate limited by Cloudflare API. Try again in a few minutes.';
    }

    return {
      data: fallback,
      warning: { collector: name, message: reason },
    };
  }
}

// ════════════════════════════════════════════════════════════════════
// Collector Dispatch Map
// ════════════════════════════════════════════════════════════════════

type CollectorFn = (zoneId: string, token: string) => Promise<unknown>;
type FallbackMap = Record<CollectorName, unknown>;

/**
 * Maps collector names → (function, fallback).
 * zone_info is NOT here because it runs separately (required).
 */
function getCollectorFn(name: CollectorName): { fn: CollectorFn; fallback: unknown } | null {
  const map: Record<string, { fn: CollectorFn; fallback: unknown }> = {
    zone_settings:        { fn: getZoneSettings,        fallback: EMPTY_SETTINGS },
    dns_records:          { fn: getDNSSummary,           fallback: EMPTY_DNS },
    dnssec:               { fn: async () => null,        fallback: null }, // DNSSEC is embedded in getDNSSummary
    rulesets_waf:         { fn: getZoneRulesets,         fallback: EMPTY_RULESETS },
    waf_events:           { fn: getWAFEvents,            fallback: EMPTY_WAF_EVENTS },
    cache_analytics:      { fn: getCacheAnalytics,       fallback: EMPTY_CACHE },
    traffic_overview:     { fn: getTrafficAnalytics,     fallback: EMPTY_TRAFFIC },
    http_methods:         { fn: getHTTPMethods,          fallback: EMPTY_METHODS },
    waf_time_series:      { fn: getWAFTimeSeries,        fallback: EMPTY_WAF_TS },
    top_attacker_ips:     { fn: getTopAttackerIPs,       fallback: EMPTY_ATTACKER_IPS },
    bot_scores:           { fn: getBotScores,            fallback: EMPTY_BOT_SCORES },
    bot_asns:             { fn: getBotASNs,              fallback: EMPTY_BOT_ASNS },
    traffic_time_series:  { fn: getTrafficTimeSeries,    fallback: EMPTY_TRAFFIC_TS },
    bot_score_histogram:  { fn: getBotScoreHistogram,    fallback: EMPTY_HISTOGRAM },
    detection_engines:    { fn: getDetectionEngines,     fallback: EMPTY_ENGINES },
    ja3_fingerprints:     { fn: getJA3Fingerprints,      fallback: EMPTY_JA3 },
    ja4_fingerprints:     { fn: getJA4Fingerprints,      fallback: EMPTY_JA4 },
  };

  return map[name] || null;
}

// ════════════════════════════════════════════════════════════════════
// Main Orchestrator
// ════════════════════════════════════════════════════════════════════

export interface CollectionResult {
  data: CollectedData;
  cfPlan: CloudflarePlanTier;
  analysisPeriod: { start: string; end: string };
  collectorsRun: number;
  collectorsSkipped: number;
  collectorsWarned: number;
}

/**
 * Run all collectors appropriate for the given audit tier.
 *
 * Flow:
 * 1. Fetch zone_info (REQUIRED — determines CF plan tier)
 * 2. Determine which collectors to run based on (auditTier, cfPlan)
 * 3. Run all active collectors in parallel with safe() wrappers
 * 4. Assemble CollectedData with warnings and skipped info
 */
export async function collectAuditData(
  zoneId: string,
  apiToken: string,
  auditTier: AuditTier,
): Promise<CollectionResult> {
  const startTime = Date.now();

  // Step 1: Zone info is REQUIRED — failure here aborts the entire audit
  const zoneInfo = await getZoneInfo(zoneId, apiToken);
  const cfPlan = detectPlanTier(zoneInfo.plan.name);

  // Step 2: Determine active vs skipped collectors
  const { active, skipped: planSkipped } = getCollectorsForTierAndPlan(auditTier, cfPlan);

  // Build skipped list (plan-gated collectors)
  const skippedCollectors: SkippedCollector[] = planSkipped.map((spec) => ({
    collector: spec.name,
    reason: 'plan_gate' as const,
    detail: `${spec.label} requires CF ${spec.minPlan}+ plan (current: ${cfPlan})`,
  }));

  // Step 3: Run all active collectors in parallel (skip zone_info — already fetched)
  const activeWithoutZoneInfo = active.filter((s) => s.name !== 'zone_info');

  // dns_records and dnssec are handled together by getDNSSummary
  // Filter out the separate 'dnssec' entry — it's covered by dns_records
  const deduped = activeWithoutZoneInfo.filter((s) => s.name !== 'dnssec');

  const collectorPromises = deduped.map((spec) => {
    const entry = getCollectorFn(spec.name);
    if (!entry) {
      return Promise.resolve({
        name: spec.name,
        result: { data: null, warning: { collector: spec.name, message: 'No collector function registered' } } as SafeResult<unknown>,
      });
    }
    return safe(spec.label, () => entry.fn(zoneId, apiToken), entry.fallback)
      .then((result) => ({ name: spec.name, result }));
  });

  const results = await Promise.all(collectorPromises);

  // Step 4: Assemble results into CollectedData
  const warnings: CollectorWarning[] = [];
  const resultMap = new Map<string, unknown>();

  for (const { name, result } of results) {
    resultMap.set(name, result.data);
    if (result.warning) warnings.push(result.warning);
  }

  // Analysis period (30 days for most, the report uses this as metadata)
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  const analysisPeriod = { start: start.toISOString(), end: end.toISOString() };

  const data: CollectedData = {
    zone_info: zoneInfo,

    // Tier 1 — Basic
    zone_settings: (resultMap.get('zone_settings') as CollectedData['zone_settings']) ?? EMPTY_SETTINGS,
    rulesets: (resultMap.get('rulesets_waf') as CollectedData['rulesets']) ?? EMPTY_RULESETS,
    dns_summary: (resultMap.get('dns_records') as CollectedData['dns_summary']) ?? EMPTY_DNS,

    // Tier 2 — Pro
    waf_events: (resultMap.get('waf_events') as CollectedData['waf_events']) ?? undefined,
    cache_analytics: (resultMap.get('cache_analytics') as CollectedData['cache_analytics']) ?? undefined,
    traffic_analytics: (resultMap.get('traffic_overview') as CollectedData['traffic_analytics']) ?? undefined,
    http_methods: (resultMap.get('http_methods') as CollectedData['http_methods']) ?? undefined,
    waf_time_series: (resultMap.get('waf_time_series') as CollectedData['waf_time_series']) ?? undefined,
    top_attacker_ips: (resultMap.get('top_attacker_ips') as CollectedData['top_attacker_ips']) ?? undefined,
    bot_scores: (resultMap.get('bot_scores') as CollectedData['bot_scores']) ?? undefined,

    // Tier 3 — Complete
    bot_asns: (resultMap.get('bot_asns') as CollectedData['bot_asns']) ?? undefined,
    traffic_time_series: (resultMap.get('traffic_time_series') as CollectedData['traffic_time_series']) ?? undefined,
    bot_score_histogram: (resultMap.get('bot_score_histogram') as CollectedData['bot_score_histogram']) ?? undefined,
    detection_engines: (resultMap.get('detection_engines') as CollectedData['detection_engines']) ?? undefined,
    ja3_fingerprints: (resultMap.get('ja3_fingerprints') as CollectedData['ja3_fingerprints']) ?? undefined,
    ja4_fingerprints: (resultMap.get('ja4_fingerprints') as CollectedData['ja4_fingerprints']) ?? undefined,

    warnings,
    skipped_collectors: skippedCollectors,
  };

  return {
    data,
    cfPlan,
    analysisPeriod,
    collectorsRun: deduped.length + 1, // +1 for zone_info
    collectorsSkipped: skippedCollectors.length,
    collectorsWarned: warnings.length,
  };
}
