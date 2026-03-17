/**
 * Anga Security — Cloudflare GraphQL Analytics Collectors
 *
 * 13 GraphQL collectors organized by audit tier:
 *   Tier 2 (Pro):     7 collectors — WAF Events, Cache, Traffic, HTTP Methods, WAF TS, Attacker IPs, Bot Scores
 *   Tier 3 (Complete): 6 collectors — Bot ASNs, Traffic TS, Bot Histogram, Detection Engines, JA3, JA4
 *
 * Improved over sentinel:
 *   - Shared date range helpers accept configurable lookback periods
 *   - Typed GraphQL response parsing with null safety
 *   - Attacker IP aggregation (deduplicates per IP across action/UA combos)
 *   - Explicit GraphQL error class for better error handling in orchestrator
 */

import type {
  BotScoreDistribution,
  WAFEventsSummary,
  CacheAnalytics,
  TrafficAnalytics,
  BotASN,
  BotScoreHistogramBucket,
  DetectionEngineBreakdown,
  JA3Fingerprint,
  JA4Fingerprint,
  HTTPMethodBreakdown,
  TrafficTimeSeries,
  WAFTimeSeries,
  AttackerIP,
} from '../../types/audit';

import {
  BOT_SCORE_QUERY,
  WAF_EVENTS_QUERY,
  CACHE_ANALYTICS_QUERY,
  TRAFFIC_OVERVIEW_QUERY,
  BOT_ASN_QUERY,
  BOT_SCORE_HISTOGRAM_QUERY,
  DETECTION_ENGINE_QUERY,
  JA3_FINGERPRINT_QUERY,
  JA4_FINGERPRINT_QUERY,
  HTTP_METHOD_QUERY,
  TRAFFIC_TIME_SERIES_QUERY,
  WAF_TIME_SERIES_QUERY,
  TOP_ATTACKER_IPS_QUERY,
} from './graphql-queries';

// ════════════════════════════════════════════════════════════════════
// GraphQL Client
// ════════════════════════════════════════════════════════════════════

const GQL_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql';

interface GQLResponse {
  data?: {
    viewer?: {
      zones?: Array<Record<string, unknown>>;
    };
  };
  errors?: Array<{ message: string; path?: string[] }>;
}

export class GqlError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(`GraphQL ${status}: ${detail}`);
    this.name = 'GqlError';
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
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '(no body)');
    throw new GqlError(res.status, text);
  }

  const json = (await res.json()) as GQLResponse;

  if (json.errors?.length) {
    const errMsg = json.errors.map((e) => e.message).join('; ');
    throw new GqlError(200, errMsg);
  }

  const zones = json.data?.viewer?.zones;
  if (!zones || zones.length === 0) return {};

  return zones[0];
}

// ════════════════════════════════════════════════════════════════════
// Date Range Helpers
// ════════════════════════════════════════════════════════════════════

/** 30-day lookback (used for most analytics) */
function get30DayRange(): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

/** 7-day lookback (used for time series — keeps data granular) */
function get7DayRange(): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

// ════════════════════════════════════════════════════════════════════
// Tier 2 — Pro Collectors
// ════════════════════════════════════════════════════════════════════

// ── Bot Score Distribution ──

export async function getBotScores(
  zoneId: string,
  token: string,
): Promise<BotScoreDistribution> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(BOT_SCORE_QUERY, { zoneTag: zoneId, start, end }, token);

  const automated = (data.automated as Array<{ count: number }>)?.[0]?.count || 0;
  const likelyAutomated = (data.likelyAutomated as Array<{ count: number }>)?.[0]?.count || 0;
  const likelyHuman = (data.likelyHuman as Array<{ count: number }>)?.[0]?.count || 0;
  const verified = (data.verified as Array<{ count: number }>)?.[0]?.count || 0;

  return {
    automated,
    likely_automated: likelyAutomated,
    likely_human: likelyHuman,
    verified_bot: verified,
    total_requests: automated + likelyAutomated + likelyHuman + verified,
  };
}

// ── WAF Events ──

export async function getWAFEvents(
  zoneId: string,
  token: string,
): Promise<WAFEventsSummary> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(WAF_EVENTS_QUERY, { zoneTag: zoneId, start, end }, token);

  const totalEvents = (data.totalEvents as Array<{ count: number }>)?.[0]?.count || 0;

  const byAction = (data.byAction as Array<{ count: number; dimensions: { action: string } }>) || [];
  const events_by_action: Record<string, number> = {};
  for (const item of byAction) {
    events_by_action[item.dimensions.action] = item.count;
  }

  const topCountries = (data.topCountries as Array<{ count: number; dimensions: { clientCountryName: string } }>) || [];
  const topPaths = (data.topPaths as Array<{ count: number; dimensions: { clientRequestPath: string } }>) || [];

  return {
    total_events: totalEvents,
    events_by_action,
    events_by_rule: [],
    top_paths: topPaths.map((p) => ({ path: p.dimensions.clientRequestPath, count: p.count })),
    top_countries: topCountries.map((c) => ({ country: c.dimensions.clientCountryName, count: c.count })),
  };
}

// ── Cache Analytics ──

export async function getCacheAnalytics(
  zoneId: string,
  token: string,
): Promise<CacheAnalytics> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(CACHE_ANALYTICS_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.cacheGroups as Array<{
    count: number;
    sum: { edgeResponseBytes: number };
    dimensions: { cacheStatus: string };
  }>) || [];

  let totalRequests = 0;
  let cachedRequests = 0;
  let uncachedRequests = 0;
  let bandwidthTotal = 0;
  let bandwidthCached = 0;
  let bandwidthUncached = 0;

  const hitStatuses = new Set(['hit', 'stale', 'revalidated', 'updating']);
  const missStatuses = new Set(['miss', 'expired', 'bypass', 'dynamic', 'none']);

  for (const g of groups) {
    const status = g.dimensions.cacheStatus?.toLowerCase() || '';
    totalRequests += g.count;
    bandwidthTotal += g.sum.edgeResponseBytes;

    if (hitStatuses.has(status)) {
      cachedRequests += g.count;
      bandwidthCached += g.sum.edgeResponseBytes;
    } else if (missStatuses.has(status)) {
      uncachedRequests += g.count;
      bandwidthUncached += g.sum.edgeResponseBytes;
    }
  }

  return {
    hit_ratio: totalRequests > 0 ? cachedRequests / totalRequests : 0,
    total_requests: totalRequests,
    cached_requests: cachedRequests,
    uncached_requests: uncachedRequests,
    bandwidth_total: bandwidthTotal,
    bandwidth_cached: bandwidthCached,
    bandwidth_uncached: bandwidthUncached,
  };
}

// ── Traffic Analytics ──

export async function getTrafficAnalytics(
  zoneId: string,
  token: string,
): Promise<TrafficAnalytics> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(TRAFFIC_OVERVIEW_QUERY, { zoneTag: zoneId, start, end }, token);

  const totals = (data.totals as Array<{ count: number; sum: { edgeResponseBytes: number } }>)?.[0];

  const statusGroups = (data.statusCodes as Array<{
    count: number;
    dimensions: { edgeResponseStatus: number };
  }>) || [];

  const statusCodes: Record<string, number> = {};
  for (const s of statusGroups) {
    statusCodes[String(s.dimensions.edgeResponseStatus)] = s.count;
  }

  const topPaths = (data.topPaths as Array<{ count: number; dimensions: { clientRequestPath: string } }>) || [];
  const topCountries = (data.topCountries as Array<{ count: number; dimensions: { clientCountryName: string } }>) || [];
  const topUserAgents = (data.topUserAgents as Array<{ count: number; dimensions: { userAgent: string } }>) || [];

  return {
    status_codes: statusCodes,
    top_paths: topPaths.map((p) => ({ path: p.dimensions.clientRequestPath, count: p.count })),
    top_countries: topCountries.map((c) => ({ country: c.dimensions.clientCountryName, count: c.count })),
    top_user_agents: topUserAgents.map((u) => ({ ua: u.dimensions.userAgent, count: u.count })),
    total_requests: totals?.count || 0,
    total_bandwidth: totals?.sum?.edgeResponseBytes || 0,
  };
}

// ── HTTP Methods ──

export async function getHTTPMethods(
  zoneId: string,
  token: string,
): Promise<HTTPMethodBreakdown[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(HTTP_METHOD_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.methods as Array<{
    count: number;
    dimensions: { clientRequestHTTPMethodName: string };
  }>) || [];

  return groups
    .filter((g) => g.count > 0)
    .map((g) => ({ method: g.dimensions.clientRequestHTTPMethodName, count: g.count }))
    .sort((a, b) => b.count - a.count);
}

// ── WAF Time Series (7-day, hourly) ──

export async function getWAFTimeSeries(
  zoneId: string,
  token: string,
): Promise<WAFTimeSeries> {
  const { start, end } = get7DayRange();
  const data = await gqlFetch(WAF_TIME_SERIES_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.series as Array<{
    count: number;
    dimensions: { datetimeHour: string; action: string };
  }>) || [];

  return {
    points: groups.map((g) => ({
      timestamp: g.dimensions.datetimeHour,
      action: g.dimensions.action,
      count: g.count,
    })),
  };
}

// ── Top Attacker IPs ──

export async function getTopAttackerIPs(
  zoneId: string,
  token: string,
): Promise<AttackerIP[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(TOP_ATTACKER_IPS_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.attackerIPs as Array<{
    count: number;
    dimensions: {
      clientIP: string;
      clientCountryName: string;
      clientAsn: string;
      clientASNDescription: string;
      action: string;
      userAgent: string;
    };
  }>) || [];

  // Aggregate by IP — GraphQL returns one row per unique (IP, action, UA) combo
  const ipMap = new Map<string, {
    ip: string;
    country: string;
    asn: number;
    asn_name: string;
    total: number;
    actions: Map<string, number>;
    uas: Map<string, number>;
  }>();

  for (const g of groups) {
    const ip = g.dimensions.clientIP;
    if (!ip) continue;

    let entry = ipMap.get(ip);
    if (!entry) {
      entry = {
        ip,
        country: g.dimensions.clientCountryName || '??',
        asn: parseInt(g.dimensions.clientAsn) || 0,
        asn_name: g.dimensions.clientASNDescription || '',
        total: 0,
        actions: new Map(),
        uas: new Map(),
      };
      ipMap.set(ip, entry);
    }

    entry.total += g.count;
    const action = g.dimensions.action || 'unknown';
    entry.actions.set(action, (entry.actions.get(action) || 0) + g.count);
    const ua = g.dimensions.userAgent || '';
    if (ua) entry.uas.set(ua, (entry.uas.get(ua) || 0) + g.count);
  }

  return Array.from(ipMap.values())
    .map((e) => {
      let topAction = 'unknown';
      let topActionCount = 0;
      for (const [a, c] of e.actions) {
        if (c > topActionCount) { topAction = a; topActionCount = c; }
      }
      let topUA = '';
      let topUACount = 0;
      for (const [u, c] of e.uas) {
        if (c > topUACount) { topUA = u; topUACount = c; }
      }
      return {
        ip: e.ip,
        country: e.country,
        asn: e.asn,
        asn_name: e.asn_name,
        action: topAction,
        user_agent: topUA,
        count: e.total,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);
}

// ════════════════════════════════════════════════════════════════════
// Tier 3 — Complete Collectors
// ════════════════════════════════════════════════════════════════════

// ── Bot ASNs ──

export async function getBotASNs(
  zoneId: string,
  token: string,
): Promise<BotASN[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(BOT_ASN_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.botASNs as Array<{
    count: number;
    dimensions: { clientASNDescription: string; clientAsn: string };
  }>) || [];

  return groups
    .filter((g) => g.count > 0)
    .map((g) => ({
      asn: parseInt(g.dimensions.clientAsn) || 0,
      name: g.dimensions.clientASNDescription || `AS${g.dimensions.clientAsn}`,
      count: g.count,
    }));
}

// ── Traffic Time Series (7-day, hourly by bot classification) ──

export async function getTrafficTimeSeries(
  zoneId: string,
  token: string,
): Promise<TrafficTimeSeries> {
  const { start, end } = get7DayRange();
  const data = await gqlFetch(TRAFFIC_TIME_SERIES_QUERY, { zoneTag: zoneId, start, end }, token);

  const mapPoints = (key: string) => {
    const groups = (data[key] as Array<{
      count: number;
      dimensions: { datetimeHour: string };
    }>) || [];
    return groups.map((g) => ({ timestamp: g.dimensions.datetimeHour, count: g.count }));
  };

  return {
    automated: mapPoints('automated'),
    likely_automated: mapPoints('likelyAutomated'),
    likely_human: mapPoints('likelyHuman'),
    verified_bot: mapPoints('verified'),
  };
}

// ── Bot Score Histogram (granular per-score) ──

export async function getBotScoreHistogram(
  zoneId: string,
  token: string,
): Promise<BotScoreHistogramBucket[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(BOT_SCORE_HISTOGRAM_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.histogram as Array<{
    count: number;
    dimensions: { botScore: number };
  }>) || [];

  return groups
    .filter((g) => g.count > 0)
    .map((g) => ({ score: g.dimensions.botScore, count: g.count }))
    .sort((a, b) => a.score - b.score);
}

// ── Detection Engine Breakdown ──

export async function getDetectionEngines(
  zoneId: string,
  token: string,
): Promise<DetectionEngineBreakdown[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(DETECTION_ENGINE_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.engines as Array<{
    count: number;
    dimensions: { botScoreSrcName: string };
  }>) || [];

  return groups
    .filter((g) => g.count > 0 && g.dimensions.botScoreSrcName)
    .map((g) => ({ engine: g.dimensions.botScoreSrcName, count: g.count }))
    .sort((a, b) => b.count - a.count);
}

// ── JA3 Fingerprints ──

export async function getJA3Fingerprints(
  zoneId: string,
  token: string,
): Promise<JA3Fingerprint[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(JA3_FINGERPRINT_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.ja3 as Array<{
    count: number;
    dimensions: { ja3Hash: string; clientRequestHTTPHost: string };
  }>) || [];

  return groups
    .filter((g) => g.count > 0 && g.dimensions.ja3Hash)
    .map((g) => ({ ja3_hash: g.dimensions.ja3Hash, host: g.dimensions.clientRequestHTTPHost || '', count: g.count }))
    .sort((a, b) => b.count - a.count);
}

// ── JA4 Fingerprints ──

export async function getJA4Fingerprints(
  zoneId: string,
  token: string,
): Promise<JA4Fingerprint[]> {
  const { start, end } = get30DayRange();
  const data = await gqlFetch(JA4_FINGERPRINT_QUERY, { zoneTag: zoneId, start, end }, token);

  const groups = (data.ja4 as Array<{
    count: number;
    dimensions: { ja4: string; clientRequestHTTPHost: string };
  }>) || [];

  return groups
    .filter((g) => g.count > 0 && g.dimensions.ja4)
    .map((g) => ({ ja4_hash: g.dimensions.ja4, host: g.dimensions.clientRequestHTTPHost || '', count: g.count }))
    .sort((a, b) => b.count - a.count);
}
