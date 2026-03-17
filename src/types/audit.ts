/**
 * Anga Security — Audit Engine Type Definitions
 *
 * Improved structure over the original Sentinel engine:
 * - Explicit 3-tier architecture (Basic / Pro / Complete)
 * - Discriminated collector registry with tier + plan requirements
 * - Partial collected data (only fields relevant to the purchased tier)
 * - Stronger typing for GraphQL response parsing
 * - Clean separation between CF API types, scoring types, and report types
 */

// ════════════════════════════════════════════════════════════════════
// Audit Tiers
// ════════════════════════════════════════════════════════════════════

/** The three purchasable audit tiers */
export type AuditTier = 'basic' | 'pro' | 'complete';

/** Internal identifiers used in DB / API */
export type AuditTypeId = 'audit_config' | 'audit_security' | 'audit_l7';

/** Maps tier to internal ID */
export const AUDIT_TIER_MAP: Record<AuditTier, AuditTypeId> = {
  basic: 'audit_config',
  pro: 'audit_security',
  complete: 'audit_l7',
};

/** Reverse map: internal ID → tier */
export const AUDIT_TYPE_TO_TIER: Record<AuditTypeId, AuditTier> = {
  audit_config: 'basic',
  audit_security: 'pro',
  audit_l7: 'complete',
};

/** Credit cost per audit tier */
export const AUDIT_CREDIT_COSTS: Record<AuditTier, number> = {
  basic: 1500,
  pro: 3000,
  complete: 5000,
};

/** Human-readable tier names */
export const AUDIT_TIER_NAMES: Record<AuditTier, { es: string; en: string }> = {
  basic: { es: 'Auditoría Basic', en: 'Basic Audit' },
  pro: { es: 'Auditoría Pro', en: 'Pro Audit' },
  complete: { es: 'Auditoría Complete', en: 'Complete Audit' },
};

// ════════════════════════════════════════════════════════════════════
// Cloudflare Plan Tiers
// ════════════════════════════════════════════════════════════════════

export type CloudflarePlanTier = 'free' | 'pro' | 'business' | 'enterprise';

/** Numeric ordering for plan comparison */
export const CF_PLAN_ORDER: Record<CloudflarePlanTier, number> = {
  free: 0,
  pro: 1,
  business: 2,
  enterprise: 3,
};

/** Normalize Cloudflare plan name string to tier */
export function detectPlanTier(planName: string): CloudflarePlanTier {
  const lower = planName.toLowerCase();
  if (lower.includes('enterprise')) return 'enterprise';
  if (lower.includes('business')) return 'business';
  if (lower.includes('pro')) return 'pro';
  return 'free';
}

/** Check if zone's plan meets or exceeds the minimum required tier */
export function planMeetsMinimum(
  zonePlan: CloudflarePlanTier,
  minPlan: CloudflarePlanTier,
): boolean {
  return CF_PLAN_ORDER[zonePlan] >= CF_PLAN_ORDER[minPlan];
}

// ════════════════════════════════════════════════════════════════════
// Collector Registry — What runs at each tier
// ════════════════════════════════════════════════════════════════════

/** All collector names in the system */
export type CollectorName =
  // REST (Tier 1 — Basic)
  | 'zone_info'
  | 'zone_settings'
  | 'dns_records'
  | 'dnssec'
  | 'rulesets_waf'
  // GraphQL (Tier 2 — Pro)
  | 'waf_events'
  | 'cache_analytics'
  | 'traffic_overview'
  | 'http_methods'
  | 'waf_time_series'
  | 'top_attacker_ips'
  | 'bot_scores'
  // GraphQL (Tier 3 — Complete)
  | 'bot_asns'
  | 'traffic_time_series'
  | 'bot_score_histogram'
  | 'detection_engines'
  | 'ja3_fingerprints'
  | 'ja4_fingerprints';

export interface CollectorSpec {
  name: CollectorName;
  label: string;
  type: 'rest' | 'graphql';
  /** Minimum audit tier required to run this collector */
  minTier: AuditTier;
  /** Minimum CF plan required (null = runs on all plans) */
  minPlan: CloudflarePlanTier | null;
}

/**
 * Master registry of all collectors, their tier requirements, and plan gates.
 * The orchestrator uses this to decide what to run for a given (tier, plan) combo.
 */
export const COLLECTOR_REGISTRY: CollectorSpec[] = [
  // ── REST Collectors (Tier 1: Basic) ──
  { name: 'zone_info',     label: 'Zone Info',       type: 'rest',    minTier: 'basic', minPlan: null },
  { name: 'zone_settings', label: 'Zone Settings',   type: 'rest',    minTier: 'basic', minPlan: null },
  { name: 'dns_records',   label: 'DNS Records',     type: 'rest',    minTier: 'basic', minPlan: null },
  { name: 'dnssec',        label: 'DNSSEC',          type: 'rest',    minTier: 'basic', minPlan: null },
  { name: 'rulesets_waf',  label: 'Rulesets / WAF',  type: 'rest',    minTier: 'basic', minPlan: null },

  // ── GraphQL Collectors (Tier 2: Pro) ──
  { name: 'waf_events',       label: 'WAF Events',         type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'cache_analytics',  label: 'Cache Analytics',    type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'traffic_overview', label: 'Traffic Overview',   type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'http_methods',     label: 'HTTP Methods',       type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'waf_time_series',  label: 'WAF Time Series',   type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'top_attacker_ips', label: 'Top Attacker IPs',  type: 'graphql', minTier: 'pro', minPlan: null },
  { name: 'bot_scores',       label: 'Bot Scores',         type: 'graphql', minTier: 'pro', minPlan: 'pro' },

  // ── GraphQL Collectors (Tier 3: Complete) ──
  { name: 'bot_asns',             label: 'Bot ASNs',             type: 'graphql', minTier: 'complete', minPlan: 'pro' },
  { name: 'traffic_time_series',  label: 'Traffic Time Series',  type: 'graphql', minTier: 'complete', minPlan: 'pro' },
  { name: 'bot_score_histogram',  label: 'Bot Score Histogram',  type: 'graphql', minTier: 'complete', minPlan: 'enterprise' },
  { name: 'detection_engines',    label: 'Detection Engines',    type: 'graphql', minTier: 'complete', minPlan: 'enterprise' },
  { name: 'ja3_fingerprints',     label: 'JA3 Fingerprints',     type: 'graphql', minTier: 'complete', minPlan: 'enterprise' },
  { name: 'ja4_fingerprints',     label: 'JA4 Fingerprints',     type: 'graphql', minTier: 'complete', minPlan: 'enterprise' },
];

/** Get the list of collectors that should run for a given audit tier + CF plan */
export function getCollectorsForTierAndPlan(
  auditTier: AuditTier,
  cfPlan: CloudflarePlanTier,
): { active: CollectorSpec[]; skipped: CollectorSpec[] } {
  const tierOrder: Record<AuditTier, number> = { basic: 0, pro: 1, complete: 2 };
  const purchasedLevel = tierOrder[auditTier];

  const active: CollectorSpec[] = [];
  const skipped: CollectorSpec[] = [];

  for (const spec of COLLECTOR_REGISTRY) {
    const specLevel = tierOrder[spec.minTier];

    // Skip collectors beyond the purchased audit tier
    if (specLevel > purchasedLevel) {
      continue; // Not included in this tier at all — don't even report as skipped
    }

    // Collector is in-tier; check CF plan gate
    if (spec.minPlan && !planMeetsMinimum(cfPlan, spec.minPlan)) {
      skipped.push(spec);
    } else {
      active.push(spec);
    }
  }

  return { active, skipped };
}

// ════════════════════════════════════════════════════════════════════
// Cloudflare API Data Types
// ════════════════════════════════════════════════════════════════════

// ── Zone Info (REST) ──

export interface ZoneInfo {
  id: string;
  name: string;
  status: string;
  plan: {
    name: string;
    price: number;
    currency: string;
    is_subscribed: boolean;
  };
  created_on: string;
  modified_on: string;
  name_servers: string[];
  original_name_servers: string[];
}

// ── Zone Settings (REST) ──

export interface ZoneSetting {
  id: string;
  value: unknown;
  editable: boolean;
  modified_on?: string;
}

// ── Rulesets / WAF (REST) ──

export interface RulesetRule {
  id: string;
  action: string;
  expression: string;
  description?: string;
  enabled: boolean;
}

export interface Ruleset {
  id: string;
  name: string;
  kind: string;
  phase: string;
  rules: RulesetRule[];
}

// ���─ DNS (REST) ──

export interface CFDNSRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  proxied: boolean;
  ttl: number;
}

export interface DNSSummary {
  total_records: number;
  proxied_count: number;
  dns_only_count: number;
  record_types: Record<string, number>;
  dnssec_enabled: boolean;
}

// ── Bot Scores (GraphQL) ──

export interface BotScoreDistribution {
  automated: number;
  likely_automated: number;
  likely_human: number;
  verified_bot: number;
  total_requests: number;
}

// ── WAF Events (GraphQL) ──

export interface WAFEventsSummary {
  total_events: number;
  events_by_action: Record<string, number>;
  events_by_rule: Array<{ rule_id: string; description: string; count: number }>;
  top_paths: Array<{ path: string; count: number }>;
  top_countries: Array<{ country: string; count: number }>;
}

// ── Cache Analytics (GraphQL) ──

export interface CacheAnalytics {
  hit_ratio: number;
  total_requests: number;
  cached_requests: number;
  uncached_requests: number;
  bandwidth_total: number;
  bandwidth_cached: number;
  bandwidth_uncached: number;
}

// ── Traffic Analytics (GraphQL) ──

export interface TrafficAnalytics {
  status_codes: Record<string, number>;
  top_paths: Array<{ path: string; count: number }>;
  top_countries: Array<{ country: string; count: number }>;
  top_user_agents: Array<{ ua: string; count: number }>;
  total_requests: number;
  total_bandwidth: number;
}

// ── Bot ASN (GraphQL) ──

export interface BotASN {
  asn: number;
  name: string;
  count: number;
}

// ── Bot Score Histogram (GraphQL — Enterprise + BM) ──

export interface BotScoreHistogramBucket {
  score: number;
  count: number;
}

// ── Detection Engines (GraphQL — Enterprise + BM) ──

export interface DetectionEngineBreakdown {
  engine: string;
  count: number;
}

// ── Fingerprints (GraphQL — Enterprise + BM) ──

export interface JA3Fingerprint {
  ja3_hash: string;
  host: string;
  count: number;
}

export interface JA4Fingerprint {
  ja4_hash: string;
  host: string;
  count: number;
}

// ── HTTP Methods (GraphQL) ──

export interface HTTPMethodBreakdown {
  method: string;
  count: number;
}

// ── Time Series (GraphQL) ──

export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
}

export interface TrafficTimeSeries {
  automated: TimeSeriesPoint[];
  likely_automated: TimeSeriesPoint[];
  likely_human: TimeSeriesPoint[];
  verified_bot: TimeSeriesPoint[];
}

export interface WAFTimeSeriesPoint {
  timestamp: string;
  action: string;
  count: number;
}

export interface WAFTimeSeries {
  points: WAFTimeSeriesPoint[];
}

// ── Attacker IPs (GraphQL) ──

export interface AttackerIP {
  ip: string;
  country: string;
  asn: number;
  asn_name: string;
  action: string;
  user_agent: string;
  count: number;
}

// ════════════════════════════════════════════════════════════════════
// Collected Data — Partial by tier
// ════════════════════════════════════════════════════════════════════

/**
 * All fields are optional because which fields are populated depends on
 * the audit tier purchased. The `zone_info` field is always required
 * because it's needed to determine the CF plan tier.
 */
export interface CollectedData {
  // Always present (required to determine plan)
  zone_info: ZoneInfo;

  // Tier 1 — Basic (REST)
  zone_settings?: ZoneSetting[];
  rulesets?: Ruleset[];
  dns_summary?: DNSSummary;

  // Tier 2 — Pro (GraphQL)
  waf_events?: WAFEventsSummary;
  cache_analytics?: CacheAnalytics;
  traffic_analytics?: TrafficAnalytics;
  http_methods?: HTTPMethodBreakdown[];
  waf_time_series?: WAFTimeSeries;
  top_attacker_ips?: AttackerIP[];
  bot_scores?: BotScoreDistribution;

  // Tier 3 — Complete (GraphQL, deep L7)
  bot_asns?: BotASN[];
  traffic_time_series?: TrafficTimeSeries;
  bot_score_histogram?: BotScoreHistogramBucket[];
  detection_engines?: DetectionEngineBreakdown[];
  ja3_fingerprints?: JA3Fingerprint[];
  ja4_fingerprints?: JA4Fingerprint[];

  // Metadata
  warnings: CollectorWarning[];
  skipped_collectors: SkippedCollector[];
}

// ════════════════════════════════════════════════════════════════════
// Collector Execution Metadata
// ════════════════════════════════════════════════════════════════════

export interface CollectorWarning {
  collector: string;
  message: string;
}

export interface SkippedCollector {
  collector: string;
  reason: 'plan_gate' | 'tier_gate';
  detail: string;
}

// ════════════════════════════════════════════════════════════════════
// Score Engine Types
// ════════════════════════════════════════════════════════════════════

export type ScoreGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export type ScoringCategory =
  | 'ssl_tls'
  | 'waf_coverage'
  | 'bot_protection'
  | 'ddos_config'
  | 'api_security'
  | 'dns_security'
  | 'access_control'
  | 'performance_cache';

/** Category weights — must sum to 1.0 */
export const CATEGORY_WEIGHTS: Record<ScoringCategory, number> = {
  ssl_tls: 0.15,
  waf_coverage: 0.20,
  bot_protection: 0.15,
  ddos_config: 0.10,
  api_security: 0.10,
  dns_security: 0.10,
  access_control: 0.10,
  performance_cache: 0.10,
};

/** Human-readable labels for each scoring category */
export const CATEGORY_LABELS: Record<ScoringCategory, { es: string; en: string }> = {
  ssl_tls:           { es: 'SSL / TLS',            en: 'SSL / TLS' },
  waf_coverage:      { es: 'Cobertura WAF',        en: 'WAF Coverage' },
  bot_protection:    { es: 'Protección contra Bots', en: 'Bot Protection' },
  ddos_config:       { es: 'Configuración DDoS',   en: 'DDoS Configuration' },
  api_security:      { es: 'Seguridad de API',     en: 'API Security' },
  dns_security:      { es: 'Seguridad DNS',        en: 'DNS Security' },
  access_control:    { es: 'Control de Acceso',     en: 'Access Control' },
  performance_cache: { es: 'Rendimiento y Caché',  en: 'Performance & Cache' },
};

/** Which scoring categories are available at each audit tier */
export const TIER_SCORING_CATEGORIES: Record<AuditTier, ScoringCategory[]> = {
  basic: ['ssl_tls', 'dns_security', 'access_control', 'ddos_config', 'performance_cache'],
  pro: ['ssl_tls', 'waf_coverage', 'bot_protection', 'ddos_config', 'api_security', 'dns_security', 'access_control', 'performance_cache'],
  complete: ['ssl_tls', 'waf_coverage', 'bot_protection', 'ddos_config', 'api_security', 'dns_security', 'access_control', 'performance_cache'],
};

export interface CategoryScore {
  category: ScoringCategory;
  label: { es: string; en: string };
  weight: number;
  score: number;          // 0-100
  weighted_score: number;
  findings: string[];
  grade: ScoreGrade;
  /** True if the score is limited because the CF plan doesn't support certain features */
  plan_limited: boolean;
  plan_note?: string;
}

export interface ScoreBreakdown {
  overall_score: number;
  overall_grade: ScoreGrade;
  categories: CategoryScore[];
  /** Normalized weight sum (may be < 1.0 if some categories were excluded at lower tiers) */
  effective_weight_sum: number;
}

// ════════════════════════════════════════════════════════════════════
// Recommendations
// ════════════════════════════════════════════════════════════════════

export type RecommendationPriority = 'critical' | 'high' | 'medium';

export interface Recommendation {
  priority: RecommendationPriority;
  category: ScoringCategory;
  title: string;
  description: string;
  /** Cloudflare product that addresses this (e.g. "WAF", "Bot Management") */
  product?: string;
  /** Estimated security impact if addressed */
  estimated_value?: string;
  /** Minimum CF plan required to implement this recommendation */
  min_plan?: CloudflarePlanTier;
}

// ════════════════════════════════════════════════════════════════════
// Audit Report — The full output stored in security_reports.data
// ════════════════════════════════════════════════════════════════════

export interface AuditReport {
  /** Angaflow report version */
  version: '1.0';
  /** Which audit tier was purchased */
  tier: AuditTier;
  tier_id: AuditTypeId;

  /** Zone metadata */
  zone_id: string;
  zone_name: string;
  cf_plan: CloudflarePlanTier;

  /** Timing */
  generated_at: string;
  duration_ms: number;
  analysis_period: {
    start: string;
    end: string;
  };

  /** Scoring */
  score: ScoreBreakdown;

  /** Raw collected data (tier-dependent, partial) */
  data: CollectedData;

  /** Actionable recommendations sorted by priority */
  recommendations: Recommendation[];

  /** Execution metadata */
  collectors_run: number;
  collectors_skipped: number;
  collectors_warned: number;
}

// ════════════════════════════════════════════════════════════════════
// API Request / Response Types
// ════════════════════════════════════════════════════════════════════

export interface StartAuditRequest {
  zone_id: string;
  api_token: string;
  tier: AuditTier;
}

export interface StartAuditResponse {
  report_id: string;
  tier: AuditTier;
  credits_charged: number;
  /** The full report — audit runs synchronously (5-30s depending on tier) */
  report: AuditReport;
}

export interface AuditReportResponse {
  report_id: string;
  tier: AuditTier;
  created_at: string;
  report: AuditReport;
}

// ════════════════════════════════════════════════════════════════════
// Default Empty Values (for graceful degradation)
// ════════════════════════════════════════════════════════════════════

export const EMPTY_SETTINGS: ZoneSetting[] = [];
export const EMPTY_RULESETS: Ruleset[] = [];
export const EMPTY_DNS: DNSSummary = {
  total_records: 0,
  proxied_count: 0,
  dns_only_count: 0,
  record_types: {},
  dnssec_enabled: false,
};
export const EMPTY_BOT_SCORES: BotScoreDistribution = {
  automated: 0,
  likely_automated: 0,
  likely_human: 0,
  verified_bot: 0,
  total_requests: 0,
};
export const EMPTY_WAF_EVENTS: WAFEventsSummary = {
  total_events: 0,
  events_by_action: {},
  events_by_rule: [],
  top_paths: [],
  top_countries: [],
};
export const EMPTY_CACHE: CacheAnalytics = {
  hit_ratio: 0,
  total_requests: 0,
  cached_requests: 0,
  uncached_requests: 0,
  bandwidth_total: 0,
  bandwidth_cached: 0,
  bandwidth_uncached: 0,
};
export const EMPTY_TRAFFIC: TrafficAnalytics = {
  status_codes: {},
  top_paths: [],
  top_countries: [],
  top_user_agents: [],
  total_requests: 0,
  total_bandwidth: 0,
};
export const EMPTY_BOT_ASNS: BotASN[] = [];
export const EMPTY_HISTOGRAM: BotScoreHistogramBucket[] = [];
export const EMPTY_ENGINES: DetectionEngineBreakdown[] = [];
export const EMPTY_JA3: JA3Fingerprint[] = [];
export const EMPTY_JA4: JA4Fingerprint[] = [];
export const EMPTY_METHODS: HTTPMethodBreakdown[] = [];
export const EMPTY_TRAFFIC_TS: TrafficTimeSeries = {
  automated: [],
  likely_automated: [],
  likely_human: [],
  verified_bot: [],
};
export const EMPTY_WAF_TS: WAFTimeSeries = { points: [] };
export const EMPTY_ATTACKER_IPS: AttackerIP[] = [];

// ════════════════════════════════════════════════════════════════════
// Utility: Grade from score
// ════════════════════════════════════════════════════════════════════

export function gradeFromScore(score: number): ScoreGrade {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
