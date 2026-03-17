/**
 * Anga Security — Score Engine (Plan + Tier Aware)
 *
 * 8 scoring categories with per-check normalization:
 *   SSL/TLS (15%) | WAF Coverage (20%) | Bot Protection (15%) | DDoS Config (10%)
 *   API Security (10%) | DNS Security (10%) | Access Control (10%) | Performance/Cache (10%)
 *
 * Key improvements over sentinel:
 *   - Tier-aware: only scores categories available at the purchased audit tier
 *   - Automatic weight normalization when categories are excluded
 *   - Each scorer uses ScoringCheck[] pattern for transparent point allocation
 *   - Bilingual category labels built into output
 *   - Recommendation generator references both CF plan and audit tier
 */

import type {
  AuditTier,
  CloudflarePlanTier,
  CollectedData,
  CategoryScore,
  ScoreBreakdown,
  ScoringCategory,
  Recommendation,
  ZoneSetting,
} from '../../types/audit';

import {
  CATEGORY_WEIGHTS,
  CATEGORY_LABELS,
  TIER_SCORING_CATEGORIES,
  gradeFromScore,
  planMeetsMinimum,
  detectPlanTier,
} from '../../types/audit';

// ════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════

function getSetting(settings: ZoneSetting[], id: string): unknown {
  return settings.find((s) => s.id === id)?.value;
}

function clamp(val: number): number {
  return Math.max(0, Math.min(100, Math.round(val)));
}

interface ScoringCheck {
  name: string;
  maxPoints: number;
  earned: number;
}

function normalizeChecks(checks: ScoringCheck[]): number {
  const totalMax = checks.reduce((s, c) => s + c.maxPoints, 0);
  if (totalMax === 0) return 50;
  const totalEarned = checks.reduce((s, c) => s + Math.min(c.earned, c.maxPoints), 0);
  return clamp(Math.round((totalEarned / totalMax) * 100));
}

interface ScorerResult {
  score: number;
  findings: string[];
  plan_limited: boolean;
  plan_note?: string;
}

function detectBotManagement(data: CollectedData): boolean {
  return (
    (data.bot_score_histogram?.length ?? 0) > 0 ||
    (data.detection_engines?.length ?? 0) > 0
  );
}

// ════════════════════════════════════════════════════════════════════
// Category Scorers
// ════════════════════════════════════════════════════════════════════

function scoreSSL(data: CollectedData, _plan: CloudflarePlanTier): ScorerResult {
  let score = 0;
  const findings: string[] = [];
  const settings = data.zone_settings ?? [];

  const sslMode = getSetting(settings, 'ssl') as string;
  if (sslMode === 'strict' || sslMode === 'full_strict') {
    score += 30;
    findings.push('SSL mode set to Full (Strict) — excellent');
  } else if (sslMode === 'full') {
    score += 20;
    findings.push('SSL mode is Full — consider upgrading to Full (Strict)');
  } else if (sslMode === 'flexible') {
    score += 5;
    findings.push('SSL mode is Flexible — insecure, traffic to origin is unencrypted');
  } else {
    findings.push(`SSL mode: ${sslMode || 'unknown'}`);
  }

  const tls13 = getSetting(settings, 'tls_1_3');
  if (tls13 === 'on' || tls13 === 'zrt') {
    score += 15;
    findings.push('TLS 1.3 enabled');
  } else {
    findings.push('TLS 1.3 not enabled');
  }

  const minTls = getSetting(settings, 'min_tls_version') as string;
  if (minTls === '1.2' || minTls === '1.3') {
    score += 20;
    findings.push(`Minimum TLS version: ${minTls}`);
  } else if (minTls === '1.1') {
    score += 10;
    findings.push('Minimum TLS 1.1 — consider requiring 1.2+');
  } else {
    findings.push(`Minimum TLS version: ${minTls || '1.0'} — insecure`);
  }

  const alwaysHttps = getSetting(settings, 'always_use_https');
  if (alwaysHttps === 'on') {
    score += 15;
    findings.push('Always Use HTTPS enabled');
  } else {
    findings.push('Always Use HTTPS not enabled');
  }

  const hsts = getSetting(settings, 'security_header') as {
    strict_transport_security?: { enabled?: boolean; max_age?: number };
  } | undefined;
  if (hsts?.strict_transport_security?.enabled) {
    score += 20;
    const maxAge = hsts.strict_transport_security.max_age || 0;
    findings.push(maxAge >= 31536000
      ? 'HSTS enabled with max-age >= 1 year'
      : `HSTS enabled but max-age is ${maxAge}s — recommend >= 31536000`);
  } else {
    findings.push('HSTS not enabled');
  }

  return { score: clamp(score), findings, plan_limited: false };
}

function scoreWAF(data: CollectedData, plan: CloudflarePlanTier): ScorerResult {
  const findings: string[] = [];
  const checks: ScoringCheck[] = [];
  let planLimited = false;
  let planNote: string | undefined;
  const rulesets = data.rulesets ?? [];

  const managed = rulesets.filter((rs) => rs.phase === 'http_request_firewall_managed');
  const custom = rulesets.filter((rs) => rs.phase === 'http_request_firewall_custom');
  const rateLimit = rulesets.filter((rs) => rs.phase === 'http_ratelimit');

  const hasWAF = managed.length > 0 || custom.length > 0;
  checks.push({ name: 'waf_enabled', maxPoints: 15, earned: hasWAF ? 15 : 0 });
  findings.push(hasWAF ? 'WAF is enabled (rulesets detected)' : 'No WAF rulesets detected — WAF appears disabled');

  if (planMeetsMinimum(plan, 'pro')) {
    const totalRules = managed.reduce((sum, rs) => sum + (rs.rules?.length || 0), 0);
    checks.push({ name: 'managed', maxPoints: 25, earned: managed.length > 0 ? 25 : 0 });
    findings.push(managed.length > 0
      ? `${managed.length} managed ruleset(s) with ${totalRules} rules`
      : 'No managed WAF rulesets — enable OWASP/CF managed rules');
  } else {
    planLimited = true;
    planNote = 'Managed WAF rulesets require Pro+ plan';
    findings.push('Managed WAF rulesets not available on Free plan');
  }

  const totalCustom = custom.reduce((sum, rs) => sum + (rs.rules?.length || 0), 0);
  const customEarned = totalCustom >= 3 ? 25 : totalCustom >= 1 ? Math.min(totalCustom * 8, 25) : 0;
  checks.push({ name: 'custom', maxPoints: 25, earned: customEarned });
  findings.push(totalCustom > 0
    ? `${totalCustom} custom firewall rule(s)`
    : 'No custom firewall rules — consider adding zone-specific rules');

  const totalRL = rateLimit.reduce((sum, rs) => sum + (rs.rules?.length || 0), 0);
  checks.push({ name: 'ratelimit', maxPoints: 20, earned: totalRL >= 2 ? 20 : totalRL >= 1 ? 12 : 0 });
  findings.push(totalRL > 0 ? `${totalRL} rate limiting rule(s)` : 'No rate limiting rules configured');

  // WAF events (only available at Pro+ tier since they need GraphQL data)
  const wafTotal = data.waf_events?.total_events ?? 0;
  if (data.waf_events) {
    checks.push({ name: 'events', maxPoints: 15, earned: wafTotal > 0 ? 15 : 0 });
    if (wafTotal > 0) findings.push(`${wafTotal.toLocaleString()} WAF events in last 30 days`);
  }

  return { score: normalizeChecks(checks), findings, plan_limited: planLimited, plan_note: planNote };
}

function scoreBotProtection(data: CollectedData, plan: CloudflarePlanTier): ScorerResult {
  const findings: string[] = [];
  const checks: ScoringCheck[] = [];
  let planLimited = false;
  let planNote: string | undefined;
  const settings = data.zone_settings ?? [];
  const botData = data.bot_scores;

  if (planMeetsMinimum(plan, 'pro') && botData && botData.total_requests > 0) {
    const automatedPct = (botData.automated / botData.total_requests) * 100;
    const likelyAutoPct = (botData.likely_automated / botData.total_requests) * 100;
    const botPct = automatedPct + likelyAutoPct;

    findings.push(`Traffic: ${automatedPct.toFixed(1)}% automated, ${likelyAutoPct.toFixed(1)}% likely automated`);

    let botEarned = 0;
    if (botPct < 10) { botEarned = 40; findings.push('Bot traffic well-controlled (<10%)'); }
    else if (botPct < 30) { botEarned = 25; findings.push('Moderate bot traffic (10-30%)'); }
    else if (botPct < 60) { botEarned = 10; findings.push('High bot traffic (30-60%) — Bot Management recommended'); }
    else { findings.push('Very high bot traffic (>60%) — urgent mitigation needed'); }
    checks.push({ name: 'bot_analytics', maxPoints: 40, earned: botEarned });

    if (botData.verified_bot > 0) {
      checks.push({ name: 'verified_bots', maxPoints: 10, earned: 10 });
      findings.push(`${botData.verified_bot.toLocaleString()} verified bot requests identified`);
    }
  } else if (plan === 'free' || !botData) {
    planLimited = true;
    planNote = 'Bot score analytics require Pro+ plan';
    findings.push('Bot analytics not available — scoring based on zone settings only');
  } else {
    findings.push('No bot analytics data available');
    checks.push({ name: 'bot_analytics', maxPoints: 40, earned: 10 });
  }

  const browserCheck = getSetting(settings, 'browser_check');
  checks.push({ name: 'browser_check', maxPoints: 15, earned: browserCheck === 'on' ? 15 : 0 });
  findings.push(browserCheck === 'on' ? 'Browser Integrity Check enabled' : 'Browser Integrity Check not enabled');

  const secLevel = getSetting(settings, 'security_level') as string;
  let secEarned = 5;
  if (secLevel === 'high' || secLevel === 'under_attack') { secEarned = 20; }
  else if (secLevel === 'medium') { secEarned = 15; }
  findings.push(`Security level: ${secLevel || 'low'}`);
  checks.push({ name: 'security_level', maxPoints: 20, earned: secEarned });

  const challengeTTL = getSetting(settings, 'challenge_ttl') as number;
  let ttlEarned = 0;
  if (challengeTTL && challengeTTL <= 1800) { ttlEarned = 15; }
  else if (challengeTTL && challengeTTL <= 3600) { ttlEarned = 10; }
  checks.push({ name: 'challenge_ttl', maxPoints: 15, earned: ttlEarned });

  return { score: normalizeChecks(checks), findings, plan_limited: planLimited, plan_note: planNote };
}

function scoreDDoS(data: CollectedData, _plan: CloudflarePlanTier): ScorerResult {
  const findings: string[] = [];
  const checks: ScoringCheck[] = [];
  const settings = data.zone_settings ?? [];
  const rulesets = data.rulesets ?? [];

  checks.push({ name: 'l7_baseline', maxPoints: 40, earned: 40 });
  findings.push('Cloudflare L7 DDoS protection is always-on');

  const secLevel = getSetting(settings, 'security_level') as string;
  let secEarned = 0;
  if (secLevel === 'under_attack') { secEarned = 20; findings.push("I'm Under Attack mode is active"); }
  else if (secLevel === 'high') { secEarned = 15; }
  checks.push({ name: 'security_level', maxPoints: 20, earned: secEarned });

  const rl = rulesets.filter((rs) => rs.phase === 'http_ratelimit');
  checks.push({ name: 'rate_limiting', maxPoints: 20, earned: rl.length > 0 ? 20 : 0 });
  findings.push(rl.length > 0 ? 'Rate limiting rules configured' : 'No rate limiting — recommended for DDoS mitigation');

  // WAF block events (only available if GraphQL data present)
  if (data.waf_events) {
    const blockActions = data.waf_events.events_by_action;
    const blocked = (blockActions['block'] || 0) + (blockActions['challenge'] || 0) +
      (blockActions['managed_challenge'] || 0) + (blockActions['js_challenge'] || 0);
    checks.push({ name: 'waf_mitigation', maxPoints: 20, earned: blocked > 0 ? 20 : 0 });
    if (blocked > 0) findings.push(`${blocked.toLocaleString()} requests blocked/challenged in last 30 days`);
  }

  return { score: normalizeChecks(checks), findings, plan_limited: false };
}

function scoreAPISecurity(data: CollectedData, plan: CloudflarePlanTier): ScorerResult {
  const findings: string[] = [];
  const checks: ScoringCheck[] = [];
  let planLimited = false;
  let planNote: string | undefined;
  const rulesets = data.rulesets ?? [];

  checks.push({ name: 'baseline', maxPoints: 20, earned: 20 });

  if (planMeetsMinimum(plan, 'enterprise')) {
    checks.push({ name: 'api_shield_access', maxPoints: 20, earned: 10 });
    findings.push('API Shield available on Enterprise plan — verify configuration in dashboard');
  } else {
    planLimited = true;
    planNote = 'API Shield requires Enterprise plan';
    findings.push(`API Shield not available on ${plan} plan`);
  }

  const custom = rulesets.filter((rs) => rs.phase === 'http_request_firewall_custom');
  const apiRules = custom.flatMap((rs) =>
    (rs.rules || []).filter((r) =>
      r.expression?.includes('http.request.uri.path') &&
      (r.expression?.includes('/api') || r.expression?.includes('content-type'))
    )
  );
  checks.push({ name: 'api_custom_rules', maxPoints: 30, earned: apiRules.length > 0 ? Math.min(apiRules.length * 10, 30) : 0 });
  findings.push(apiRules.length > 0
    ? `${apiRules.length} custom rule(s) targeting API paths`
    : 'No custom rules targeting API endpoints detected');

  // Traffic-based API detection (only at Pro+ tier)
  if (data.traffic_analytics) {
    const isApiPath = (p: string): boolean => {
      const lower = p.toLowerCase();
      return lower.includes('/api') || lower.includes('/v1') || lower.includes('/v2') ||
        lower.includes('/graphql') || lower.includes('/rest') || lower.includes('/webhook');
    };
    const apiPaths = data.traffic_analytics.top_paths.filter((p) => isApiPath(p.path));
    if (apiPaths.length > 0) {
      findings.push(`${apiPaths.length} API endpoint(s) detected in traffic`);
      for (const ep of apiPaths.slice(0, 5)) findings.push(`  ${ep.path}`);
      checks.push({ name: 'api_traffic', maxPoints: 10, earned: 10 });
    }

    // Cross-reference WAF events
    if (data.waf_events) {
      const attackedApi = (data.waf_events.top_paths || []).filter((p) => isApiPath(p.path));
      if (attackedApi.length > 0) {
        findings.push(`${attackedApi.length} API endpoint(s) targeted by attacks`);
        if (apiRules.length === 0) {
          checks.push({ name: 'api_unprotected', maxPoints: 20, earned: 0 });
          findings.push('API endpoints under attack with no custom WAF rules');
        } else {
          checks.push({ name: 'api_mitigated', maxPoints: 20, earned: 15 });
        }
      }
    }
  }

  return { score: normalizeChecks(checks), findings, plan_limited: planLimited, plan_note: planNote };
}

function scoreDNS(data: CollectedData, _plan: CloudflarePlanTier): ScorerResult {
  let score = 0;
  const findings: string[] = [];
  const dns = data.dns_summary;
  const settings = data.zone_settings ?? [];

  if (!dns) return { score: 50, findings: ['DNS data not available'], plan_limited: false };

  if (dns.dnssec_enabled) {
    score += 35;
    findings.push('DNSSEC enabled');
  } else {
    findings.push('DNSSEC not enabled — recommended for DNS integrity');
  }

  if (dns.total_records > 0) {
    const proxiedPct = (dns.proxied_count / dns.total_records) * 100;
    if (proxiedPct >= 80) { score += 30; }
    else if (proxiedPct >= 50) { score += 20; }
    else { score += 10; }
    findings.push(`${proxiedPct.toFixed(0)}% of records proxied through Cloudflare`);
  }

  const ipv6 = getSetting(settings, 'ipv6');
  if (ipv6 === 'on') { score += 15; findings.push('IPv6 compatibility enabled'); }
  else { findings.push('IPv6 not enabled'); }

  findings.push(`${dns.total_records} total DNS records`);
  score += 20;

  return { score: clamp(score), findings, plan_limited: false };
}

function scoreAccessControl(data: CollectedData, _plan: CloudflarePlanTier): ScorerResult {
  let score = 20;
  const findings: string[] = [];
  const settings = data.zone_settings ?? [];
  const rulesets = data.rulesets ?? [];

  const custom = rulesets.filter((rs) => rs.phase === 'http_request_firewall_custom');
  const accessRules = custom.flatMap((rs) =>
    (rs.rules || []).filter((r) =>
      r.expression?.includes('ip.src') ||
      r.expression?.includes('ip.geoip') ||
      r.expression?.includes('http.request.uri') ||
      r.action === 'block'
    )
  );

  if (accessRules.length > 0) {
    score += Math.min(accessRules.length * 10, 40);
    findings.push(`${accessRules.length} access control rule(s) configured`);
  } else {
    findings.push('No IP/geo-based access control rules detected');
  }

  if (getSetting(settings, 'hotlink_protection') === 'on') { score += 10; findings.push('Hotlink Protection enabled'); }
  if (getSetting(settings, 'browser_check') === 'on') { score += 15; findings.push('Browser Integrity Check enabled'); }
  if (getSetting(settings, 'email_obfuscation') === 'on') { score += 15; findings.push('Email Address Obfuscation enabled'); }

  return { score: clamp(score), findings, plan_limited: false };
}

function scorePerformance(data: CollectedData, plan: CloudflarePlanTier): ScorerResult {
  const findings: string[] = [];
  const checks: ScoringCheck[] = [];
  let planLimited = false;
  let planNote: string | undefined;
  const settings = data.zone_settings ?? [];
  const cache = data.cache_analytics;

  if (cache) {
    let cacheEarned = 0;
    if (cache.hit_ratio >= 0.8) { cacheEarned = 35; findings.push(`Cache hit ratio: ${(cache.hit_ratio * 100).toFixed(1)}% — excellent`); }
    else if (cache.hit_ratio >= 0.5) { cacheEarned = 25; findings.push(`Cache hit ratio: ${(cache.hit_ratio * 100).toFixed(1)}%`); }
    else if (cache.hit_ratio > 0) { cacheEarned = 10; findings.push(`Cache hit ratio: ${(cache.hit_ratio * 100).toFixed(1)}% — low`); }
    else { findings.push('No cache data available'); }
    checks.push({ name: 'cache_ratio', maxPoints: 35, earned: cacheEarned });
  }

  const minify = getSetting(settings, 'minify') as { css?: string; js?: string; html?: string } | undefined;
  if (minify) {
    const enabled = [minify.css, minify.js, minify.html].filter((v) => v === 'on').length;
    checks.push({ name: 'minify', maxPoints: 15, earned: enabled * 5 });
    findings.push(`Minification: ${enabled}/3 types enabled`);
  }

  const brotli = getSetting(settings, 'brotli');
  checks.push({ name: 'brotli', maxPoints: 10, earned: brotli === 'on' ? 10 : 0 });
  findings.push(brotli === 'on' ? 'Brotli compression enabled' : 'Brotli compression not enabled');

  if (planMeetsMinimum(plan, 'pro')) {
    const h2 = getSetting(settings, 'h2_prioritization');
    checks.push({ name: 'h2_prio', maxPoints: 10, earned: h2 === 'on' ? 10 : 0 });
  } else {
    planLimited = true;
    planNote = 'H2 Prioritization requires Pro+ plan';
  }

  const http3 = getSetting(settings, 'http3');
  checks.push({ name: 'http3', maxPoints: 10, earned: http3 === 'on' ? 10 : 0 });
  if (http3 === 'on') findings.push('HTTP/3 enabled');
  else findings.push('HTTP/3 not enabled');

  const earlyHints = getSetting(settings, 'early_hints');
  checks.push({ name: 'early_hints', maxPoints: 10, earned: earlyHints === 'on' ? 10 : 0 });
  if (earlyHints === 'on') findings.push('Early Hints (103) enabled');

  const ws = getSetting(settings, 'websockets');
  checks.push({ name: 'websockets', maxPoints: 5, earned: ws === 'on' ? 5 : 0 });

  return { score: normalizeChecks(checks), findings, plan_limited: planLimited, plan_note: planNote };
}

// ════════════════════════════════════════════════════════════════════
// Scorer Registry
// ════════════════════════════════════════════════════════════════════

type ScorerFn = (data: CollectedData, plan: CloudflarePlanTier) => ScorerResult;

const SCORER_MAP: Record<ScoringCategory, ScorerFn> = {
  ssl_tls: scoreSSL,
  waf_coverage: scoreWAF,
  bot_protection: scoreBotProtection,
  ddos_config: scoreDDoS,
  api_security: scoreAPISecurity,
  dns_security: scoreDNS,
  access_control: scoreAccessControl,
  performance_cache: scorePerformance,
};

// ════════════════════════════════════════════════════════════════════
// Main Score Calculator
// ════════════════════════════════════════════════════════════════════

export function calculateScore(
  data: CollectedData,
  auditTier: AuditTier,
): ScoreBreakdown {
  const plan = detectPlanTier(data.zone_info.plan.name);
  const activeCategories = TIER_SCORING_CATEGORIES[auditTier];

  // Calculate effective weights (normalized to sum to 1.0)
  const rawWeightSum = activeCategories.reduce((sum, cat) => sum + CATEGORY_WEIGHTS[cat], 0);

  const scored: CategoryScore[] = activeCategories.map((category) => {
    const scorer = SCORER_MAP[category];
    const result = scorer(data, plan);
    const originalWeight = CATEGORY_WEIGHTS[category];
    const normalizedWeight = originalWeight / rawWeightSum; // Ensure weights sum to 1.0

    return {
      category,
      label: CATEGORY_LABELS[category],
      weight: normalizedWeight,
      score: result.score,
      weighted_score: Math.round(result.score * normalizedWeight * 100) / 100,
      findings: result.findings,
      grade: gradeFromScore(result.score),
      plan_limited: result.plan_limited,
      plan_note: result.plan_note,
    };
  });

  const overallScore = Math.round(
    scored.reduce((sum, c) => sum + c.score * c.weight, 0),
  );

  return {
    overall_score: clamp(overallScore),
    overall_grade: gradeFromScore(overallScore),
    categories: scored,
    effective_weight_sum: rawWeightSum,
  };
}

// ════════════════════════════════════════════════════════════════════
// Recommendation Generator
// ════════════════════════════════════════════════════════════════════

export function generateRecommendations(
  data: CollectedData,
  score: ScoreBreakdown,
  auditTier: AuditTier,
): Recommendation[] {
  const recs: Recommendation[] = [];
  const plan = detectPlanTier(data.zone_info.plan.name);
  const settings = data.zone_settings ?? [];
  const rulesets = data.rulesets ?? [];

  // ── SSL/TLS ──
  const sslMode = getSetting(settings, 'ssl') as string;
  if (sslMode !== 'strict' && sslMode !== 'full_strict') {
    recs.push({
      priority: sslMode === 'flexible' || sslMode === 'off' ? 'critical' : 'high',
      category: 'ssl_tls',
      title: 'Upgrade SSL Mode to Full (Strict)',
      description: 'Full (Strict) ensures encrypted and authenticated connections to your origin, preventing MITM attacks.',
      product: 'SSL/TLS',
      min_plan: 'free',
    });
  }

  if (getSetting(settings, 'always_use_https') !== 'on') {
    recs.push({
      priority: 'high',
      category: 'ssl_tls',
      title: 'Enable Always Use HTTPS',
      description: 'Redirects all HTTP requests to HTTPS, preventing unencrypted traffic.',
      product: 'SSL/TLS',
      min_plan: 'free',
    });
  }

  const hsts = getSetting(settings, 'security_header') as {
    strict_transport_security?: { enabled?: boolean };
  } | undefined;
  if (!hsts?.strict_transport_security?.enabled) {
    recs.push({
      priority: 'high',
      category: 'ssl_tls',
      title: 'Enable HSTS',
      description: 'HTTP Strict Transport Security tells browsers to always use HTTPS.',
      product: 'SSL/TLS',
      min_plan: 'free',
    });
  }

  // ── WAF ──
  const wafCat = score.categories.find((c) => c.category === 'waf_coverage');
  if (wafCat && wafCat.score < 50) {
    if (planMeetsMinimum(plan, 'pro')) {
      recs.push({
        priority: 'critical',
        category: 'waf_coverage',
        title: 'Enable WAF Managed Rules',
        description: 'Cloudflare WAF protects against OWASP Top 10, SQLi, XSS, and other attacks.',
        product: 'WAF',
        estimated_value: '$$$',
        min_plan: 'pro',
      });
    } else {
      recs.push({
        priority: 'high',
        category: 'waf_coverage',
        title: 'Upgrade to Pro for WAF Managed Rules',
        description: 'Managed WAF rulesets require Pro or higher. Consider upgrading for automated threat protection.',
        product: 'WAF',
        estimated_value: '~$20/mo (Pro plan)',
        min_plan: 'pro',
      });
    }
  }

  const rl = rulesets.filter((rs) => rs.phase === 'http_ratelimit');
  if (rl.length === 0) {
    recs.push({
      priority: 'high',
      category: 'waf_coverage',
      title: 'Configure Rate Limiting Rules',
      description: 'Rate limiting protects against brute force attacks, API abuse, and L7 DDoS.',
      product: 'Rate Limiting',
      min_plan: 'free',
    });
  }

  // ── Bot Protection (only recommend if we have data — Pro+ tier) ──
  if (data.bot_scores && data.bot_scores.total_requests > 0) {
    const botPct = ((data.bot_scores.automated + data.bot_scores.likely_automated) / data.bot_scores.total_requests) * 100;
    if (botPct > 20) {
      recs.push({
        priority: botPct > 50 ? 'critical' : 'high',
        category: 'bot_protection',
        title: 'Deploy Bot Management',
        description: `${botPct.toFixed(1)}% of traffic is automated. Bot Management provides ML-based detection and behavioral analysis.`,
        product: 'Bot Management',
        estimated_value: '$$$',
        min_plan: 'enterprise',
      });
    }
  }

  // ── DNS ──
  const dns = data.dns_summary;
  if (dns && !dns.dnssec_enabled) {
    recs.push({
      priority: 'medium',
      category: 'dns_security',
      title: 'Enable DNSSEC',
      description: 'DNSSEC adds cryptographic signatures to DNS records, preventing spoofing.',
      product: 'DNS',
      min_plan: 'free',
    });
  }

  if (dns && dns.total_records > 0) {
    const proxiedPct = (dns.proxied_count / dns.total_records) * 100;
    if (proxiedPct < 50) {
      recs.push({
        priority: 'medium',
        category: 'dns_security',
        title: 'Proxy More DNS Records',
        description: `Only ${proxiedPct.toFixed(0)}% of records are proxied. Un-proxied records expose your origin IP.`,
        product: 'DNS',
        min_plan: 'free',
      });
    }
  }

  // ── Performance ──
  if (data.cache_analytics && data.cache_analytics.hit_ratio < 0.5 && data.cache_analytics.total_requests > 0) {
    recs.push({
      priority: 'medium',
      category: 'performance_cache',
      title: 'Improve Cache Hit Ratio',
      description: `Cache hit ratio is ${(data.cache_analytics.hit_ratio * 100).toFixed(1)}%. Review cache rules and increase TTLs.`,
      product: 'Cache',
      min_plan: 'free',
    });
  }

  if (getSetting(settings, 'brotli') !== 'on') {
    recs.push({
      priority: 'medium',
      category: 'performance_cache',
      title: 'Enable Brotli Compression',
      description: 'Brotli provides 15-20% better compression than gzip.',
      product: 'Speed',
      min_plan: 'free',
    });
  }

  // ── API Security ──
  if (data.traffic_analytics) {
    const apiPaths = data.traffic_analytics.top_paths.filter(
      (p) => p.path.includes('/api') || p.path.includes('/v1') || p.path.includes('/v2') || p.path.includes('/graphql'),
    );
    if (apiPaths.length > 0) {
      recs.push({
        priority: 'high',
        category: 'api_security',
        title: 'Enable API Shield',
        description: `Detected ${apiPaths.length} API path(s). API Shield provides schema validation and endpoint discovery.`,
        product: 'API Shield',
        estimated_value: '$$$',
        min_plan: 'enterprise',
      });
    }
  }

  // Sort by priority
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2 };
  recs.sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3));

  return recs;
}
