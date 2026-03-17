/**
 * Anga Security \u2014 Attack Simulator Engine (Main Orchestrator)
 *
 * Orchestrates the three-phase simulation:
 *   Phase 1: Intelligence Gathering (CF REST API)
 *   Phase 2: Active Probing (HTTP attack payloads)
 *   Phase 3: Post-Simulation Correlation (CF GraphQL firewall events)
 *
 * After all phases, computes:
 *   - Overall defense effectiveness score (0-100)
 *   - Per-module scores and grades
 *   - Defense layer attribution (donut chart data)
 *   - 17 actionable findings
 *   - 6-phase adoption roadmap
 *   - Executive summary
 *
 * Also exports `runSimulationAssembly()` for the Cloudflare Workflow
 * to call as a pure-computation step (Step 4).
 */

import type {
  SimulationReport,
  SimulationModuleResult,
  AttackTestResult,
  AttackModuleId,
  RoadmapPhase,
} from '../../types/simulation';

import {
  ATTACK_MODULES,
  MODULE_INFO,
  ROADMAP_PHASES,
  gradeFromScore,
  riskFromScore,
} from '../../types/simulation';

import { gatherIntelligence } from './intelligence';
import { executeAttacks } from './attacker';
import { correlateFirewallEvents, buildDefenseAttribution } from './correlation';
import { generateFindings } from './findings';

// ======================================================================
// Scoring
// ======================================================================

/**
 * Calculate module defense score (0-100).
 * Blocked/challenged = good, bypassed/error = bad.
 *
 * Weighting: blocked=1.0, challenged=0.85, bypassed=0, error=0.
 * Score = weighted sum / total * 100
 */
function calculateModuleScore(tests: AttackTestResult[]): number {
  if (tests.length === 0) return 100;

  let score = 0;
  for (const test of tests) {
    switch (test.outcome) {
      case 'blocked': score += 1.0; break;
      case 'challenged': score += 0.85; break;
      case 'bypassed': score += 0; break;
      case 'error': score += 0; break;
    }
  }

  return Math.round((score / tests.length) * 100);
}

/**
 * Calculate overall score as weighted average of module scores.
 * Critical modules get higher weight.
 */
const MODULE_WEIGHTS: Record<AttackModuleId, number> = {
  waf_bypass: 2.0,        // Most critical
  rate_limit: 1.5,
  bot_evasion: 1.3,
  custom_rule_bypass: 1.5,
  ip_geo_access: 1.2,
  ssl_tls: 1.0,
  cache_poisoning: 1.0,
  api_security: 1.5,
  challenge_analysis: 0.8,
};

function calculateOverallScore(modules: SimulationModuleResult[]): number {
  let weightedSum = 0;
  let totalWeight = 0;

  for (const mod of modules) {
    const weight = MODULE_WEIGHTS[mod.module] || 1.0;
    weightedSum += mod.score * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
}

// ======================================================================
// Module Results
// ======================================================================

function buildModuleResults(
  tests: AttackTestResult[],
  intelligence: import('../../types/simulation').SecurityIntelligence,
): SimulationModuleResult[] {
  const results: SimulationModuleResult[] = [];

  for (const moduleId of ATTACK_MODULES) {
    const moduleTests = tests.filter((t) => t.module === moduleId);
    const score = calculateModuleScore(moduleTests);

    const notes = buildIntelligenceNotes(moduleId, intelligence);

    results.push({
      module: moduleId,
      score,
      grade: gradeFromScore(score),
      total_tests: moduleTests.length,
      blocked: moduleTests.filter((t) => t.outcome === 'blocked').length,
      challenged: moduleTests.filter((t) => t.outcome === 'challenged').length,
      bypassed: moduleTests.filter((t) => t.outcome === 'bypassed').length,
      errors: moduleTests.filter((t) => t.outcome === 'error').length,
      intelligence_notes: notes,
      test_ids: moduleTests.map((t) => t.test_id),
    });
  }

  return results;
}

function buildIntelligenceNotes(
  moduleId: AttackModuleId,
  intel: import('../../types/simulation').SecurityIntelligence,
): { es: string; en: string }[] {
  const notes: { es: string; en: string }[] = [];

  switch (moduleId) {
    case 'waf_bypass':
      if (!intel.waf.cf_managed_ruleset) notes.push({ es: 'Cloudflare Managed Ruleset NO desplegado', en: 'Cloudflare Managed Ruleset NOT deployed' });
      if (!intel.waf.owasp_enabled) notes.push({ es: 'OWASP Core Ruleset NO habilitado', en: 'OWASP Core Ruleset NOT enabled' });
      if (intel.waf.owasp_paranoia_level && intel.waf.owasp_paranoia_level < 2) notes.push({ es: `Paranoia Level: PL${intel.waf.owasp_paranoia_level} (recomendado PL2+)`, en: `Paranoia Level: PL${intel.waf.owasp_paranoia_level} (recommended PL2+)` });
      if (!intel.waf.attack_score_rules) notes.push({ es: 'WAF Attack Score sin reglas activas', en: 'WAF Attack Score has no active rules' });
      break;
    case 'rate_limit':
      if (intel.rate_limits.total === 0) notes.push({ es: 'Sin reglas de rate limiting configuradas', en: 'No rate limiting rules configured' });
      else notes.push({ es: `${intel.rate_limits.total} regla(s) de rate limiting`, en: `${intel.rate_limits.total} rate limiting rule(s)` });
      break;
    case 'bot_evasion':
      if (!intel.bot_management.enabled && !intel.bot_management.sbfm_enabled) notes.push({ es: 'Bot Management / SBFM NO activo', en: 'Bot Management / SBFM NOT active' });
      if (!intel.bot_management.js_detection_enabled) notes.push({ es: 'JavaScript Detections deshabilitadas', en: 'JavaScript Detections disabled' });
      break;
    case 'custom_rule_bypass':
      notes.push({ es: `${intel.custom_rules.total} regla(s) custom analizadas`, en: `${intel.custom_rules.total} custom rule(s) analyzed` });
      break;
    case 'ip_geo_access':
      notes.push({ es: `${intel.ip_access_rules.length} regla(s) de acceso IP`, en: `${intel.ip_access_rules.length} IP access rule(s)` });
      break;
    case 'ssl_tls':
      notes.push({ es: `SSL Mode: ${intel.ssl_tls.ssl_mode}, Min TLS: ${intel.ssl_tls.min_tls_version}`, en: `SSL Mode: ${intel.ssl_tls.ssl_mode}, Min TLS: ${intel.ssl_tls.min_tls_version}` });
      if (!intel.ssl_tls.hsts_enabled) notes.push({ es: 'HSTS NO habilitado', en: 'HSTS NOT enabled' });
      break;
    case 'cache_poisoning':
      if (!intel.security.cache_deception_armor) notes.push({ es: 'Cache Deception Armor NO habilitado', en: 'Cache Deception Armor NOT enabled' });
      break;
    case 'api_security':
      notes.push({ es: `${intel.api_paths.length} ruta(s) API identificadas`, en: `${intel.api_paths.length} API path(s) identified` });
      if (!intel.security.leaked_credentials_enabled) notes.push({ es: 'Leaked Credentials Detection NO activa', en: 'Leaked Credentials Detection NOT active' });
      break;
    case 'challenge_analysis':
      notes.push({ es: `Security Level: ${intel.security.security_level}`, en: `Security Level: ${intel.security.security_level}` });
      notes.push({ es: `Challenge TTL: ${intel.security.challenge_ttl}s`, en: `Challenge TTL: ${intel.security.challenge_ttl}s` });
      break;
  }

  return notes;
}

// ======================================================================
// Executive Summary
// ======================================================================

function buildExecutiveSummary(
  modules: SimulationModuleResult[],
  tests: AttackTestResult[],
  intel: import('../../types/simulation').SecurityIntelligence,
  overallScore: number,
): SimulationReport['executive_summary'] {
  const bypassed = tests.filter((t) => t.outcome === 'bypassed').length;
  const blocked = tests.filter((t) => t.outcome === 'blocked').length;
  const challenged = tests.filter((t) => t.outcome === 'challenged').length;
  const riskLevel = riskFromScore(overallScore);

  // Attack surface description
  const attackSurface = {
    es: `Dominio ${intel.zone_name} (Plan: ${intel.cf_plan}). ${intel.waf.managed_rule_count} reglas WAF, ${intel.custom_rules.total} reglas custom, ${intel.rate_limits.total} rate limits. ${tests.length} pruebas de ataque ejecutadas.`,
    en: `Domain ${intel.zone_name} (Plan: ${intel.cf_plan}). ${intel.waf.managed_rule_count} WAF rules, ${intel.custom_rules.total} custom rules, ${intel.rate_limits.total} rate limits. ${tests.length} attack tests executed.`,
  };

  // Key findings (top 3 worst modules)
  const keyFindings: { es: string; en: string }[] = [];
  const sorted = [...modules].sort((a, b) => a.score - b.score);
  for (const mod of sorted.slice(0, 3)) {
    if (mod.bypassed > 0) {
      const info = MODULE_INFO[mod.module];
      keyFindings.push({
        es: `${info.name.es}: ${mod.bypassed}/${mod.total_tests} pruebas pasaron sin detecci\u00f3n (Score: ${mod.score}/100)`,
        en: `${info.name.en}: ${mod.bypassed}/${mod.total_tests} tests bypassed undetected (Score: ${mod.score}/100)`,
      });
    }
  }

  if (keyFindings.length === 0) {
    keyFindings.push({
      es: 'Todas las pruebas fueron bloqueadas o desafiadas exitosamente.',
      en: 'All tests were successfully blocked or challenged.',
    });
  }

  // Strengths
  const strengths: { es: string; en: string }[] = [];
  const strongModules = modules.filter((m) => m.score >= 80);
  if (strongModules.length > 0) {
    strengths.push({
      es: `${strongModules.length} m\u00f3dulo(s) con puntuaci\u00f3n >= 80: ${strongModules.map((m) => MODULE_INFO[m.module].name.es).join(', ')}`,
      en: `${strongModules.length} module(s) with score >= 80: ${strongModules.map((m) => MODULE_INFO[m.module].name.en).join(', ')}`,
    });
  }
  if (blocked + challenged > 0) {
    strengths.push({
      es: `${blocked + challenged} de ${tests.length} ataques (${Math.round((blocked + challenged) / tests.length * 100)}%) fueron detenidos.`,
      en: `${blocked + challenged} of ${tests.length} attacks (${Math.round((blocked + challenged) / tests.length * 100)}%) were stopped.`,
    });
  }

  // Immediate actions (from Phase 1 findings)
  const immediateActions: { es: string; en: string }[] = [];
  const bypassedCount = tests.filter((t) => t.outcome === 'bypassed').length;
  const bypassedPct = tests.length > 0 ? Math.round((bypassedCount / tests.length) * 100) : 0;

  if (!intel.waf.cf_managed_ruleset) {
    immediateActions.push({
      es: 'Habilitar Cloudflare Managed Ruleset inmediatamente.',
      en: 'Enable Cloudflare Managed Ruleset immediately.',
    });
  } else if (bypassedPct > 50) {
    // Managed Ruleset IS active but majority of tests bypassed — suggest tuning
    immediateActions.push({
      es: 'Revisar las reglas del Managed Ruleset — está habilitado pero el ' + bypassedPct + '% de ataques lo evadieron. Verificar que las reglas estén en modo "Block" y no "Log".',
      en: 'Review Managed Ruleset rules — it is enabled but ' + bypassedPct + '% of attacks evaded it. Verify rules are in "Block" mode, not "Log".',
    });
  }

  if (!intel.ssl_tls.always_use_https) {
    immediateActions.push({
      es: 'Activar "Always Use HTTPS" para forzar HTTPS.',
      en: 'Enable "Always Use HTTPS" to force HTTPS.',
    });
  }

  if (intel.rate_limits.total === 0) {
    immediateActions.push({
      es: 'Configurar rate limiting para endpoints críticos.',
      en: 'Configure rate limiting for critical endpoints.',
    });
  } else if (intel.rate_limits.total > 0) {
    // Rate limits exist — check if rate limit tests bypassed
    const rlBypassed = tests.filter((t) => t.module === 'rate_limit' && t.outcome === 'bypassed').length;
    const rlTotal = tests.filter((t) => t.module === 'rate_limit').length;
    if (rlBypassed > 0 && rlTotal > 0) {
      immediateActions.push({
        es: `Rate limiting configurado (${intel.rate_limits.total} regla(s)) pero ${rlBypassed} de ${rlTotal} pruebas lograron evadirlo. Revisar umbrales y paths cubiertos.`,
        en: `Rate limiting configured (${intel.rate_limits.total} rule(s)) but ${rlBypassed} of ${rlTotal} tests bypassed it. Review thresholds and covered paths.`,
      });
    }
  }

  if (!intel.bot_management.enabled && !intel.bot_management.sbfm_enabled) {
    immediateActions.push({
      es: 'Activar Super Bot Fight Mode o Bot Management.',
      en: 'Enable Super Bot Fight Mode or Bot Management.',
    });
  }

  if (immediateActions.length === 0) {
    immediateActions.push({
      es: 'Revisar y ajustar umbrales según los hallazgos del reporte.',
      en: 'Review and adjust thresholds based on report findings.',
    });
  }
  if (!intel.ssl_tls.always_use_https) {
    immediateActions.push({
      es: 'Activar "Always Use HTTPS" para forzar HTTPS.',
      en: 'Enable "Always Use HTTPS" to force HTTPS.',
    });
  }
  if (intel.rate_limits.total === 0) {
    immediateActions.push({
      es: 'Configurar rate limiting para endpoints cr\u00edticos.',
      en: 'Configure rate limiting for critical endpoints.',
    });
  }
  if (!intel.bot_management.enabled && !intel.bot_management.sbfm_enabled) {
    immediateActions.push({
      es: 'Activar Super Bot Fight Mode o Bot Management.',
      en: 'Enable Super Bot Fight Mode or Bot Management.',
    });
  }
  if (immediateActions.length === 0) {
    immediateActions.push({
      es: 'Revisar y ajustar umbrales seg\u00fan los hallazgos del reporte.',
      en: 'Review and adjust thresholds based on report findings.',
    });
  }

  return {
    risk_level: riskLevel,
    attack_surface: attackSurface,
    key_findings: keyFindings,
    strengths,
    immediate_actions: immediateActions,
  };
}

// ======================================================================
// Roadmap Builder
// ======================================================================

function buildRoadmap(findings: import('../../types/simulation').SimulationFinding[]): RoadmapPhase[] {
  return ROADMAP_PHASES.map((phase) => ({
    ...phase,
    finding_ids: findings
      .filter((f) => f.roadmap_phase === phase.phase)
      .map((f) => f.finding_id),
  }));
}

// ======================================================================
// Report Assembly (used by Workflow Step 4 -- pure computation, no I/O)
// ======================================================================

export interface AssemblyInput {
  intelligence: import('../../types/simulation').SecurityIntelligence;
  tests: AttackTestResult[];
  zoneId: string;
  domain: string;
}

/**
 * Pure-computation step: takes the outputs of Phases 1-3 and assembles
 * the full SimulationReport. No network calls -- only data transforms.
 *
 * Exported so the Cloudflare Workflow can call it from a dedicated step.
 */
export function runSimulationAssembly(input: AssemblyInput): SimulationReport {
  const { intelligence, tests, zoneId } = input;

  const modules = buildModuleResults(tests, intelligence);
  const overallScore = calculateOverallScore(modules);
  const overallGrade = gradeFromScore(overallScore);
  const riskLevel = riskFromScore(overallScore);
  const defenseAttribution = buildDefenseAttribution(tests);
  const findings = generateFindings(tests, intelligence);
  const roadmap = buildRoadmap(findings);
  const executiveSummary = buildExecutiveSummary(modules, tests, intelligence, overallScore);

  const blocked = tests.filter((t) => t.outcome === 'blocked').length;
  const challenged = tests.filter((t) => t.outcome === 'challenged').length;
  const bypassed = tests.filter((t) => t.outcome === 'bypassed').length;
  const errors = tests.filter((t) => t.outcome === 'error').length;

  return {
    zone_name: intelligence.zone_name,
    zone_id: zoneId,
    cf_plan: intelligence.cf_plan,
    generated_at: new Date().toISOString(),
    duration_ms: 0, // Filled by the caller (workflow or monolithic runner)
    phase_durations: {
      intelligence_ms: 0,
      probing_ms: 0,
      correlation_ms: 0,
    },

    overall_score: overallScore,
    overall_grade: overallGrade,
    risk_level: riskLevel,

    summary: {
      total_tests: tests.length,
      blocked,
      challenged,
      bypassed,
      errors,
      modules_tested: modules.length,
    },

    executive_summary: executiveSummary,
    defense_attribution: defenseAttribution,
    intelligence,
    modules,
    test_results: tests,
    findings,
    roadmap,

    disclaimer: {
      es: 'Este reporte fue generado mediante simulaci\u00f3n automatizada de ataques seguros. Los resultados reflejan la configuraci\u00f3n de seguridad al momento de la ejecuci\u00f3n y pueden variar. Las pruebas utilizan payloads de detecci\u00f3n no destructivos dise\u00f1ados para activar reglas de seguridad sin causar da\u00f1o. Este reporte no reemplaza una auditor\u00eda de penetraci\u00f3n profesional.',
      en: 'This report was generated through automated safe attack simulation. Results reflect the security configuration at execution time and may vary. Tests use non-destructive detection payloads designed to trigger security rules without causing damage. This report does not replace a professional penetration audit.',
    },
  };
}

// ======================================================================
// Main Export: Run Full Simulation (legacy monolithic runner)
// ======================================================================

export interface SimulationConfig {
  zoneId: string;
  apiToken: string;
  accountId: string;
  /** Override domain (defaults to zone_name from intelligence) */
  domain?: string;
}

/**
 * Runs all three phases sequentially then assembles the report.
 * This is the legacy monolithic function -- the Workflow now calls
 * each phase as a separate step instead.
 */
export async function runSimulation(config: SimulationConfig): Promise<SimulationReport> {
  const totalStartTime = Date.now();

  // ---- Phase 1: Intelligence Gathering ----
  const phase1Start = Date.now();
  const intelligence = await gatherIntelligence(config.zoneId, config.apiToken);
  const phase1Duration = Date.now() - phase1Start;

  // Determine target domain
  const domain = config.domain || intelligence.zone_name;

  // ---- Phase 2: Active Probing ----
  const phase2Start = Date.now();
  const simulationStartISO = new Date(phase2Start).toISOString();
  const rawTests = await executeAttacks(domain, intelligence);
  const phase2Duration = Date.now() - phase2Start;

  // ---- Phase 3: Post-Simulation Correlation ----
  const phase3Start = Date.now();
  const correlationResult = await correlateFirewallEvents(
    config.zoneId,
    config.apiToken,
    rawTests,
    simulationStartISO,
  );
  const phase3Duration = Date.now() - phase3Start;

  const tests = correlationResult.tests;

  // ---- Assemble report using shared helper ----
  const report = runSimulationAssembly({
    intelligence,
    tests,
    zoneId: config.zoneId,
    domain,
  });

  // Fill in timing data that only the monolithic runner knows
  report.duration_ms = Date.now() - totalStartTime;
  report.phase_durations = {
    intelligence_ms: phase1Duration,
    probing_ms: phase2Duration,
    correlation_ms: phase3Duration,
  };

  return report;
}
