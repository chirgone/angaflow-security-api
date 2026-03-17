/**
 * Anga Security \u2014 Attack Simulator Type Definitions
 *
 * Three-phase architecture:
 *   Phase 1: Intelligence Gathering (CF REST + GraphQL API)
 *   Phase 2: Active Probing (HTTP requests with attack payloads)
 *   Phase 3: Post-Simulation Correlation (CF GraphQL firewall events)
 *
 * 9 attack modules, 75+ simulated attacks, 17 actionable findings.
 * Costs 3,500 credits per simulation run.
 */

import type { CloudflarePlanTier } from './audit';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Constants
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export const SIMULATION_CREDIT_COST = 3500;

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Attack Modules
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export type AttackModuleId =
  | 'waf_bypass'
  | 'rate_limit'
  | 'bot_evasion'
  | 'custom_rule_bypass'
  | 'ip_geo_access'
  | 'ssl_tls'
  | 'cache_poisoning'
  | 'api_security'
  | 'challenge_analysis';

export const ATTACK_MODULES: AttackModuleId[] = [
  'waf_bypass',
  'rate_limit',
  'bot_evasion',
  'custom_rule_bypass',
  'ip_geo_access',
  'ssl_tls',
  'cache_poisoning',
  'api_security',
  'challenge_analysis',
];

export interface AttackModuleInfo {
  id: AttackModuleId;
  name: { es: string; en: string };
  description: { es: string; en: string };
  icon: string; // unicode escape
  color: string;
  testCount: number;
}

export const MODULE_INFO: Record<AttackModuleId, AttackModuleInfo> = {
  waf_bypass: {
    id: 'waf_bypass',
    name: { es: 'WAF Bypass / OWASP Top 10', en: 'WAF Bypass / OWASP Top 10' },
    description: {
      es: 'Pruebas de inyecci\u00f3n SQL, XSS, path traversal, inyecci\u00f3n de comandos y SSRF contra WAF managed rules y OWASP Core Ruleset.',
      en: 'SQL injection, XSS, path traversal, command injection, and SSRF tests against WAF managed rules and OWASP Core Ruleset.',
    },
    icon: '\u{1F6E1}',
    color: '#ef4444',
    testCount: 12,
  },
  rate_limit: {
    id: 'rate_limit',
    name: { es: 'L\u00edmites de Velocidad / DDoS', en: 'Rate Limiting / DDoS Threshold' },
    description: {
      es: 'R\u00e1fagas controladas para detectar cu\u00e1ndo se activan los l\u00edmites de velocidad y protecci\u00f3n DDoS HTTP.',
      en: 'Controlled bursts to detect when rate limiting and HTTP DDoS protection activate.',
    },
    icon: '\u26A1',
    color: '#f59e0b',
    testCount: 8,
  },
  bot_evasion: {
    id: 'bot_evasion',
    name: { es: 'Evasi\u00f3n de Bot Management', en: 'Bot Management Evasion' },
    description: {
      es: 'Variaci\u00f3n de User-Agents, cabeceras de automatizaci\u00f3n y firmas de headless browsers.',
      en: 'Varying User-Agents, automation headers, and headless browser signatures.',
    },
    icon: '\u{1F916}',
    color: '#8b5cf6',
    testCount: 10,
  },
  custom_rule_bypass: {
    id: 'custom_rule_bypass',
    name: { es: 'Bypass de Reglas Custom', en: 'Custom Firewall Rule Bypass' },
    description: {
      es: 'Analiza las expresiones exactas de tus reglas custom y prueba variaciones de may\u00fasculas, encoding y rutas.',
      en: 'Parses exact custom rule expressions and tests casing, encoding, and path variations.',
    },
    icon: '\u{1F50D}',
    color: '#06b6d4',
    testCount: 8,
  },
  ip_geo_access: {
    id: 'ip_geo_access',
    name: { es: 'Control de IP/Geo', en: 'IP/Geo Access Control' },
    description: {
      es: 'Prueba de spoofing de X-Forwarded-For, confianza en cabeceras y controles de acceso geogr\u00e1fico.',
      en: 'X-Forwarded-For spoofing, header trust issues, and geographic access control tests.',
    },
    icon: '\u{1F30D}',
    color: '#10b981',
    testCount: 6,
  },
  ssl_tls: {
    id: 'ssl_tls',
    name: { es: 'Configuraci\u00f3n SSL/TLS', en: 'SSL/TLS Configuration' },
    description: {
      es: 'Comportamiento de redirecci\u00f3n HTTP\u2192HTTPS, HSTS, downgrade de protocolo y contenido mixto.',
      en: 'HTTP to HTTPS redirect behavior, HSTS enforcement, protocol downgrade, and mixed content.',
    },
    icon: '\u{1F512}',
    color: '#3b82f6',
    testCount: 8,
  },
  cache_poisoning: {
    id: 'cache_poisoning',
    name: { es: 'Cache Poisoning / Deception', en: 'Cache Poisoning / Deception' },
    description: {
      es: 'Par\u00e1metros de cache-busting, variaci\u00f3n de Host header, Cache Deception Armor y consistencia de respuestas.',
      en: 'Cache-busting parameters, Host header variation, Cache Deception Armor, and response consistency.',
    },
    icon: '\u{1F4BE}',
    color: '#ec4899',
    testCount: 8,
  },
  api_security: {
    id: 'api_security',
    name: { es: 'Seguridad de API', en: 'API Endpoint Security' },
    description: {
      es: 'Payloads maliciosos en endpoints API, m\u00e9todos HTTP inesperados, cuerpos sobredimensionados y JSON malformado.',
      en: 'Malicious payloads on API endpoints, unexpected HTTP methods, oversized bodies, and malformed JSON.',
    },
    icon: '\u{1F517}',
    color: '#f97316',
    testCount: 8,
  },
  challenge_analysis: {
    id: 'challenge_analysis',
    name: { es: 'An\u00e1lisis de Challenge Pages', en: 'Challenge Page Analysis' },
    description: {
      es: 'Identifica qu\u00e9 activa los challenges, tipos de challenge (managed/JS/interactive) y comportamiento de clearance.',
      en: 'Identifies what triggers challenges, challenge types (managed/JS/interactive), and clearance behavior.',
    },
    icon: '\u{1F6A7}',
    color: '#64748b',
    testCount: 8,
  },
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Test Results
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** What happened to the attack request */
export type AttackOutcome = 'blocked' | 'challenged' | 'bypassed' | 'error';

/** Severity of a finding */
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Individual attack test result */
export interface AttackTestResult {
  /** Unique test ID e.g. SIM-T001 */
  test_id: string;
  /** Which module this test belongs to */
  module: AttackModuleId;
  /** Short name for the test */
  name: { es: string; en: string };
  /** Full description of what was tested */
  description: { es: string; en: string };
  /** The outcome: blocked, challenged, bypassed, or error */
  outcome: AttackOutcome;
  /** Severity rating */
  severity: FindingSeverity;

  // ---- Request Details ----
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };

  // ---- Response Details ----
  response: {
    status_code: number;
    /** Time to first byte in ms */
    response_time_ms: number;
    /** Key response headers */
    headers: Record<string, string>;
    /** Was cf-mitigated: challenge present? */
    cf_mitigated: boolean;
    /** cf-ray ID */
    cf_ray: string | null;
    /** cf-cache-status value */
    cf_cache_status: string | null;
    /** First 500 chars of body (for challenge detection) */
    body_preview: string;
    /** Detected challenge type if any */
    challenge_type: 'managed_challenge' | 'js_challenge' | 'interactive_challenge' | 'none';
  };

  // ---- Phase 3 Correlation (filled after GraphQL query) ----
  correlation: {
    /** CF rule ID that matched, if any */
    rule_id: string | null;
    /** CF rule description */
    rule_description: string | null;
    /** Which CF security system caught it */
    security_source: string | null;
    /** CF action taken */
    action: string | null;
    /** OWASP anomaly score if applicable */
    owasp_score: number | null;
    /** Bot score assigned by CF */
    bot_score: number | null;
    /** WAF attack score if available */
    waf_attack_score: number | null;
  };

  // ---- Recommendation (always present for bypassed tests) ----
  recommendation: {
    /** What to do */
    action: { es: string; en: string };
    /** Which CF product to configure */
    cf_product: string;
    /** Dashboard path in CF */
    dashboard_path: string;
    /** CF docs URL */
    docs_url: string;
    /** Effort estimate */
    effort: 'quick_fix' | 'moderate' | 'complex';
    /** Which roadmap phase this maps to */
    roadmap_phase: number;
  } | null;

  /** Linked finding ID (e.g. SIM-003), if this test is evidence for a finding */
  linked_finding_id: string | null;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Module Result
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Aggregated result for one attack module */
export interface SimulationModuleResult {
  module: AttackModuleId;
  /** Defense effectiveness score for this module 0-100 */
  score: number;
  grade: string;
  /** Counts */
  total_tests: number;
  blocked: number;
  challenged: number;
  bypassed: number;
  errors: number;
  /** Intelligence discovered in Phase 1 for this module */
  intelligence_notes: { es: string; en: string }[];
  /** The test IDs belonging to this module */
  test_ids: string[];
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Findings
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** One of the 17 actionable findings */
export interface SimulationFinding {
  /** Finding ID e.g. SIM-001 */
  finding_id: string;
  /** Severity */
  severity: FindingSeverity;
  /** Which module produced this finding */
  module: AttackModuleId;
  /** Title */
  title: { es: string; en: string };
  /** Detailed description of the issue */
  description: { es: string; en: string };
  /** Which tests proved this finding */
  evidence_test_ids: string[];
  /** How many tests bypassed related to this finding */
  bypassed_count: number;
  /** Remediation */
  remediation: {
    /** Summary of what to do */
    summary: { es: string; en: string };
    /** Step-by-step numbered actions */
    steps: Array<{
      order: number;
      action: { es: string; en: string };
      where: string;
      detail: { es: string; en: string };
    }>;
    /** CF product to configure */
    cf_product: string;
    /** Dashboard path */
    dashboard_path: string;
    /** CF docs link */
    docs_url: string;
    /** Effort estimate */
    effort: 'quick_fix' | 'moderate' | 'complex';
    /** Risk if not remediated */
    risk_if_ignored: { es: string; en: string };
  };
  /** Roadmap phase (1-6) */
  roadmap_phase: number;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Roadmap
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface RoadmapPhase {
  phase: number;
  name: { es: string; en: string };
  timeline: { es: string; en: string };
  description: { es: string; en: string };
  /** Finding IDs assigned to this phase */
  finding_ids: string[];
}

export const ROADMAP_PHASES: Omit<RoadmapPhase, 'finding_ids'>[] = [
  {
    phase: 1,
    name: { es: 'Correcciones Inmediatas', en: 'Immediate Fixes' },
    timeline: { es: '0-7 d\u00edas', en: '0-7 days' },
    description: {
      es: 'Vulnerabilidades cr\u00edticas donde ataques bypassearon completamente las defensas.',
      en: 'Critical vulnerabilities where attacks fully bypassed defenses.',
    },
  },
  {
    phase: 2,
    name: { es: 'Ganancias R\u00e1pidas', en: 'Quick Wins' },
    timeline: { es: '1-2 semanas', en: '1-2 weeks' },
    description: {
      es: 'Cambios de alto impacto y bajo esfuerzo (habilitar features existentes).',
      en: 'High-impact, low-effort changes (enable existing features).',
    },
  },
  {
    phase: 3,
    name: { es: 'Construcci\u00f3n de Fundamentos', en: 'Foundation Building' },
    timeline: { es: '2-4 semanas', en: '2-4 weeks' },
    description: {
      es: 'Mejoras principales en WAF, bot management y rate limiting.',
      en: 'Core WAF, bot management, and rate limiting improvements.',
    },
  },
  {
    phase: 4,
    name: { es: 'Protecci\u00f3n Avanzada', en: 'Advanced Protection' },
    timeline: { es: '1-2 meses', en: '1-2 months' },
    description: {
      es: 'Reglas custom, bot management avanzado y seguridad API.',
      en: 'Custom rules, advanced bot management, and API security.',
    },
  },
  {
    phase: 5,
    name: { es: 'Monitoreo y Ajuste', en: 'Monitoring & Tuning' },
    timeline: { es: '2-3 meses', en: '2-3 months' },
    description: {
      es: 'Afinar umbrales, reducir falsos positivos, optimizar reglas.',
      en: 'Fine-tune thresholds, reduce false positives, optimize rules.',
    },
  },
  {
    phase: 6,
    name: { es: 'Mejora Continua', en: 'Continuous Improvement' },
    timeline: { es: 'Permanente', en: 'Ongoing' },
    description: {
      es: 'Re-simulaci\u00f3n peri\u00f3dica, adaptaci\u00f3n a nuevas amenazas.',
      en: 'Periodic re-simulation, adapt to new threats.',
    },
  },
];

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Intelligence (Phase 1 output)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface SecurityIntelligence {
  /** Zone basic info */
  zone_name: string;
  cf_plan: CloudflarePlanTier;

  /** WAF configuration */
  waf: {
    managed_rules_enabled: boolean;
    /** Cloudflare Managed Ruleset deployed */
    cf_managed_ruleset: boolean;
    /** OWASP Core Ruleset deployed */
    owasp_enabled: boolean;
    owasp_paranoia_level: number | null;
    owasp_score_threshold: string | null; // 'low' | 'medium' | 'high'
    owasp_action: string | null;
    /** WAF attack score rules present */
    attack_score_rules: boolean;
    /** Total managed rules */
    managed_rule_count: number;
  };

  /** Custom firewall rules */
  custom_rules: {
    total: number;
    /** Parsed rule expressions for targeted bypass testing */
    rules: Array<{
      id: string;
      description: string;
      expression: string;
      action: string;
      enabled: boolean;
    }>;
  };

  /** Rate limiting rules */
  rate_limits: {
    total: number;
    rules: Array<{
      id: string;
      description: string;
      expression: string;
      period: number;
      requests_per_period: number;
      mitigation_timeout: number;
      action: string;
    }>;
  };

  /** Bot management */
  bot_management: {
    enabled: boolean;
    /** Super Bot Fight Mode for non-Enterprise */
    sbfm_enabled: boolean;
    /** JavaScript Detections enabled */
    js_detection_enabled: boolean;
    /** Bot score rules in custom rules */
    bot_score_rules: boolean;
  };

  /** SSL/TLS config */
  ssl_tls: {
    ssl_mode: string;
    min_tls_version: string;
    tls_1_3: string;
    always_use_https: boolean;
    hsts_enabled: boolean;
    hsts_max_age: number;
    hsts_include_subdomains: boolean;
    hsts_preload: boolean;
  };

  /** Security settings */
  security: {
    security_level: string;
    browser_check: boolean;
    challenge_ttl: number;
    privacy_pass: boolean;
    /** Leaked credentials detection */
    leaked_credentials_enabled: boolean;
    /** Cache deception armor */
    cache_deception_armor: boolean;
    hotlink_protection: boolean;
    email_obfuscation: boolean;
  };

  /** DNS summary */
  dns: {
    total_records: number;
    proxied_records: number;
    unproxied_records: number;
    dnssec_active: boolean;
  };

  /** IP access rules */
  ip_access_rules: Array<{
    mode: string;
    value: string;
    notes: string;
  }>;

  /** Discovered API paths (from traffic analytics if available) */
  api_paths: string[];

  /** Discovered login/auth paths */
  auth_paths: string[];
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Defense Layer Attribution (for the donut chart)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export type SecuritySourceKey =
  | 'waf_managed'
  | 'firewall_custom'
  | 'rate_limit'
  | 'bot_management'
  | 'ddos_protection'
  | 'not_blocked';

export interface DefenseAttribution {
  source: SecuritySourceKey;
  label: { es: string; en: string };
  count: number;
  color: string;
  /** Test IDs attributed to this source */
  test_ids: string[];
}

export const DEFENSE_SOURCE_META: Record<SecuritySourceKey, { label: { es: string; en: string }; color: string }> = {
  waf_managed: { label: { es: 'WAF Managed Rules', en: 'WAF Managed Rules' }, color: '#3b82f6' },
  firewall_custom: { label: { es: 'Reglas Custom', en: 'Custom Firewall Rules' }, color: '#06b6d4' },
  rate_limit: { label: { es: 'Rate Limiting', en: 'Rate Limiting' }, color: '#f59e0b' },
  bot_management: { label: { es: 'Bot Management', en: 'Bot Management' }, color: '#8b5cf6' },
  ddos_protection: { label: { es: 'Protecci\u00f3n DDoS', en: 'DDoS Protection' }, color: '#10b981' },
  not_blocked: { label: { es: 'No Bloqueados', en: 'Not Blocked' }, color: '#ef4444' },
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Full Simulation Report
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550


// ════════════════════════════════════════════════════════════════════
// Multi-Target Simulation Support
// ════════════════════════════════════════════════════════════════════

/** A discovered domain from DNS records that can be used as a simulation target */
export interface DiscoveredDomain {
  name: string;           // e.g., "api.anga-online.click"
  type: string;           // "A", "AAAA", or "CNAME"
  is_apex: boolean;       // true if this is the root domain
}

/** Summary of test results for a single target domain */
export interface TargetTestSummary {
  domain: string;
  is_apex: boolean;
  total_tests: number;
  blocked: number;
  challenged: number;
  bypassed: number;
  errors: number;
  score: number;          // 0-100 for this specific target
  grade: string;          // A-F for this target
  risk_level: 'critical' | 'high' | 'medium' | 'low';
}

export interface SimulationReport {
  // ---- Meta ----
  zone_name: string;
  zone_id: string;
  cf_plan: CloudflarePlanTier;
  generated_at: string;
  duration_ms: number;
  /** Phase timings */
  phase_durations: {
    intelligence_ms: number;
    probing_ms: number;
    correlation_ms: number;
  };

  // ---- Overall Scores ----
  overall_score: number; // 0-100 defense effectiveness
  overall_grade: string; // A-F
  risk_level: 'critical' | 'high' | 'medium' | 'low';

  // ---- Summary Stats ----
  summary: {
    total_tests: number;
    blocked: number;
    challenged: number;
    bypassed: number;
    errors: number;
    modules_tested: number;
  };

  // ---- Multi-Target Results (optional) ----
  targets?: TargetTestSummary[];

  // ---- Executive Summary ----
  executive_summary: {
    risk_level: string;
    attack_surface: { es: string; en: string };
    key_findings: Array<{ es: string; en: string }>;
    strengths: Array<{ es: string; en: string }>;
    immediate_actions: Array<{ es: string; en: string }>;
  };

  // ---- Defense Attribution ----
  defense_attribution: DefenseAttribution[];

  // ---- Intelligence (Phase 1) ----
  intelligence: SecurityIntelligence;

  // ---- Module Results ----
  modules: SimulationModuleResult[];

  // ---- All Test Results ----
  test_results: AttackTestResult[];

  // ---- 17 Actionable Findings ----
  findings: SimulationFinding[];

  // ---- 6-Phase Roadmap ----
  roadmap: RoadmapPhase[];

  // ---- Disclaimer ----
  disclaimer: { es: string; en: string };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// API Request / Response Types
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface StartSimulationRequest {
  zone_id: string;
  api_token: string;
  account_id: string;
  /** Target domain to probe (resolved from zone info) */
  domain?: string;
}

export interface StartSimulationResponse {
  success: boolean;
  report_id: string;
  credits_charged: number;
  report: SimulationReport;
}

export interface SimulationHistoryItem {
  id: string;
  zone_name: string;
  zone_id: string;
  overall_score: number;
  overall_grade: string;
  risk_level: string;
  total_tests: number;
  bypassed: number;
  findings_count: number;
  duration_ms: number;
  credits_charged: number;
  created_at: string;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Helper: Grade from score
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export function gradeFromScore(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function riskFromScore(score: number): SimulationReport['risk_level'] {
  if (score >= 85) return 'low';
  if (score >= 70) return 'medium';
  if (score >= 50) return 'high';
  return 'critical';
}
