/**
 * Anga Security \u2014 Attack Simulator: 17 Actionable Findings Generator
 *
 * Analyzes Phase 1 intelligence + Phase 2 test results to produce
 * 17 specific findings (SIM-001 through SIM-017), each with:
 *   - Severity assessment based on how many tests bypassed
 *   - Evidence linking to specific test IDs
 *   - Step-by-step remediation
 *   - Roadmap phase placement
 *
 * Findings are only emitted if there is evidence (bypassed tests or
 * intelligence gaps). Each finding has a minimum threshold to be
 * considered active. If all tests for a finding passed, the finding
 * is still emitted with severity=info as a "verified secure" notice.
 */

import type {
  AttackTestResult,
  SecurityIntelligence,
  SimulationFinding,
  FindingSeverity,
  AttackModuleId,
} from '../../types/simulation';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Helpers
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function getTestsForFinding(
  findingId: string,
  tests: AttackTestResult[],
): AttackTestResult[] {
  return tests.filter((t) => t.linked_finding_id === findingId);
}

function countBypassed(tests: AttackTestResult[]): number {
  return tests.filter((t) => t.outcome === 'bypassed').length;
}

function severityFromBypassed(bypassed: number, total: number): FindingSeverity {
  if (total === 0) return 'info';
  const ratio = bypassed / total;
  if (ratio >= 0.75) return 'critical';
  if (ratio >= 0.5) return 'high';
  if (ratio >= 0.25) return 'medium';
  if (bypassed > 0) return 'low';
  return 'info';
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Main Export
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export function generateFindings(
  tests: AttackTestResult[],
  intel: SecurityIntelligence,
): SimulationFinding[] {
  const findings: SimulationFinding[] = [];

  // SIM-001: WAF Managed Ruleset deployment gaps
  findings.push(buildSIM001(tests, intel));

  // SIM-002: OWASP paranoia/threshold misconfiguration
  findings.push(buildSIM002(tests, intel));

  // SIM-003: WAF Attack Score not enabled
  findings.push(buildSIM003(tests, intel));

  // SIM-004: Custom rule expression bypass (encoding/casing)
  findings.push(buildSIM004(tests, intel));

  // SIM-005: Missing rate limiting on sensitive endpoints
  findings.push(buildSIM005(tests, intel));

  // SIM-006: Rate limit threshold too permissive
  findings.push(buildSIM006(tests, intel));

  // SIM-007: Bot Management not enabled / SBFM gaps
  findings.push(buildSIM007(tests, intel));

  // SIM-008: JavaScript Detections not active
  findings.push(buildSIM008(tests, intel));

  // SIM-009: X-Forwarded-For trust vulnerability
  findings.push(buildSIM009(tests, intel));

  // SIM-010: HTTP\u2192HTTPS redirect gap or HSTS missing
  findings.push(buildSIM010(tests, intel));

  // SIM-011: TLS 1.0/1.1 still accepted
  findings.push(buildSIM011(tests, intel));

  // SIM-012: Cache Deception Armor not enabled
  findings.push(buildSIM012(tests, intel));

  // SIM-013: Cache key misconfiguration
  findings.push(buildSIM013(tests, intel));

  // SIM-014: API endpoints lack schema validation
  findings.push(buildSIM014(tests, intel));

  // SIM-015: Leaked credentials detection not enabled
  findings.push(buildSIM015(tests, intel));

  // SIM-016: Challenge type suboptimal
  findings.push(buildSIM016(tests, intel));

  // SIM-017: Security feature coverage gap (cross-module)
  findings.push(buildSIM017(tests, intel));

  return findings;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Individual Finding Builders
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function buildSIM001(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-001', tests);
  const bypassed = countBypassed(evidence);
  const baseSeverity = severityFromBypassed(bypassed, evidence.length);
  // Elevate severity if managed rules are completely disabled
  const severity: FindingSeverity = !intel.waf.cf_managed_ruleset && baseSeverity === 'info' ? 'high' : baseSeverity;

  return {
    finding_id: 'SIM-001',
    severity,
    module: 'waf_bypass' as AttackModuleId,
    title: {
      es: 'Brechas en el despliegue del WAF Managed Ruleset',
      en: 'WAF Managed Ruleset deployment gaps',
    },
    description: {
      es: `El Cloudflare Managed Ruleset ${intel.waf.cf_managed_ruleset ? 'est\u00e1 habilitado pero' : 'NO est\u00e1 habilitado.'} ${bypassed} de ${evidence.length} pruebas de ataques cl\u00e1sicos (SQLi, XSS) lograron pasar sin ser detectadas.`,
      en: `The Cloudflare Managed Ruleset ${intel.waf.cf_managed_ruleset ? 'is enabled but' : 'is NOT enabled.'} ${bypassed} of ${evidence.length} classic attack tests (SQLi, XSS) passed through undetected.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: intel.waf.cf_managed_ruleset
      ? {
          // Managed Ruleset IS enabled — recommend tuning, not enabling
          summary: {
            es: 'El Cloudflare Managed Ruleset está habilitado pero algunos ataques lograron pasar. Revisar la configuración de reglas individuales y asegurar que estén en modo "Block".',
            en: 'The Cloudflare Managed Ruleset is enabled but some attacks got through. Review individual rule configuration and ensure they are set to "Block" mode.',
          },
          steps: [
            { order: 1, action: { es: 'Ir a Security > WAF > Managed rules', en: 'Go to Security > WAF > Managed rules' }, where: 'Cloudflare Dashboard', detail: { es: 'Navegar a la sección de reglas WAF administradas.', en: 'Navigate to the WAF managed rules section.' } },
            { order: 2, action: { es: 'Revisar reglas individuales del Managed Ruleset', en: 'Review individual Managed Ruleset rules' }, where: 'Managed rules > Configure', detail: { es: 'Verificar que las reglas para SQLi y XSS estén en modo "Block" y no "Log" o "Disabled".', en: 'Verify that SQLi and XSS rules are set to "Block" not "Log" or "Disabled".' } },
            { order: 3, action: { es: 'Verificar que no haya overrides deshabilitando reglas', en: 'Check for overrides disabling rules' }, where: 'Managed rules > Configure', detail: { es: 'Buscar reglas con status "Log" o "Disabled" que podrían permitir ataques.', en: 'Look for rules with "Log" or "Disabled" status that could allow attacks through.' } },
            { order: 4, action: { es: 'Considerar habilitar OWASP Core Ruleset como capa adicional', en: 'Consider enabling OWASP Core Ruleset as additional layer' }, where: 'Security > WAF > Managed rules', detail: { es: 'OWASP CRS complementa el Managed Ruleset con detección por scoring de anomalías.', en: 'OWASP CRS complements the Managed Ruleset with anomaly scoring detection.' } },
          ],
          cf_product: 'WAF Managed Rules',
          dashboard_path: 'Security > WAF > Managed rules',
          docs_url: 'https://developers.cloudflare.com/waf/managed-rules/',
          effort: 'quick_fix',
          risk_if_ignored: {
            es: 'Algunos ataques SQLi y XSS están evadiendo las reglas actuales y pueden llegar al origen.',
            en: 'Some SQLi and XSS attacks are evading current rules and can reach the origin.',
          },
        }
      : {
          // Managed Ruleset NOT enabled — recommend enabling
          summary: {
            es: 'Habilitar el Cloudflare Managed Ruleset para bloquear ataques conocidos como SQLi y XSS.',
            en: 'Enable the Cloudflare Managed Ruleset to block known attacks like SQLi and XSS.',
          },
          steps: [
            { order: 1, action: { es: 'Ir a Security > WAF > Managed rules', en: 'Go to Security > WAF > Managed rules' }, where: 'Cloudflare Dashboard', detail: { es: 'Navegar a la sección de reglas WAF administradas.', en: 'Navigate to the WAF managed rules section.' } },
            { order: 2, action: { es: 'Habilitar "Cloudflare Managed Ruleset"', en: 'Enable "Cloudflare Managed Ruleset"' }, where: 'Managed rules', detail: { es: 'Activar el ruleset principal de Cloudflare que protege contra OWASP Top 10.', en: 'Activate the main Cloudflare ruleset protecting against OWASP Top 10.' } },
            { order: 3, action: { es: 'Revisar reglas individuales', en: 'Review individual rules' }, where: 'Managed rules > Configure', detail: { es: 'Verificar que las reglas para SQLi y XSS estén en modo "Block" y no "Log".', en: 'Verify that SQLi and XSS rules are set to "Block" not "Log".' } },
          ],
          cf_product: 'WAF Managed Rules',
          dashboard_path: 'Security > WAF > Managed rules',
          docs_url: 'https://developers.cloudflare.com/waf/managed-rules/',
          effort: 'quick_fix',
          risk_if_ignored: {
            es: 'Ataques SQLi y XSS conocidos pueden llegar al origen sin ser detectados.',
            en: 'Known SQLi and XSS attacks can reach the origin undetected.',
          },
        },
    roadmap_phase: 1,
  };
}

function buildSIM002(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-002', tests);
  const bypassed = countBypassed(evidence);
  const severity = !intel.waf.owasp_enabled ? 'high' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-002',
    severity,
    module: 'waf_bypass',
    title: {
      es: 'Configuraci\u00f3n de OWASP Paranoia/Threshold incorrecta',
      en: 'OWASP paranoia/threshold misconfiguration',
    },
    description: {
      es: `OWASP Core Ruleset: ${intel.waf.owasp_enabled ? `Habilitado (Paranoia: ${intel.waf.owasp_paranoia_level || '?'}, Threshold: ${intel.waf.owasp_score_threshold || '?'})` : 'NO habilitado'}. ${bypassed} pruebas con encoding avanzado lograron pasar.`,
      en: `OWASP Core Ruleset: ${intel.waf.owasp_enabled ? `Enabled (Paranoia: ${intel.waf.owasp_paranoia_level || '?'}, Threshold: ${intel.waf.owasp_score_threshold || '?'})` : 'NOT enabled'}. ${bypassed} tests with advanced encoding bypassed.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Incrementar el OWASP Paranoia Level a PL2 y ajustar el threshold a Medium.',
        en: 'Increase OWASP Paranoia Level to PL2 and adjust threshold to Medium.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > WAF > Managed rules', en: 'Go to Security > WAF > Managed rules' }, where: 'Dashboard', detail: { es: 'Localizar "Cloudflare OWASP Core Ruleset".', en: 'Locate "Cloudflare OWASP Core Ruleset".' } },
        { order: 2, action: { es: 'Configurar Paranoia Level a PL2', en: 'Set Paranoia Level to PL2' }, where: 'OWASP Config', detail: { es: 'PL2 detecta encoding avanzado y variaciones de payloads.', en: 'PL2 detects advanced encoding and payload variations.' } },
        { order: 3, action: { es: 'Establecer Anomaly Score Threshold en Medium (40)', en: 'Set Anomaly Score Threshold to Medium (40)' }, where: 'OWASP Config', detail: { es: 'Medium bloquea ataques con 2+ reglas coincidentes.', en: 'Medium blocks attacks matching 2+ rules.' } },
      ],
      cf_product: 'WAF OWASP Core Ruleset',
      dashboard_path: 'Security > WAF > Managed rules > OWASP',
      docs_url: 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Ataques con encoding alternativo o payload variations pueden evadir la detecci\u00f3n.',
        en: 'Attacks using alternative encoding or payload variations can evade detection.',
      },
    },
    roadmap_phase: 2,
  };
}

function buildSIM003(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-003', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = !intel.waf.attack_score_rules ? 'medium' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-003',
    severity,
    module: 'waf_bypass',
    title: {
      es: 'WAF Attack Score no habilitado',
      en: 'WAF Attack Score not enabled',
    },
    description: {
      es: `WAF Attack Score (ML): ${intel.waf.attack_score_rules ? 'Reglas activas' : 'Sin reglas activas'}. Esta funci\u00f3n usa machine learning para detectar variaciones de ataques no cubiertas por reglas est\u00e1ticas.`,
      en: `WAF Attack Score (ML): ${intel.waf.attack_score_rules ? 'Active rules' : 'No active rules'}. This feature uses machine learning to detect attack variations not covered by static rules.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Crear reglas custom usando cf.waf.score para bloquear payloads con score bajo.',
        en: 'Create custom rules using cf.waf.score to block payloads with low attack score.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > WAF > Custom rules', en: 'Go to Security > WAF > Custom rules' }, where: 'Dashboard', detail: { es: 'Crear nueva regla custom.', en: 'Create new custom rule.' } },
        { order: 2, action: { es: 'Usar expresi\u00f3n: cf.waf.score lt 40', en: 'Use expression: cf.waf.score lt 40' }, where: 'Rule builder', detail: { es: 'Bloquear requests con WAF attack score menor a 40 (sospechoso).', en: 'Block requests with WAF attack score below 40 (suspicious).' } },
        { order: 3, action: { es: 'Configurar acci\u00f3n: Managed Challenge', en: 'Set action: Managed Challenge' }, where: 'Rule action', detail: { es: 'Managed Challenge es menos agresivo que Block para minimizar falsos positivos.', en: 'Managed Challenge is less aggressive than Block to minimize false positives.' } },
      ],
      cf_product: 'WAF Attack Score',
      dashboard_path: 'Security > WAF > Custom rules',
      docs_url: 'https://developers.cloudflare.com/waf/detections/attack-score/',
      effort: 'moderate',
      risk_if_ignored: {
        es: 'Variaciones novedosas de ataques pueden evadir reglas est\u00e1ticas del WAF.',
        en: 'Novel attack variations can evade static WAF rules.',
      },
    },
    roadmap_phase: 2,
  };
}

function buildSIM004(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-004', tests);
  const bypassed = countBypassed(evidence);
  const severity = severityFromBypassed(bypassed, Math.max(evidence.length, 1));

  return {
    finding_id: 'SIM-004',
    severity: bypassed > 0 ? severity : (intel.custom_rules.total === 0 ? 'medium' : 'info'),
    module: 'custom_rule_bypass',
    title: {
      es: 'Bypass de reglas custom por encoding/casing',
      en: 'Custom rule expression bypass (encoding/casing)',
    },
    description: {
      es: `${intel.custom_rules.total} reglas custom encontradas. ${bypassed} pruebas con variaciones de may\u00fasculas/encoding lograron evadir las reglas.`,
      en: `${intel.custom_rules.total} custom rules found. ${bypassed} tests with casing/encoding variations bypassed the rules.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Usar funciones lower() en expresiones y a\u00f1adir cobertura para URL encoding.',
        en: 'Use lower() functions in expressions and add URL encoding coverage.',
      },
      steps: [
        { order: 1, action: { es: 'Revisar expresiones de reglas custom', en: 'Review custom rule expressions' }, where: 'Security > WAF > Custom rules', detail: { es: 'Identificar reglas que comparan strings sin normalizar.', en: 'Identify rules comparing strings without normalization.' } },
        { order: 2, action: { es: 'Aplicar lower() a campos de texto', en: 'Apply lower() to text fields' }, where: 'Rule expressions', detail: { es: 'Cambiar contains(http.request.uri.path, "/admin") a contains(lower(http.request.uri.path), "/admin").', en: 'Change contains(http.request.uri.path, "/admin") to contains(lower(http.request.uri.path), "/admin").' } },
        { order: 3, action: { es: 'Agregar url_decode() para encoded paths', en: 'Add url_decode() for encoded paths' }, where: 'Rule expressions', detail: { es: 'Prevenir bypass por URL encoding doble.', en: 'Prevent bypass via double URL encoding.' } },
      ],
      cf_product: 'Custom Firewall Rules',
      dashboard_path: 'Security > WAF > Custom rules',
      docs_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      effort: 'moderate',
      risk_if_ignored: {
        es: 'Atacantes pueden evadir reglas custom con simples cambios de may\u00fasculas o encoding.',
        en: 'Attackers can evade custom rules with simple casing or encoding changes.',
      },
    },
    roadmap_phase: 1,
  };
}

function buildSIM005(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-005', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = intel.rate_limits.total === 0 ? 'high' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-005',
    severity,
    module: 'rate_limit',
    title: {
      es: 'Falta rate limiting en endpoints sensibles',
      en: 'Missing rate limiting on sensitive endpoints',
    },
    description: {
      es: `${intel.rate_limits.total} regla(s) de rate limiting configuradas. ${bypassed} r\u00e1fagas de solicitudes no activaron ning\u00fan l\u00edmite.`,
      en: `${intel.rate_limits.total} rate limiting rule(s) configured. ${bypassed} request bursts did not trigger any limit.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Configurar rate limiting rules para endpoints de login, API y formularios.',
        en: 'Configure rate limiting rules for login, API, and form endpoints.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > WAF > Rate limiting rules', en: 'Go to Security > WAF > Rate limiting rules' }, where: 'Dashboard', detail: { es: 'Crear nuevas reglas de rate limiting.', en: 'Create new rate limiting rules.' } },
        { order: 2, action: { es: 'Proteger /login y /api/* con 10 req/10s', en: 'Protect /login and /api/* with 10 req/10s' }, where: 'Rule config', detail: { es: 'L\u00edmite conservador para prevenir brute force.', en: 'Conservative limit to prevent brute force.' } },
        { order: 3, action: { es: 'Habilitar respuesta personalizada (429)', en: 'Enable custom response (429)' }, where: 'Rule action', detail: { es: 'Responder con 429 Too Many Requests y un Retry-After header.', en: 'Respond with 429 Too Many Requests and a Retry-After header.' } },
      ],
      cf_product: 'Rate Limiting Rules',
      dashboard_path: 'Security > WAF > Rate limiting rules',
      docs_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Ataques de fuerza bruta y abuso de API sin restricci\u00f3n.',
        en: 'Brute force attacks and API abuse without restriction.',
      },
    },
    roadmap_phase: 2,
  };
}

function buildSIM006(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-006', tests);
  const bypassed = countBypassed(evidence);
  const hasPermissiveRules = intel.rate_limits.rules.some((r) => r.requests_per_period > 100);
  const severity: FindingSeverity = hasPermissiveRules ? 'medium' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-006',
    severity,
    module: 'rate_limit',
    title: {
      es: 'Umbral de rate limiting demasiado permisivo',
      en: 'Rate limit threshold too permissive',
    },
    description: {
      es: `${intel.rate_limits.rules.filter((r) => r.requests_per_period > 100).length} regla(s) con umbral >100 req/periodo. R\u00e1fagas de ${bypassed > 0 ? '10-20' : '0'} requests pasaron sin l\u00edmite.`,
      en: `${intel.rate_limits.rules.filter((r) => r.requests_per_period > 100).length} rule(s) with threshold >100 req/period. Bursts of ${bypassed > 0 ? '10-20' : '0'} requests passed without limit.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Reducir umbrales de rate limiting a valores m\u00e1s conservadores por endpoint.',
        en: 'Reduce rate limiting thresholds to more conservative values per endpoint.',
      },
      steps: [
        { order: 1, action: { es: 'Revisar umbrales actuales', en: 'Review current thresholds' }, where: 'Security > WAF > Rate limiting', detail: { es: 'Identificar reglas con l\u00edmites altos (>100 req/min).', en: 'Identify rules with high limits (>100 req/min).' } },
        { order: 2, action: { es: 'Ajustar a 30-50 req/min para endpoints p\u00fablicos', en: 'Adjust to 30-50 req/min for public endpoints' }, where: 'Rule config', detail: { es: 'Bajar gradualmente y monitorear falsos positivos.', en: 'Lower gradually and monitor false positives.' } },
        { order: 3, action: { es: 'Implementar l\u00edmites escalonados', en: 'Implement tiered limits' }, where: 'Multiple rules', detail: { es: 'L\u00edmites m\u00e1s estrictos para /login y /api que para p\u00e1ginas est\u00e1ticas.', en: 'Stricter limits for /login and /api than for static pages.' } },
      ],
      cf_product: 'Rate Limiting Rules',
      dashboard_path: 'Security > WAF > Rate limiting rules',
      docs_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      effort: 'moderate',
      risk_if_ignored: {
        es: 'Los l\u00edmites permisivos permiten ataques de enumeraci\u00f3n y scraping lento.',
        en: 'Permissive limits allow enumeration attacks and slow scraping.',
      },
    },
    roadmap_phase: 3,
  };
}

function buildSIM007(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-007', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = !intel.bot_management.enabled && !intel.bot_management.sbfm_enabled ? 'high' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-007',
    severity,
    module: 'bot_evasion',
    title: {
      es: 'Bot Management no habilitado / SBFM con brechas',
      en: 'Bot Management not enabled / SBFM gaps',
    },
    description: {
      es: `Bot Management: ${intel.bot_management.enabled ? 'Enterprise BM activo' : intel.bot_management.sbfm_enabled ? 'SBFM activo' : 'NO activo'}. ${bypassed} pruebas de evasi\u00f3n de bots lograron pasar.`,
      en: `Bot Management: ${intel.bot_management.enabled ? 'Enterprise BM active' : intel.bot_management.sbfm_enabled ? 'SBFM active' : 'NOT active'}. ${bypassed} bot evasion tests bypassed.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Habilitar Super Bot Fight Mode (Free/Pro/Biz) o Bot Management (Enterprise).',
        en: 'Enable Super Bot Fight Mode (Free/Pro/Biz) or Bot Management (Enterprise).',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > Bots', en: 'Go to Security > Bots' }, where: 'Dashboard', detail: { es: 'Configurar la protecci\u00f3n contra bots.', en: 'Configure bot protection.' } },
        { order: 2, action: { es: 'Activar "Definitely automated" > Block', en: 'Enable "Definitely automated" > Block' }, where: 'Bot config', detail: { es: 'Bloquear bots definitivamente automatizados.', en: 'Block definitely automated bots.' } },
        { order: 3, action: { es: 'Activar "Likely automated" > Managed Challenge', en: 'Enable "Likely automated" > Managed Challenge' }, where: 'Bot config', detail: { es: 'Desafiar bots probablemente automatizados.', en: 'Challenge likely automated bots.' } },
      ],
      cf_product: 'Bot Management',
      dashboard_path: 'Security > Bots',
      docs_url: 'https://developers.cloudflare.com/bots/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Bots automatizados pueden hacer scraping, credential stuffing y abuso de API sin detecci\u00f3n.',
        en: 'Automated bots can perform scraping, credential stuffing, and API abuse undetected.',
      },
    },
    roadmap_phase: 3,
  };
}

function buildSIM008(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-008', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = !intel.bot_management.js_detection_enabled ? 'medium' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-008',
    severity,
    module: 'bot_evasion',
    title: {
      es: 'JavaScript Detections no activas',
      en: 'JavaScript Detections not active',
    },
    description: {
      es: `JS Detection: ${intel.bot_management.js_detection_enabled ? 'Activo' : 'NO activo'}. Sin JS Detection, los bots headless no se distinguen de humanos.`,
      en: `JS Detection: ${intel.bot_management.js_detection_enabled ? 'Active' : 'NOT active'}. Without JS Detection, headless bots are indistinguishable from humans.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Habilitar JavaScript Detections en la configuraci\u00f3n de Bot Management.',
        en: 'Enable JavaScript Detections in Bot Management configuration.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > Bots > Configure', en: 'Go to Security > Bots > Configure' }, where: 'Dashboard', detail: { es: 'Acceder a configuraci\u00f3n avanzada de bots.', en: 'Access advanced bot configuration.' } },
        { order: 2, action: { es: 'Habilitar "JavaScript Detections"', en: 'Enable "JavaScript Detections"' }, where: 'Bot config', detail: { es: 'Esto inyecta un script ligero para verificar si el cliente ejecuta JS.', en: 'This injects a lightweight script to verify if the client executes JS.' } },
      ],
      cf_product: 'Bot Management',
      dashboard_path: 'Security > Bots > Configure',
      docs_url: 'https://developers.cloudflare.com/bots/reference/javascript-detections/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Headless browsers y herramientas de automatizaci\u00f3n avanzadas pasan como humanos.',
        en: 'Headless browsers and advanced automation tools pass as humans.',
      },
    },
    roadmap_phase: 2,
  };
}

function buildSIM009(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-009', tests);
  const bypassed = countBypassed(evidence);
  const severity = severityFromBypassed(bypassed, Math.max(evidence.length, 1));

  return {
    finding_id: 'SIM-009',
    severity: bypassed > 0 ? 'critical' : severity,
    module: 'ip_geo_access',
    title: {
      es: 'Vulnerabilidad de confianza en X-Forwarded-For',
      en: 'X-Forwarded-For trust vulnerability',
    },
    description: {
      es: `${bypassed} pruebas de spoofing de X-Forwarded-For lograron pasar. Si las reglas conf\u00edan en esta cabecera, un atacante puede falsificar su IP.`,
      en: `${bypassed} X-Forwarded-For spoofing tests bypassed. If rules trust this header, an attacker can spoof their IP.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Usar ip.src en lugar de http.request.headers["x-forwarded-for"] en expresiones de reglas.',
        en: 'Use ip.src instead of http.request.headers["x-forwarded-for"] in rule expressions.',
      },
      steps: [
        { order: 1, action: { es: 'Auditar reglas que usen X-Forwarded-For', en: 'Audit rules using X-Forwarded-For' }, where: 'Security > WAF > Custom rules', detail: { es: 'Buscar expresiones que referencien headers XFF.', en: 'Search for expressions referencing XFF headers.' } },
        { order: 2, action: { es: 'Reemplazar con ip.src', en: 'Replace with ip.src' }, where: 'Rule expressions', detail: { es: 'ip.src es la IP real del visitante seg\u00fan Cloudflare, no spoofeable.', en: 'ip.src is the real visitor IP per Cloudflare, not spoofable.' } },
        { order: 3, action: { es: 'Habilitar "Pseudo IPv4" si necesario', en: 'Enable "Pseudo IPv4" if needed' }, where: 'Network settings', detail: { es: 'Para compatibilidad con clientes IPv6-only.', en: 'For compatibility with IPv6-only clients.' } },
      ],
      cf_product: 'Custom Firewall Rules',
      dashboard_path: 'Security > WAF > Custom rules',
      docs_url: 'https://developers.cloudflare.com/ruleset-engine/rules-language/fields/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Atacantes pueden evadir listas de bloqueo de IP falsificando la cabecera X-Forwarded-For.',
        en: 'Attackers can bypass IP blocklists by spoofing the X-Forwarded-For header.',
      },
    },
    roadmap_phase: 1,
  };
}

function buildSIM010(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-010', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = (!intel.ssl_tls.always_use_https || !intel.ssl_tls.hsts_enabled) ? 'high' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-010',
    severity,
    module: 'ssl_tls',
    title: {
      es: 'Falta redirecci\u00f3n HTTP\u2192HTTPS o HSTS',
      en: 'HTTP\u2192HTTPS redirect gap or HSTS missing',
    },
    description: {
      es: `Always Use HTTPS: ${intel.ssl_tls.always_use_https ? 'S\u00ed' : 'NO'}. HSTS: ${intel.ssl_tls.hsts_enabled ? `S\u00ed (max-age: ${intel.ssl_tls.hsts_max_age}s)` : 'NO'}.`,
      en: `Always Use HTTPS: ${intel.ssl_tls.always_use_https ? 'Yes' : 'NO'}. HSTS: ${intel.ssl_tls.hsts_enabled ? `Yes (max-age: ${intel.ssl_tls.hsts_max_age}s)` : 'NO'}.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Habilitar "Always Use HTTPS" y configurar HSTS con max-age >= 31536000.',
        en: 'Enable "Always Use HTTPS" and configure HSTS with max-age >= 31536000.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar "Always Use HTTPS"', en: 'Enable "Always Use HTTPS"' }, where: 'SSL/TLS > Edge Certificates', detail: { es: 'Redirigir autom\u00e1ticamente todo el tr\u00e1fico HTTP a HTTPS.', en: 'Automatically redirect all HTTP traffic to HTTPS.' } },
        { order: 2, action: { es: 'Habilitar HSTS', en: 'Enable HSTS' }, where: 'SSL/TLS > Edge Certificates', detail: { es: 'Establecer max-age a 31536000 (1 a\u00f1o), includeSubDomains, preload.', en: 'Set max-age to 31536000 (1 year), includeSubDomains, preload.' } },
      ],
      cf_product: 'SSL/TLS',
      dashboard_path: 'SSL/TLS > Edge Certificates',
      docs_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Tr\u00e1fico HTTP sin cifrar expone cookies, credenciales y datos sensibles.',
        en: 'Unencrypted HTTP traffic exposes cookies, credentials, and sensitive data.',
      },
    },
    roadmap_phase: 2,
  };
}

function buildSIM011(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-011', tests);
  const bypassed = countBypassed(evidence);
  const isOldTLS = !['1.2', '1.3'].includes(intel.ssl_tls.min_tls_version);
  const severity: FindingSeverity = isOldTLS ? 'high' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-011',
    severity,
    module: 'ssl_tls',
    title: {
      es: 'TLS 1.0/1.1 a\u00fan aceptado',
      en: 'TLS 1.0/1.1 still accepted',
    },
    description: {
      es: `Min TLS Version: ${intel.ssl_tls.min_tls_version}. TLS 1.3: ${intel.ssl_tls.tls_1_3}. ${isOldTLS ? 'Versiones antiguas de TLS son vulnerables a ataques BEAST/POODLE.' : 'Configuraci\u00f3n correcta.'}`,
      en: `Min TLS Version: ${intel.ssl_tls.min_tls_version}. TLS 1.3: ${intel.ssl_tls.tls_1_3}. ${isOldTLS ? 'Old TLS versions are vulnerable to BEAST/POODLE attacks.' : 'Configuration is correct.'}`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Establecer TLS m\u00ednimo en 1.2 y habilitar TLS 1.3.',
        en: 'Set minimum TLS to 1.2 and enable TLS 1.3.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a SSL/TLS > Edge Certificates', en: 'Go to SSL/TLS > Edge Certificates' }, where: 'Dashboard', detail: { es: 'Localizar "Minimum TLS Version".', en: 'Locate "Minimum TLS Version".' } },
        { order: 2, action: { es: 'Establecer m\u00ednimo en TLS 1.2', en: 'Set minimum to TLS 1.2' }, where: 'TLS config', detail: { es: 'Deshabilita TLS 1.0 y 1.1 en el edge.', en: 'Disables TLS 1.0 and 1.1 at the edge.' } },
        { order: 3, action: { es: 'Habilitar TLS 1.3', en: 'Enable TLS 1.3' }, where: 'TLS config', detail: { es: 'TLS 1.3 ofrece mejor seguridad y rendimiento.', en: 'TLS 1.3 offers better security and performance.' } },
      ],
      cf_product: 'SSL/TLS',
      dashboard_path: 'SSL/TLS > Edge Certificates',
      docs_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Protocolos TLS antiguos permiten ataques de downgrade y descifrado de tr\u00e1fico.',
        en: 'Old TLS protocols allow downgrade attacks and traffic decryption.',
      },
    },
    roadmap_phase: 3,
  };
}

function buildSIM012(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-012', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = !intel.security.cache_deception_armor ? 'medium' : severityFromBypassed(bypassed, evidence.length);

  return {
    finding_id: 'SIM-012',
    severity,
    module: 'cache_poisoning',
    title: {
      es: 'Cache Deception Armor no habilitado',
      en: 'Cache Deception Armor not enabled',
    },
    description: {
      es: `Cache Deception Armor: ${intel.security.cache_deception_armor ? 'Habilitado' : 'NO habilitado'}. Sin esta protecci\u00f3n, ataques de web cache deception pueden exponer datos de usuarios.`,
      en: `Cache Deception Armor: ${intel.security.cache_deception_armor ? 'Enabled' : 'NOT enabled'}. Without this protection, web cache deception attacks can expose user data.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Habilitar Cache Deception Armor en la configuraci\u00f3n de caching.',
        en: 'Enable Cache Deception Armor in caching configuration.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Caching > Configuration', en: 'Go to Caching > Configuration' }, where: 'Dashboard', detail: { es: 'Localizar "Cache Deception Armor".', en: 'Locate "Cache Deception Armor".' } },
        { order: 2, action: { es: 'Habilitar Cache Deception Armor', en: 'Enable Cache Deception Armor' }, where: 'Caching config', detail: { es: 'Protege contra ataques que intentan cachear respuestas din\u00e1micas personalizadas.', en: 'Protects against attacks trying to cache personalized dynamic responses.' } },
      ],
      cf_product: 'Cache Deception Armor',
      dashboard_path: 'Caching > Configuration',
      docs_url: 'https://developers.cloudflare.com/cache/about/cache-deception-armor/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Datos personalizados de usuarios pueden quedar cacheados y accesibles p\u00fablicamente.',
        en: 'Personalized user data can be cached and publicly accessible.',
      },
    },
    roadmap_phase: 3,
  };
}

function buildSIM013(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-013', tests);
  const bypassed = countBypassed(evidence);
  const severity = severityFromBypassed(bypassed, Math.max(evidence.length, 1));

  return {
    finding_id: 'SIM-013',
    severity,
    module: 'cache_poisoning',
    title: {
      es: 'Misconfiguraci\u00f3n de cache key',
      en: 'Cache key misconfiguration',
    },
    description: {
      es: `${bypassed} pruebas de variaci\u00f3n de Host header y par\u00e1metros de cache-busting generaron respuestas inconsistentes, indicando posible cache poisoning.`,
      en: `${bypassed} Host header variation and cache-busting parameter tests generated inconsistent responses, indicating possible cache poisoning.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Configurar cache keys estrictas excluyendo headers manipulables.',
        en: 'Configure strict cache keys excluding manipulable headers.',
      },
      steps: [
        { order: 1, action: { es: 'Revisar Cache Rules', en: 'Review Cache Rules' }, where: 'Caching > Cache Rules', detail: { es: 'Verificar que el Host header no forma parte del cache key sin validaci\u00f3n.', en: 'Verify Host header is not part of cache key without validation.' } },
        { order: 2, action: { es: 'Crear Cache Rules restrictivas', en: 'Create restrictive Cache Rules' }, where: 'Caching > Cache Rules', detail: { es: 'Definir qu\u00e9 query params y headers incluir en la cache key.', en: 'Define which query params and headers to include in cache key.' } },
      ],
      cf_product: 'Cache Rules',
      dashboard_path: 'Caching > Cache Rules',
      docs_url: 'https://developers.cloudflare.com/cache/how-to/cache-rules/',
      effort: 'moderate',
      risk_if_ignored: {
        es: 'Cache poisoning puede servir contenido malicioso a todos los visitantes.',
        en: 'Cache poisoning can serve malicious content to all visitors.',
      },
    },
    roadmap_phase: 4,
  };
}

function buildSIM014(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-014', tests);
  const bypassed = countBypassed(evidence);
  const severity = severityFromBypassed(bypassed, Math.max(evidence.length, 1));

  return {
    finding_id: 'SIM-014',
    severity,
    module: 'api_security',
    title: {
      es: 'Endpoints API sin validaci\u00f3n de schema',
      en: 'API endpoints lack schema validation',
    },
    description: {
      es: `${bypassed} pruebas con payloads maliciosos en endpoints API pasaron sin detecci\u00f3n. ${intel.api_paths.length} ruta(s) API identificadas.`,
      en: `${bypassed} tests with malicious payloads on API endpoints passed undetected. ${intel.api_paths.length} API path(s) identified.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Implementar API Shield con Schema Validation para validar requests entrantes.',
        en: 'Implement API Shield with Schema Validation to validate incoming requests.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > API Shield', en: 'Go to Security > API Shield' }, where: 'Dashboard', detail: { es: 'Configurar protecci\u00f3n de API endpoints.', en: 'Configure API endpoint protection.' } },
        { order: 2, action: { es: 'Subir OpenAPI Schema', en: 'Upload OpenAPI Schema' }, where: 'API Shield > Schema Validation', detail: { es: 'Cloudflare validar\u00e1 todos los requests contra el schema.', en: 'Cloudflare will validate all requests against the schema.' } },
        { order: 3, action: { es: 'Habilitar Sequence Mitigation', en: 'Enable Sequence Mitigation' }, where: 'API Shield', detail: { es: 'Detectar y bloquear secuencias de API an\u00f3malas.', en: 'Detect and block anomalous API sequences.' } },
      ],
      cf_product: 'API Shield',
      dashboard_path: 'Security > API Shield',
      docs_url: 'https://developers.cloudflare.com/api-shield/',
      effort: 'complex',
      risk_if_ignored: {
        es: 'Payloads maliciosos y requests malformados llegan directamente a la API del origen.',
        en: 'Malicious payloads and malformed requests reach the origin API directly.',
      },
    },
    roadmap_phase: 4,
  };
}

function buildSIM015(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-015', tests);
  const bypassed = countBypassed(evidence);
  const severity: FindingSeverity = !intel.security.leaked_credentials_enabled ? 'medium' : 'info';

  return {
    finding_id: 'SIM-015',
    severity,
    module: 'api_security',
    title: {
      es: 'Detecci\u00f3n de credenciales filtradas no habilitada',
      en: 'Leaked credentials detection not enabled',
    },
    description: {
      es: `Detecci\u00f3n de credenciales filtradas: ${intel.security.leaked_credentials_enabled ? 'Habilitada' : 'NO habilitada'}. Esta funci\u00f3n alerta cuando se usan credenciales comprometidas en login.`,
      en: `Leaked credentials detection: ${intel.security.leaked_credentials_enabled ? 'Enabled' : 'NOT enabled'}. This feature alerts when compromised credentials are used for login.`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Habilitar Leaked Credentials Detection en las reglas WAF.',
        en: 'Enable Leaked Credentials Detection in WAF rules.',
      },
      steps: [
        { order: 1, action: { es: 'Ir a Security > WAF > Managed rules', en: 'Go to Security > WAF > Managed rules' }, where: 'Dashboard', detail: { es: 'Localizar "Cloudflare Leaked Credentials Check".', en: 'Locate "Cloudflare Leaked Credentials Check".' } },
        { order: 2, action: { es: 'Habilitar el ruleset', en: 'Enable the ruleset' }, where: 'Managed rules', detail: { es: 'Activa la comprobaci\u00f3n autom\u00e1tica de credenciales filtradas.', en: 'Activates automatic leaked credentials checking.' } },
        { order: 3, action: { es: 'Configurar acci\u00f3n para credenciales filtradas', en: 'Configure action for leaked credentials' }, where: 'Custom rule', detail: { es: 'Crear regla custom con cf.waf.credential_check.username_and_password_leaked.', en: 'Create custom rule using cf.waf.credential_check.username_and_password_leaked.' } },
      ],
      cf_product: 'WAF Leaked Credentials',
      dashboard_path: 'Security > WAF > Managed rules',
      docs_url: 'https://developers.cloudflare.com/waf/managed-rules/check-for-exposed-credentials/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Atacantes pueden usar credenciales de data breaches sin ser detectados.',
        en: 'Attackers can use credentials from data breaches without detection.',
      },
    },
    roadmap_phase: 3,
  };
}

function buildSIM016(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  const evidence = getTestsForFinding('SIM-016', tests);
  const bypassed = countBypassed(evidence);
  const severity = severityFromBypassed(bypassed, Math.max(evidence.length, 1));

  return {
    finding_id: 'SIM-016',
    severity: bypassed === 0 ? 'info' : severity,
    module: 'challenge_analysis',
    title: {
      es: 'Tipo de challenge sub\u00f3ptimo',
      en: 'Challenge type suboptimal',
    },
    description: {
      es: `Security Level: ${intel.security.security_level}. Challenge TTL: ${intel.security.challenge_ttl}s. ${bypassed > 0 ? 'Algunos challenges pueden ser evadidos o son demasiado permisivos.' : 'Configuraci\u00f3n de challenge adecuada.'}`,
      en: `Security Level: ${intel.security.security_level}. Challenge TTL: ${intel.security.challenge_ttl}s. ${bypassed > 0 ? 'Some challenges may be evaded or are too permissive.' : 'Challenge configuration is adequate.'}`,
    },
    evidence_test_ids: evidence.map((t) => t.test_id),
    bypassed_count: bypassed,
    remediation: {
      summary: {
        es: 'Usar Managed Challenge en lugar de JS Challenge, y reducir Challenge TTL.',
        en: 'Use Managed Challenge instead of JS Challenge, and reduce Challenge TTL.',
      },
      steps: [
        { order: 1, action: { es: 'Revisar reglas que usen js_challenge', en: 'Review rules using js_challenge' }, where: 'Security > WAF', detail: { es: 'Identificar reglas con js_challenge y cambiar a managed_challenge.', en: 'Identify rules using js_challenge and switch to managed_challenge.' } },
        { order: 2, action: { es: 'Reducir Challenge Passage TTL', en: 'Reduce Challenge Passage TTL' }, where: 'Security > Settings', detail: { es: 'Establecer TTL en 30 min o menos para limitar ventana de clearance.', en: 'Set TTL to 30 min or less to limit clearance window.' } },
      ],
      cf_product: 'Security Settings',
      dashboard_path: 'Security > Settings',
      docs_url: 'https://developers.cloudflare.com/waf/tools/challenge-passage/',
      effort: 'quick_fix',
      risk_if_ignored: {
        es: 'Challenges d\u00e9biles permiten a bots obtener clearance duradera.',
        en: 'Weak challenges allow bots to obtain long-lasting clearance.',
      },
    },
    roadmap_phase: 5,
  };
}

function buildSIM017(tests: AttackTestResult[], intel: SecurityIntelligence): SimulationFinding {
  // Cross-module: count total bypassed across all modules
  const allBypassed = tests.filter((t) => t.outcome === 'bypassed');
  const total = tests.length;
  const bypassedCount = allBypassed.length;
  const severity = severityFromBypassed(bypassedCount, total);

  // Find modules with highest bypass rates
  const moduleBypass = new Map<AttackModuleId, { bypassed: number; total: number }>();
  for (const test of tests) {
    const entry = moduleBypass.get(test.module) || { bypassed: 0, total: 0 };
    entry.total++;
    if (test.outcome === 'bypassed') entry.bypassed++;
    moduleBypass.set(test.module, entry);
  }

  const weakModules = Array.from(moduleBypass.entries())
    .filter(([_, v]) => v.total > 0 && v.bypassed / v.total > 0.5)
    .map(([k]) => k);

  return {
    finding_id: 'SIM-017',
    severity,
    module: 'waf_bypass', // Cross-module, assigned to waf_bypass as primary
    title: {
      es: 'Brecha de cobertura de features de seguridad',
      en: 'Security feature coverage gap',
    },
    description: {
      es: `${bypassedCount} de ${total} pruebas (${total > 0 ? Math.round(bypassedCount / total * 100) : 0}%) lograron pasar las defensas. M\u00f3dulos d\u00e9biles: ${weakModules.length > 0 ? weakModules.join(', ') : 'ninguno'}.`,
      en: `${bypassedCount} of ${total} tests (${total > 0 ? Math.round(bypassedCount / total * 100) : 0}%) bypassed defenses. Weak modules: ${weakModules.length > 0 ? weakModules.join(', ') : 'none'}.`,
    },
    evidence_test_ids: allBypassed.map((t) => t.test_id),
    bypassed_count: bypassedCount,
    remediation: {
      summary: {
        es: 'Implementar protecci\u00f3n en capas: WAF + Rate Limiting + Bot Management + API Security.',
        en: 'Implement defense in depth: WAF + Rate Limiting + Bot Management + API Security.',
      },
      steps: [
        { order: 1, action: { es: 'Priorizar hallazgos SIM-001 a SIM-016', en: 'Prioritize findings SIM-001 through SIM-016' }, where: 'Este reporte', detail: { es: 'Implementar las correcciones en orden de roadmap phase.', en: 'Implement fixes in roadmap phase order.' } },
        { order: 2, action: { es: 'Re-ejecutar simulaci\u00f3n despu\u00e9s de cambios', en: 'Re-run simulation after changes' }, where: 'Anga', detail: { es: 'Verificar que los cambios mejoran la puntuaci\u00f3n.', en: 'Verify that changes improve the score.' } },
        { order: 3, action: { es: 'Programar simulaciones peri\u00f3dicas', en: 'Schedule periodic simulations' }, where: 'Anga', detail: { es: 'Ejecutar mensualmente para detectar regresi\u00f3n de seguridad.', en: 'Run monthly to detect security regression.' } },
      ],
      cf_product: 'Multiple',
      dashboard_path: 'Security > Overview',
      docs_url: 'https://developers.cloudflare.com/fundamentals/security/',
      effort: 'complex',
      risk_if_ignored: {
        es: 'La brecha acumulativa de seguridad deja m\u00faltiples vectores de ataque abiertos simult\u00e1neamente.',
        en: 'Cumulative security gap leaves multiple attack vectors open simultaneously.',
      },
    },
    roadmap_phase: 6,
  };
}
