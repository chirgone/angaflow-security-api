/**
 * Anga Security \u2014 Compliance Control Evaluator Helpers
 *
 * Shared utility functions used by all framework control evaluators.
 * Keeps evaluator code DRY and consistent.
 */

import type {
  EvaluationContext,
  ControlEvaluation,
  ControlStatus,
} from '../../../types/compliance';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Zone Settings Helper
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Get a zone setting value by ID */
export function s(ctx: EvaluationContext, settingId: string): any {
  return ctx.audit_data.zone_settings?.find(
    (setting) => setting.id === settingId,
  )?.value;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// ControlEvaluation Builder
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Build a ControlEvaluation result */
export function ev(
  status: ControlStatus,
  score: number,
  current_value: string,
  expected_value: string,
  details: string,
  data_sources_used: string[],
  raw_data?: any,
): ControlEvaluation {
  return {
    status,
    score,
    evidence: {
      current_value,
      expected_value,
      details,
      data_sources_used,
      raw_data,
    },
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Enriched Data Permission Check
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Check if enriched data is available. If not, return either
 * `insufficient_permissions` or `fail` depending on whether the
 * token has the required permission.
 *
 * Returns null if data IS available (caller should proceed with evaluation).
 * Returns a ControlEvaluation if data is NOT available.
 */
export function enrichedOrPerm(
  ctx: EvaluationContext,
  data: any | undefined,
  perm: string,
  sources: string[],
): ControlEvaluation | null {
  if (data !== undefined && data !== null) return null;

  if (!ctx.available_permissions.includes(perm)) {
    return ev(
      'insufficient_permissions',
      0,
      'N/A',
      `Requires permission: ${perm}`,
      'API token lacks the required permission to evaluate this control. Add the permission and re-run.',
      sources,
    );
  }

  return ev(
    'fail',
    0,
    'Not configured',
    'Feature should be enabled/configured',
    'Permission is available but no data was returned. The feature may not be configured on this zone.',
    sources,
  );
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// WAF / Ruleset Helpers
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Get rules from a specific WAF phase */
export function getRulesForPhase(ctx: EvaluationContext, phase: string) {
  return (
    ctx.audit_data.rulesets
      ?.filter((r) => r.phase === phase)
      ?.flatMap((r) => r.rules || []) || []
  );
}

/** Check if managed WAF rules are deployed */
export function hasManagedWaf(ctx: EvaluationContext): boolean {
  const rules = getRulesForPhase(ctx, 'http_request_firewall_managed');
  return rules.length > 0;
}

/** Check if OWASP ruleset is active */
export function hasOwaspRules(ctx: EvaluationContext): boolean {
  return getRulesForPhase(ctx, 'http_request_firewall_managed').some(
    (r) =>
      r.description?.toLowerCase().includes('owasp') ||
      r.action === 'score',
  );
}

/** Get custom WAF rules */
export function getCustomWafRules(ctx: EvaluationContext) {
  return getRulesForPhase(ctx, 'http_request_firewall_custom');
}

/** Get rate limiting rules */
export function getRateLimitRules(ctx: EvaluationContext) {
  return getRulesForPhase(ctx, 'http_ratelimit');
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// HSTS Helper
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Check HSTS configuration */
export function getHsts(ctx: EvaluationContext): {
  enabled: boolean;
  max_age: number;
  include_subdomains: boolean;
  nosniff: boolean;
} {
  const header = s(ctx, 'security_header');
  const sts = header?.strict_transport_security;
  return {
    enabled: sts?.enabled === true,
    max_age: sts?.max_age || 0,
    include_subdomains: sts?.include_subdomains === true,
    nosniff: sts?.nosniff === true,
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Section Metadata
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

import type { BiStr, ComplianceFramework } from '../../../types/compliance';

export interface SectionMeta {
  id: string;
  framework: ComplianceFramework;
  title: BiStr;
  description: BiStr;
}

/** All section metadata across all frameworks */
export const SECTION_METADATA: SectionMeta[] = [
  // PCI DSS 4.0
  { id: 'req_1', framework: 'pci_dss_4', title: { es: 'Req 1: Controles de Seguridad de Red', en: 'Req 1: Network Security Controls' }, description: { es: 'Instalar y mantener controles de seguridad de red', en: 'Install and maintain network security controls' } },
  { id: 'req_4', framework: 'pci_dss_4', title: { es: 'Req 4: Criptograf\u00eda en Tr\u00e1nsito', en: 'Req 4: Cryptography in Transit' }, description: { es: 'Proteger datos del titular con criptograf\u00eda fuerte durante la transmisi\u00f3n', en: 'Protect cardholder data with strong cryptography during transmission' } },
  { id: 'req_6', framework: 'pci_dss_4', title: { es: 'Req 6: Sistemas Seguros', en: 'Req 6: Secure Systems' }, description: { es: 'Desarrollar y mantener sistemas y software seguros', en: 'Develop and maintain secure systems and software' } },
  { id: 'req_7', framework: 'pci_dss_4', title: { es: 'Req 7: Control de Acceso', en: 'Req 7: Access Control' }, description: { es: 'Restringir acceso a componentes del sistema', en: 'Restrict access to system components' } },
  { id: 'req_8', framework: 'pci_dss_4', title: { es: 'Req 8: Autenticaci\u00f3n', en: 'Req 8: Authentication' }, description: { es: 'Identificar usuarios y autenticar acceso', en: 'Identify users and authenticate access' } },
  { id: 'req_10', framework: 'pci_dss_4', title: { es: 'Req 10: Registro y Monitoreo', en: 'Req 10: Logging & Monitoring' }, description: { es: 'Registrar y monitorear todo acceso a componentes del sistema', en: 'Log and monitor all access to system components' } },
  { id: 'req_11', framework: 'pci_dss_4', title: { es: 'Req 11: Pruebas de Seguridad', en: 'Req 11: Security Testing' }, description: { es: 'Probar la seguridad de sistemas y redes regularmente', en: 'Test security of systems and networks regularly' } },
  // ISO 27001:2022
  { id: 'annex_a8', framework: 'iso_27001', title: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' }, description: { es: 'Controles tecnol\u00f3gicos para la seguridad de la informaci\u00f3n', en: 'Technological controls for information security' } },
  // SOC 2 Type II
  { id: 'cc6', framework: 'soc2_type2', title: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical & Physical Access' }, description: { es: 'Controles de acceso l\u00f3gico y f\u00edsico', en: 'Logical and physical access controls' } },
  { id: 'cc7', framework: 'soc2_type2', title: { es: 'CC7: Operaciones del Sistema', en: 'CC7: System Operations' }, description: { es: 'Monitoreo y detecci\u00f3n de operaciones del sistema', en: 'System operations monitoring and detection' } },
  { id: 'cc8', framework: 'soc2_type2', title: { es: 'CC8: Gesti\u00f3n de Cambios', en: 'CC8: Change Management' }, description: { es: 'Gesti\u00f3n de cambios en la infraestructura', en: 'Infrastructure change management' } },
  { id: 'a1', framework: 'soc2_type2', title: { es: 'A1: Disponibilidad', en: 'A1: Availability' }, description: { es: 'Criterios adicionales de disponibilidad', en: 'Additional availability criteria' } },
  // LFPDPPP
  { id: 'medidas_seguridad', framework: 'lfpdppp', title: { es: 'Medidas de Seguridad (Arts. 19, 36)', en: 'Security Measures (Arts. 19, 36)' }, description: { es: 'Medidas de seguridad administrativas, t\u00e9cnicas y f\u00edsicas para protecci\u00f3n de datos personales', en: 'Administrative, technical and physical security measures for personal data protection' } },
  // GDPR
  { id: 'art_5', framework: 'gdpr', title: { es: 'Art. 5: Principios del Tratamiento', en: 'Art. 5: Processing Principles' }, description: { es: 'Principios relativos al tratamiento de datos personales', en: 'Principles relating to processing of personal data' } },
  { id: 'art_25', framework: 'gdpr', title: { es: 'Art. 25: Protecci\u00f3n por Dise\u00f1o', en: 'Art. 25: Data Protection by Design' }, description: { es: 'Protecci\u00f3n de datos desde el dise\u00f1o y por defecto', en: 'Data protection by design and by default' } },
  { id: 'art_32', framework: 'gdpr', title: { es: 'Art. 32: Seguridad del Tratamiento', en: 'Art. 32: Security of Processing' }, description: { es: 'Seguridad del tratamiento de datos personales', en: 'Security of personal data processing' } },
  { id: 'art_33', framework: 'gdpr', title: { es: 'Art. 33: Notificaci\u00f3n de Brechas', en: 'Art. 33: Breach Notification' }, description: { es: 'Notificaci\u00f3n de violaciones de seguridad', en: 'Notification of personal data breaches' } },

  // NIST SP 800-53 Rev 5
  { id: 'sc', framework: 'nist_800_53', title: { es: 'SC: Protección de Sistemas y Comunicaciones', en: 'SC: System and Communications Protection' }, description: { es: 'Controles de protección de sistemas y comunicaciones', en: 'System and communications protection controls' } },
  { id: 'au', framework: 'nist_800_53', title: { es: 'AU: Auditoría y Responsabilidad', en: 'AU: Audit and Accountability' }, description: { es: 'Controles de auditoría y registro', en: 'Audit and accountability controls' } },
  { id: 'cm', framework: 'nist_800_53', title: { es: 'CM: Gestión de Configuración', en: 'CM: Configuration Management' }, description: { es: 'Controles de gestión de configuración', en: 'Configuration management controls' } },
  { id: 'si', framework: 'nist_800_53', title: { es: 'SI: Integridad del Sistema', en: 'SI: System Integrity' }, description: { es: 'Controles de integridad del sistema', en: 'System integrity controls' } },
  { id: 'ac', framework: 'nist_800_53', title: { es: 'AC: Control de Acceso', en: 'AC: Access Control' }, description: { es: 'Controles de acceso', en: 'Access control controls' } },
  { id: 'ra', framework: 'nist_800_53', title: { es: 'RA: Evaluación de Riesgo', en: 'RA: Risk Assessment' }, description: { es: 'Controles de evaluación de riesgo', en: 'Risk assessment controls' } },
  { id: 'ca', framework: 'nist_800_53', title: { es: 'CA: Monitoreo Continuo', en: 'CA: Continuous Monitoring' }, description: { es: 'Controles de monitoreo continuo', en: 'Continuous monitoring controls' } },
  { id: 'ia', framework: 'nist_800_53', title: { es: 'IA: Identificación y Autenticación', en: 'IA: Identification and Authentication' }, description: { es: 'Controles de identificación y autenticación', en: 'Identification and authentication controls' } },
  // NIST CSF 2.0
  { id: 'gv_oc', framework: 'nist_csf', title: { es: 'GV: Gobernar', en: 'GV: Govern' }, description: { es: 'Función de gobierno organizacional', en: 'Organizational governance function' } },
  { id: 'id_am', framework: 'nist_csf', title: { es: 'ID: Identificar', en: 'ID: Identify' }, description: { es: 'Función de identificación', en: 'Identify function' } },
  { id: 'pr_ds', framework: 'nist_csf', title: { es: 'PR: Proteger — DS: Seguridad de Datos', en: 'PR: Protect — DS: Data Security' }, description: { es: 'Función de protección de datos', en: 'Data protection function' } },
  { id: 'pr_ac', framework: 'nist_csf', title: { es: 'PR: Proteger — AC: Control de Acceso', en: 'PR: Protect — AC: Access Control' }, description: { es: 'Función de control de acceso', en: 'Access control function' } },
  { id: 'pr_ip', framework: 'nist_csf', title: { es: 'PR: Proteger — IP: Procesos de Protección', en: 'PR: Protect — IP: Information Protection Processes' }, description: { es: 'Función de procesos de protección', en: 'Information protection processes function' } },
  { id: 'pr_at', framework: 'nist_csf', title: { es: 'PR: Proteger — AT: Concienciación', en: 'PR: Protect — AT: Awareness and Training' }, description: { es: 'Función de concienciación y entrenamiento', en: 'Awareness and training function' } },
  { id: 'de_cm', framework: 'nist_csf', title: { es: 'DE: Detectar — CM: Monitoreo Continuo', en: 'DE: Detect — CM: Continuous Monitoring' }, description: { es: 'Función de monitoreo continuo', en: 'Continuous monitoring function' } },
  { id: 'de_ae', framework: 'nist_csf', title: { es: 'DE: Detectar — AE: Anomalías y Eventos', en: 'DE: Detect — AE: Anomalies and Events' }, description: { es: 'Función de detección de anomalías', en: 'Anomalies and events detection function' } },
  { id: 'rs_co', framework: 'nist_csf', title: { es: 'RS: Responder — CO: Comunicaciones', en: 'RS: Respond — CO: Communications' }, description: { es: 'Función de comunicaciones de respuesta', en: 'Response communications function' } },
  { id: 'rc_rp', framework: 'nist_csf', title: { es: 'RC: Recuperar — RP: Planificación', en: 'RC: Recover — RP: Recovery Planning' }, description: { es: 'Función de planificación de recuperación', en: 'Recovery planning function' } },
  // Infra Baseline
  { id: 'tls', framework: 'infra_baseline', title: { es: 'TLS: Seguridad de Transporte', en: 'TLS: Transport Security' }, description: { es: 'Controles de cifrado en tránsito', en: 'Encryption in transit controls' } },
  { id: 'waf', framework: 'infra_baseline', title: { es: 'WAF: Firewall de Aplicaciones Web', en: 'WAF: Web Application Firewall' }, description: { es: 'Controles de firewall de aplicaciones web', en: 'Web application firewall controls' } },
  { id: 'dns', framework: 'infra_baseline', title: { es: 'DNS: Seguridad del Dominio', en: 'DNS: Domain Security' }, description: { es: 'Controles de seguridad DNS', en: 'DNS security controls' } },
  { id: 'headers', framework: 'infra_baseline', title: { es: 'Headers: Cabeceras de Seguridad', en: 'Headers: Security Headers' }, description: { es: 'Controles de headers HTTP de seguridad', en: 'HTTP security header controls' } },
  { id: 'rate', framework: 'infra_baseline', title: { es: 'RATE: Control de Velocidad', en: 'RATE: Rate Control' }, description: { es: 'Controles de rate limiting', en: 'Rate limiting controls' } },
  { id: 'ddos', framework: 'infra_baseline', title: { es: 'DDOS: Protección DDoS', en: 'DDOS: DDoS Protection' }, description: { es: 'Controles de protección DDoS', en: 'DDoS protection controls' } },
  { id: 'access', framework: 'infra_baseline', title: { es: 'ACCESS: Control de Acceso', en: 'ACCESS: Access Control' }, description: { es: 'Controles de acceso a bots y tráfico', en: 'Bot and traffic access controls' } },
  { id: 'cache', framework: 'infra_baseline', title: { es: 'CACHE: Seguridad del Cache', en: 'CACHE: Cache Security' }, description: { es: 'Controles de seguridad de caché', en: 'Cache security controls' } },
  { id: 'logging', framework: 'infra_baseline', title: { es: 'LOG: Registro y Monitoreo', en: 'LOG: Logging and Monitoring' }, description: { es: 'Controles de logging y monitoreo', en: 'Logging and monitoring controls' } },
  { id: 'privacy', framework: 'infra_baseline', title: { es: 'PRIV: Privacidad', en: 'PRIV: Privacy' }, description: { es: 'Controles de privacidad', en: 'Privacy controls' } },
  { id: 'api', framework: 'infra_baseline', title: { es: 'API: Seguridad de API Gateway', en: 'API: API Gateway Security' }, description: { es: 'Controles de seguridad de API Shield/Gateway (Enterprise)', en: 'API Shield/Gateway security controls (Enterprise)' } },
];