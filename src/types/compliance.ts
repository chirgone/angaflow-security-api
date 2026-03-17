/**
 * Anga Security \u2014 Compliance Engine Type Definitions
 *
 * Enterprise-grade compliance mapping system for 5 regulatory frameworks:
 * PCI DSS 4.0, ISO 27001:2022, SOC 2 Type II, LFPDPPP, GDPR
 *
 * Each framework\u2019s controls are mapped to Cloudflare API data points.
 * Controls are evaluated as: automated, partial, or manual-flag.
 */

import type { AuditTier, CloudflarePlanTier, CollectedData } from './audit';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Frameworks & Pricing
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export type ComplianceFramework =
  | 'pci_dss_4'
  | 'iso_27001'
  | 'soc2_type2'
  | 'lfpdppp'
  | 'gdpr'
  | 'nist_800_53'
  | 'nist_csf'
  | 'infra_baseline';

export const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  'pci_dss_4',
  'iso_27001',
  'soc2_type2',
  'lfpdppp',
  'gdpr',
  'nist_800_53',
  'nist_csf',
  'infra_baseline',
];

/** Credit costs per framework */
export const COMPLIANCE_CREDIT_COSTS: Record<ComplianceFramework | 'bundle' | 'bundle_8', number> = {
  pci_dss_4: 800,
  iso_27001: 800,
  soc2_type2: 800,
  lfpdppp: 500,
  gdpr: 800,
  nist_800_53: 800,
  nist_csf: 700,
  infra_baseline: 600,
  bundle: 2500,    // Original 5-framework bundle
  bundle_8: 3800,  // Full 8-framework bundle (saves 2,100)
};

/** Audit credit costs (imported here to avoid circular deps) */
const AUDIT_COSTS = {
  pro: 3000,
  complete: 5000,
} as const;

/** Discounts for bundled audit + compliance purchase */
const DIRECT_COMPLIANCE_DISCOUNTS = {
  pro: 500,
  complete: 700,
} as const;

/**
 * Calculate total credits for direct compliance mode (audit + compliance bundled).
 * Applies discount when purchasing both together.
 */
export function calculateDirectComplianceCost(
  tier: 'pro' | 'complete',
  frameworks: ComplianceFramework[] | 'bundle' | 'bundle_8',
): number {
  const auditCost = AUDIT_COSTS[tier];
  const discount = DIRECT_COMPLIANCE_DISCOUNTS[tier];

  let complianceCost: number;
  if (frameworks === 'bundle') {
    complianceCost = COMPLIANCE_CREDIT_COSTS.bundle;
  } else if (frameworks === 'bundle_8') {
    complianceCost = COMPLIANCE_CREDIT_COSTS.bundle_8;
  } else {
    complianceCost = frameworks.reduce((sum, fw) => sum + COMPLIANCE_CREDIT_COSTS[fw], 0);
  }

  return auditCost + complianceCost - discount;
}

/**
 * Get detailed breakdown of direct compliance cost for display.
 */
export function getDirectComplianceCostBreakdown(
  tier: 'pro' | 'complete',
  frameworks: ComplianceFramework[] | 'bundle' | 'bundle_8',
): {
  audit_cost: number;
  compliance_cost: number;
  discount: number;
  total: number;
  audit_tier: string;
  frameworks_label: string;
} {
  const auditCost = AUDIT_COSTS[tier];
  const discount = DIRECT_COMPLIANCE_DISCOUNTS[tier];

  let complianceCost: number;
  let frameworksLabel: string;

  if (frameworks === 'bundle') {
    complianceCost = COMPLIANCE_CREDIT_COSTS.bundle;
    frameworksLabel = 'Bundle (5 frameworks)';
  } else if (frameworks === 'bundle_8') {
    complianceCost = COMPLIANCE_CREDIT_COSTS.bundle_8;
    frameworksLabel = 'Bundle (8 frameworks)';
  } else {
    complianceCost = frameworks.reduce((sum, fw) => sum + COMPLIANCE_CREDIT_COSTS[fw], 0);
    frameworksLabel = frameworks.length === 1
      ? FRAMEWORK_INFO[frameworks[0]].name
      : `${frameworks.length} frameworks`;
  }

  return {
    audit_cost: auditCost,
    compliance_cost: complianceCost,
    discount,
    total: auditCost + complianceCost - discount,
    audit_tier: tier === 'pro' ? 'Pro' : 'Complete',
    frameworks_label: frameworksLabel,
  };
}

/** Framework metadata */
export const FRAMEWORK_INFO: Record<ComplianceFramework, {
  name: string;
  version: string;
  full_name: { es: string; en: string };
  region: { es: string; en: string };
  source_url: string;
  issuing_body: string;
}> = {
  pci_dss_4: {
    name: 'PCI DSS 4.0',
    version: 'v4.0',
    full_name: {
      es: 'Payment Card Industry Data Security Standard',
      en: 'Payment Card Industry Data Security Standard',
    },
    region: { es: 'Global', en: 'Global' },
    source_url: 'https://www.pcisecuritystandards.org/document_library/',
    issuing_body: 'PCI Security Standards Council',
  },
  iso_27001: {
    name: 'ISO 27001:2022',
    version: '2022',
    full_name: {
      es: 'Sistema de Gesti\u00f3n de Seguridad de la Informaci\u00f3n',
      en: 'Information Security Management System',
    },
    region: { es: 'Global', en: 'Global' },
    source_url: 'https://www.iso.org/standard/27001',
    issuing_body: 'International Organization for Standardization',
  },
  soc2_type2: {
    name: 'SOC 2 Type II',
    version: 'Type II',
    full_name: {
      es: 'Service Organization Control 2',
      en: 'Service Organization Control 2',
    },
    region: { es: 'EE.UU.', en: 'USA' },
    source_url: 'https://www.aicpa.org/topic/audit-assurance/audit-and-assurance-greater-than-soc-2',
    issuing_body: 'AICPA (American Institute of CPAs)',
  },
  lfpdppp: {
    name: 'LFPDPPP',
    version: '2010',
    full_name: {
      es: 'Ley Federal de Protecci\u00f3n de Datos Personales en Posesi\u00f3n de los Particulares',
      en: 'Federal Law on Protection of Personal Data Held by Private Parties',
    },
    region: { es: 'M\u00e9xico', en: 'Mexico' },
    source_url: 'https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf',
    issuing_body: 'Congreso de la Uni\u00f3n (M\u00e9xico)',
  },
  gdpr: {
    name: 'GDPR',
    version: '2016/679',
    full_name: {
      es: 'Reglamento General de Protección de Datos',
      en: 'General Data Protection Regulation',
    },
    region: { es: 'Unión Europea', en: 'European Union' },
    source_url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj',
    issuing_body: 'European Parliament & Council',
  },
  nist_800_53: {
    name: 'NIST 800-53 Rev 5',
    version: 'Rev 5',
    full_name: {
      es: 'Controles de Seguridad y Privacidad para Sistemas de Información (Infraestructura)',
      en: 'Security and Privacy Controls for Information Systems (Infrastructure)',
    },
    region: { es: 'EE.UU. / Global', en: 'USA / Global' },
    source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    issuing_body: 'National Institute of Standards and Technology (NIST)',
  },
  nist_csf: {
    name: 'NIST CSF 2.0',
    version: '2.0',
    full_name: {
      es: 'Marco de Ciberseguridad NIST (Proteger y Detectar)',
      en: 'NIST Cybersecurity Framework (Protect & Detect)',
    },
    region: { es: 'EE.UU. / Global', en: 'USA / Global' },
    source_url: 'https://www.nist.gov/cyberframework',
    issuing_body: 'National Institute of Standards and Technology (NIST)',
  },
  infra_baseline: {
    name: 'Infrastructure Security Baseline',
    version: '1.0',
    full_name: {
      es: 'Línea Base de Seguridad de Infraestructura para CDN/WAF',
      en: 'Infrastructure Security Baseline for CDN/WAF',
    },
    region: { es: 'Global', en: 'Global' },
    source_url: 'https://angaflow.com/frameworks/infra-baseline',
    issuing_body: 'Anga Security',
  },
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Control Definitions (static, used by framework-controls.ts)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export type ControlStatus =
  | 'pass'
  | 'fail'
  | 'partial'
  | 'not_applicable'
  | 'manual_required'
  | 'insufficient_permissions';

export type ControlSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type EvaluationMethod = 'automated' | 'partial' | 'manual_flag';

/** Bilingual string */
export interface BiStr {
  es: string;
  en: string;
}

/** The static definition of a compliance control (before evaluation) */
export interface FrameworkControl {
  control_id: string;            // 'PCI-4.2.1', 'ISO-A.8.24'
  control_ref: string;           // 'Requirement 4.2.1', 'Annex A.8.24'
  framework: ComplianceFramework;
  section_id: string;            // 'req_4', 'annex_a8', 'cc6'
  title: BiStr;
  description: BiStr;
  severity: ControlSeverity;
  evaluation_method: EvaluationMethod;

  // Regulatory reference text
  regulatory_reference: {
    section: BiStr;              // 'Requirement 4: Protect Cardholder Data...'
    clause: string;              // '4.2.1'
    official_text: BiStr;        // Verbatim regulatory text
    applicability_note: BiStr;   // How this applies to Cloudflare
    source_url?: string;
  };

  // What data sources this control needs
  required_data_sources: string[];  // ['zone_settings.ssl', 'edge_certificates']
  required_permissions: string[];   // ['SSL and Certificates Read']

  // Cross-references to other frameworks
  cross_references: {
    framework: ComplianceFramework;
    control_id: string;
    clause: string;
  }[];

  // Remediation template (populated at definition time)
  remediation_template: {
    summary: BiStr;
    risk_if_ignored: BiStr;
    steps: {
      order: number;
      action: BiStr;
      where: BiStr;
      detail: BiStr;
    }[];
    cloudflare_doc_url: string;
    estimated_effort: 'minutes' | 'hours' | 'days';
    requires_plan_upgrade: boolean;
    min_plan?: CloudflarePlanTier;
    can_be_automated: boolean;
  };

  /** The evaluator function — takes enriched data, returns evaluation result */
  evaluate: (ctx: EvaluationContext) => ControlEvaluation;
}

/** Context passed to each control evaluator */
export interface EvaluationContext {
  audit_data: CollectedData;
  enriched_data: EnrichedComplianceData;
  cf_plan: CloudflarePlanTier;
  available_permissions: string[];
}

/** Result from a single control evaluation */
export interface ControlEvaluation {
  status: ControlStatus;
  score: number;                  // 0-100
  evidence: {
    current_value: string;
    expected_value: string;
    details: string;
    data_sources_used: string[];
    raw_data?: any;
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Control Result (after evaluation \u2014 stored in the report)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface ControlResult {
  // Identification
  control_id: string;
  control_ref: string;
  title: BiStr;
  description: BiStr;

  // Regulatory reference (the verbatim article/clause)
  regulatory_reference: {
    framework_name: string;
    section: BiStr;
    clause: string;
    official_text: BiStr;
    applicability_note: BiStr;
    source_url?: string;
  };

  // Evaluation
  status: ControlStatus;
  severity: ControlSeverity;
  score: number;                 // 0-100 (pass=100, partial=50, fail=0)
  evaluation_method: EvaluationMethod;

  // Evidence
  evidence: {
    data_sources: string[];
    current_value: string;
    expected_value: string;
    details: string;
    raw_data?: any;
  };

  // Remediation (detailed steps)
  remediation: {
    summary: BiStr;
    risk_if_ignored: BiStr;
    steps: {
      order: number;
      action: BiStr;
      where: BiStr;
      detail: BiStr;
    }[];
    cloudflare_doc_url: string;
    estimated_effort: 'minutes' | 'hours' | 'days';
    requires_plan_upgrade: boolean;
    min_plan?: CloudflarePlanTier;
    can_be_automated: boolean;
  };

  // Cross-references to other frameworks
  cross_references: {
    framework: ComplianceFramework;
    control_id: string;
    clause: string;
  }[];

  // Manual checklist (user can mark verified)
  manual_checklist?: {
    verified: boolean;
    verified_by?: string;
    verified_at?: string;
    notes?: string;
  };

  evaluated_at: string;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Section (groups controls by framework section)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface ComplianceSection {
  id: string;                    // 'req_4', 'annex_a8'
  title: BiStr;
  description: BiStr;
  controls: ControlResult[];
  section_score: number;         // 0-100 (weighted by severity)
  section_grade: 'A' | 'B' | 'C' | 'D' | 'F';
  passed: number;
  failed: number;
  partial: number;
  manual: number;
  not_applicable: number;
  insufficient_permissions: number;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Enriched Compliance Data (additional collectors beyond audit)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface EdgeCertificate {
  id: string;
  type: 'universal' | 'advanced' | 'custom' | 'unknown';
  hosts: string[];
  issuer: string;
  signature: string;
  expires_on: string;
  status: string;
  days_until_expiry: number;
}

export interface LogpushJob {
  id: number;
  dataset: string;
  destination: string;
  enabled: boolean;
  last_complete: string | null;
  last_error: string | null;
}

export interface IPAccessRule {
  mode: string;     // 'block' | 'challenge' | 'whitelist' | 'js_challenge'
  target: string;   // IP, range, country, ASN
  notes: string;
}

export interface HealthCheck {
  name: string;
  type: string;
  status: string;   // 'healthy' | 'unhealthy' | 'suspended'
  interval: number;
}

export interface NotificationPolicy {
  id: string;
  name: string;
  alert_type: string;
  enabled: boolean;
}

// ══════════════════════════════════════════════════════════════════════
// API Shield / API Gateway Types (Enterprise Feature)
// ══════════════════════════════════════════════════════════════════════

export interface APIShieldOperation {
  id: string;
  method: string;
  endpoint: string;
  host: string;
  last_updated?: string;
  features?: {
    schema_validation?: { enabled: boolean };
    rate_limiting?: { enabled: boolean };
  };
}

export interface APIShieldData {
  /** Whether the API Shield:Read permission was granted */
  permission_granted: boolean;

  /** Zone plan info */
  plan: 'free' | 'pro' | 'business' | 'enterprise' | 'unknown';
  is_enterprise: boolean;

  /** API Discovery - inventoried endpoints */
  discovery: {
    enabled: boolean;
    total_operations: number;
    operations: APIShieldOperation[];
  };

  /** Schema Validation - OpenAPI/Swagger validation */
  schema_validation: {
    enabled: boolean;
    schemas_configured: number;
    operations_covered: number;
    total_operations: number;
    coverage_percent: number;
  };

  /** JWT Token Validation */
  jwt_validation: {
    enabled: boolean;
    configs_count: number;
  };

  /** Mutual TLS (mTLS) */
  mtls: {
    enabled: boolean;
    certificates_configured: number;
  };

  /** Rate Limiting (API-specific) */
  rate_limiting: {
    enabled: boolean;
    rules_configured: number;
  };

  /** Session Identifiers */
  session_identifiers: {
    enabled: boolean;
    identifiers_configured: number;
  };

  /** Volumetric Abuse Detection */
  volumetric_abuse: {
    enabled: boolean;
  };

  /** Sequence Mitigation */
  sequence_mitigation: {
    enabled: boolean;
  };

  /** Collection metadata */
  collected_at: string;
  collection_duration_ms: number;
}

export interface EnrichedComplianceData {
  /** API Shield / API Gateway data (Enterprise feature) */
  api_shield?: APIShieldData;

  edge_certificates?: {
    total: number;
    certificates: EdgeCertificate[];
    any_expired: boolean;
    any_expiring_soon: boolean;
  };

  cipher_suites?: {
    configured: string[];
    pci_dss_compliant: boolean;
    fips_140_compliant: boolean;
    weak_ciphers: string[];
    missing_recommended: string[];
  };

  authenticated_origin_pulls?: {
    enabled: boolean;
  };

  logpush_jobs?: {
    total: number;
    jobs: LogpushJob[];
    has_firewall_logs: boolean;
    has_http_logs: boolean;
    has_audit_logs: boolean;
  };

  audit_logs?: {
    available: boolean;
    recent_count: number;
    has_config_changes: boolean;
    sample_actions: string[];
  };

  ip_access_rules?: {
    total: number;
    rules: IPAccessRule[];
    has_geo_blocks: boolean;
    has_ip_allowlist: boolean;
  };

  page_shield?: {
    enabled: boolean;
    total_scripts: number;
    malicious_scripts: number;
    scripts_first_party: number;
    scripts_third_party: number;
  };

  notification_policies?: {
    total: number;
    alert_types: string[];
    has_security_alerts: boolean;
    has_ssl_alerts: boolean;
    has_ddos_alerts: boolean;
  };

  health_checks?: {
    total: number;
    checks: HealthCheck[];
    all_healthy: boolean;
  };

  /** Tracks which collectors succeeded/failed/skipped */
  collector_results: {
    name: string;
    status: 'success' | 'failed' | 'skipped';
    error?: string;
    duration_ms: number;
  }[];
}

export const EMPTY_ENRICHED_DATA: EnrichedComplianceData = {
  collector_results: [],
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Compliance Report (the final output stored in security_reports.data)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface ComplianceReport {
  version: '1.0';
  
  /** Which frameworks are included (1 for individual, 5 for bundle) */
  frameworks: ComplianceFramework[];
  is_bundle: boolean;

  /** Source audit reference */
  source_audit_id: string;
  source_audit_tier: AuditTier;
  zone_name: string;
  zone_id: string;
  cf_plan: CloudflarePlanTier;

  /** Timing */
  generated_at: string;
  duration_ms: number;
  analysis_period: { start: string; end: string };

  /** Overall scoring (severity-weighted) */
  compliance_score: number;        // 0-100
  compliance_grade: 'A' | 'B' | 'C' | 'D' | 'F';

  /** Summary counters */
  summary: {
    total_controls: number;
    passed: number;
    failed: number;
    partial: number;
    not_applicable: number;
    manual_required: number;
    insufficient_permissions: number;
    coverage_pct: number;          // % auto-verifiable
  };

  /** Per-framework sections */
  framework_results: FrameworkResult[];

  /** Cross-framework coverage matrix (for bundle) */
  cross_framework_matrix?: CrossFrameworkEntry[];

  /** AI-generated recommendations for cross-framework matrix (for bundle) */
  cross_framework_recommendations?: CrossFrameworkRecommendation[];

  /** Executive summary */
  executive_summary: {
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    key_findings: BiStr[];
    strengths: BiStr[];
    immediate_actions: BiStr[];
    estimated_remediation_hours: number;
  };

  /** Enriched data collected for compliance */
  enriched_data: EnrichedComplianceData;

  /** Token permission audit */
  token_audit: {
    permissions_available: string[];
    permissions_missing: string[];
    controls_limited_by_permissions: number;
  };

  /** Staleness info */
  source_audit_age_days: number;
  staleness_warning: boolean;     // true if > 7 days old

  /** Disclaimer */
  disclaimer: BiStr;

  /** Metadata */
  collectors_run: number;
  collectors_failed: number;
}

/** Results for a single framework within the report */
export interface FrameworkResult {
  framework: ComplianceFramework;
  framework_info: typeof FRAMEWORK_INFO[ComplianceFramework];
  sections: ComplianceSection[];
  framework_score: number;
  framework_grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: {
    total_controls: number;
    passed: number;
    failed: number;
    partial: number;
    not_applicable: number;
    manual_required: number;
    insufficient_permissions: number;
  };
}

/** Cross-framework mapping entry (shows shared controls) */
export interface CrossFrameworkEntry {
  data_point: string;            // 'SSL/TLS Mode'
  cloudflare_setting: string;    // 'zone_settings.ssl'
  current_value: string;
  frameworks_covered: {
    framework: ComplianceFramework;
    control_id: string;
    status: ControlStatus;
  }[];
}

/** AI-generated recommendation for cross-framework data point */
export interface CrossFrameworkRecommendation {
  data_point: string;                    // 'SSL/TLS Mode'
  priority_score: number;                // 0-100 (calculated ROI)
  frameworks_impacted: number;           // Count of frameworks affected
  failed_frameworks: number;             // Count of failing/partial frameworks
  effort_estimate: 'minutes' | 'hours' | 'days';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  
  ai_insight: BiStr;                     // AI-generated contextual explanation
  
  quick_win: boolean;                    // True if high impact + low effort
  can_autofix: boolean;                  // True if can be fixed via Anga AutoFix
  
  recommendation: BiStr;                 // What to do
  business_impact: BiStr;                // Why it matters
  technical_details: string;             // Technical explanation
  
  // For AutoFix integration
  related_control_ids: string[];         // Control IDs that can be auto-fixed
}

// ══════════════════════════════════════════════════════════════════
// Severity Weights (for scoring)
// ══════════════════════════════════════════════════════════════════

export const SEVERITY_WEIGHTS: Record<ControlSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0.5,
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// API Request / Response Types
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface RunComplianceRequest {
  source_audit_id: string;
  frameworks: ComplianceFramework[];  // or ['bundle'] handled server-side
  zone_id: string;
  api_token: string;
}

export interface PreCheckResponse {
  can_run: boolean;
  source_audit: {
    id: string;
    tier: AuditTier;
    zone_name: string;
    age_days: number;
    is_stale: boolean;
  };
  token_permissions: {
    available: string[];
    missing: string[];
    controls_limited: number;
  };
  credits_required: number;
  credits_available: number;
  insufficient_credits: boolean;
}

export interface RunComplianceResponse {
  success: boolean;
  report_id: string;
  frameworks: ComplianceFramework[];
  credits_charged: number;
  report: ComplianceReport;
}

export interface UpdateManualChecklistRequest {
  report_id: string;
  control_id: string;
  framework: ComplianceFramework;
  verified: boolean;
  notes?: string;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// PCI DSS compliant cipher suites (from Cloudflare docs)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export const PCI_DSS_COMPLIANT_CIPHERS = [
  'AEAD-AES128-GCM-SHA256',
  'AEAD-AES256-GCM-SHA384',
  'AEAD-CHACHA20-POLY1305-SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305',
  'ECDHE-RSA-CHACHA20-POLY1305',
];

/** Known weak ciphers that should never be used */
export const WEAK_CIPHERS = [
  'DES-CBC3-SHA',
  'RC4-SHA',
  'RC4-MD5',
  'AES128-SHA',
  'AES256-SHA',
  'DES-CBC-SHA',
];

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Legal Disclaimer
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export const COMPLIANCE_DISCLAIMER: BiStr = {
  es: 'Este reporte es generado por Anga Security, un servicio de asesor\u00eda de terceros especializado en Cloudflare. Este an\u00e1lisis NO constituye una certificaci\u00f3n formal ni una auditor\u00eda oficial de cumplimiento. Los resultados son una evaluaci\u00f3n t\u00e9cnica automatizada basada en la configuraci\u00f3n actual de Cloudflare y deben ser validados por un auditor certificado (QSA para PCI DSS, auditor ISO acreditado, CPA para SOC 2, etc.) antes de reclamar cumplimiento formal. Anga Security no es responsable por decisiones tomadas con base en este reporte.',
  en: 'This report is generated by Anga Security, a third-party advisory service specializing in Cloudflare. This analysis does NOT constitute a formal certification or an official compliance audit. The results are an automated technical assessment based on the current Cloudflare configuration and must be validated by a certified auditor (QSA for PCI DSS, accredited ISO auditor, CPA for SOC 2, etc.) before claiming formal compliance. Anga Security is not liable for decisions made based on this report.',
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Compliance Preview (teaser in audit report)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface CompliancePreviewControl {
  framework: ComplianceFramework;
  framework_name: string;
  control_id: string;
  title: BiStr;
  clause: string;
  status: ControlStatus;
  severity: ControlSeverity;
  current_value: string;
  expected_value: string;
}

export interface CompliancePreview {
  controls: CompliancePreviewControl[];
  total_mappable_controls: number;
  frameworks_available: ComplianceFramework[];
  requires_pro_or_complete: boolean;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Token Permission Requirements
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** All permissions needed for 100% compliance coverage */
export const COMPLIANCE_TOKEN_PERMISSIONS = {
  // Zone-scoped (existing from audit)
  zone_read: 'Zone:Read',
  analytics_read: 'Analytics:Read',
  firewall_read: 'Firewall Services:Read',
  dns_read: 'DNS:Read',
  // Zone-scoped (NEW for compliance)
  ssl_read: 'SSL and Certificates:Read',
  logs_read: 'Logs:Read',
  page_shield_read: 'Page Shield:Read',
  health_checks_read: 'Health Checks:Read',
  // Zone-scoped (API Shield - Enterprise)
  api_shield_read: 'API Shield:Read',
  // Account-scoped (NEW for compliance)
  audit_logs_read: 'Account Access: Audit Logs',
  notifications_read: 'Notifications:Read',
} as const;

/** Permissions inherited from the source audit token */
export const AUDIT_INHERITED_PERMISSIONS = [
  'Zone:Read',
  'Analytics:Read',
  'Firewall Services:Read',
  'DNS:Read',
];

/** NEW permissions required specifically for compliance */
export const COMPLIANCE_EXTRA_PERMISSIONS = [
  'SSL and Certificates:Read',
  'Logs:Read',
  'Page Shield:Read',
  'Health Checks:Read',
  'API Shield:Read',  // Enterprise feature
  'Account Access: Audit Logs',
  'Notifications:Read',
];

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Helper: Compute severity-weighted score
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/**
 * Calculates a severity-weighted compliance score.
 * critical=4x, high=3x, medium=2x, low=1x, info=0.5x
 * Controls with insufficient_permissions or not_applicable are excluded.
 */
export function calculateWeightedScore(
  controls: ControlResult[],
): { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F' } {
  const scorable = controls.filter(
    (c) => c.status !== 'not_applicable' && c.status !== 'insufficient_permissions',
  );
  if (scorable.length === 0) return { score: 0, grade: 'F' };

  let totalWeight = 0;
  let weightedSum = 0;

  for (const ctrl of scorable) {
    const w = SEVERITY_WEIGHTS[ctrl.severity] || 1;
    totalWeight += w;
    weightedSum += (ctrl.score / 100) * w;
  }

  const score = Math.round((weightedSum / totalWeight) * 100);
  const grade =
    score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return { score, grade };
}
