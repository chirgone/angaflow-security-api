/**
 * Anga Security \u2014 Compliance Controls Registry
 *
 * Central barrel file for all framework controls.
 * Provides lookup functions, the master registry, and preview controls.
 */

import type {
  ComplianceFramework,
  FrameworkControl,
  CompliancePreviewControl,
  CompliancePreview,
  EvaluationContext,
} from '../../../types/compliance';
import { FRAMEWORK_INFO } from '../../../types/compliance';
import { PCI_DSS_CONTROLS } from './pci-dss';
import { ISO_27001_CONTROLS } from './iso-27001';
import { SOC2_CONTROLS } from './soc2';
import { LFPDPPP_CONTROLS } from './lfpdppp';
import { GDPR_CONTROLS } from './gdpr';
import { NIST_800_53_CONTROLS } from './nist-800-53';
import { NIST_CSF_CONTROLS } from './nist-csf';
import { INFRA_BASELINE_CONTROLS } from './infra-baseline';
import {
  PCI_DSS_API_SHIELD_CONTROLS,
  ISO_27001_API_SHIELD_CONTROLS,
  SOC2_API_SHIELD_CONTROLS,
  NIST_800_53_API_SHIELD_CONTROLS,
  INFRA_BASELINE_API_SHIELD_CONTROLS,
} from './api-shield';
import { SECTION_METADATA, type SectionMeta } from './helpers';

// Re-export helpers and section metadata
export { SECTION_METADATA, type SectionMeta } from './helpers';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Master Registry
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** All controls from all 8 frameworks combined (including API Shield) */
export const ALL_CONTROLS: FrameworkControl[] = [
  ...PCI_DSS_CONTROLS,
  ...PCI_DSS_API_SHIELD_CONTROLS,
  ...ISO_27001_CONTROLS,
  ...ISO_27001_API_SHIELD_CONTROLS,
  ...SOC2_CONTROLS,
  ...SOC2_API_SHIELD_CONTROLS,
  ...LFPDPPP_CONTROLS,
  ...GDPR_CONTROLS,
  ...NIST_800_53_CONTROLS,
  ...NIST_800_53_API_SHIELD_CONTROLS,
  ...NIST_CSF_CONTROLS,
  ...INFRA_BASELINE_CONTROLS,
  ...INFRA_BASELINE_API_SHIELD_CONTROLS,
];

/** Per-framework control arrays (including API Shield controls) */
const FRAMEWORK_CONTROLS_MAP: Record<ComplianceFramework, FrameworkControl[]> = {
  pci_dss_4: [...PCI_DSS_CONTROLS, ...PCI_DSS_API_SHIELD_CONTROLS],
  iso_27001: [...ISO_27001_CONTROLS, ...ISO_27001_API_SHIELD_CONTROLS],
  soc2_type2: [...SOC2_CONTROLS, ...SOC2_API_SHIELD_CONTROLS],
  lfpdppp: LFPDPPP_CONTROLS,  // No API Shield controls (Mexican data protection law)
  gdpr: GDPR_CONTROLS,         // No API Shield controls (EU data protection law)
  nist_800_53: [...NIST_800_53_CONTROLS, ...NIST_800_53_API_SHIELD_CONTROLS],
  nist_csf: NIST_CSF_CONTROLS, // API Shield maps primarily to 800-53
  infra_baseline: [...INFRA_BASELINE_CONTROLS, ...INFRA_BASELINE_API_SHIELD_CONTROLS],
};

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Lookup Functions
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Get all controls for a specific framework */
export function getControlsForFramework(
  framework: ComplianceFramework,
): FrameworkControl[] {
  return FRAMEWORK_CONTROLS_MAP[framework] || [];
}

/** Get a single control by ID */
export function getControlById(
  controlId: string,
): FrameworkControl | undefined {
  return ALL_CONTROLS.find((c) => c.control_id === controlId);
}

/** Get controls grouped by section for a framework */
export function getControlsBySection(
  framework: ComplianceFramework,
): Map<string, FrameworkControl[]> {
  const controls = getControlsForFramework(framework);
  const sections = new Map<string, FrameworkControl[]>();
  for (const ctrl of controls) {
    const existing = sections.get(ctrl.section_id) || [];
    existing.push(ctrl);
    sections.set(ctrl.section_id, existing);
  }
  return sections;
}

/** Get section metadata */
export function getSectionInfo(
  sectionId: string,
  framework: ComplianceFramework,
): SectionMeta | undefined {
  return SECTION_METADATA.find(
    (sm) => sm.id === sectionId && sm.framework === framework,
  );
}

/** Get all unique section IDs for a framework */
export function getSectionIds(framework: ComplianceFramework): string[] {
  const controls = getControlsForFramework(framework);
  return [...new Set(controls.map((c) => c.section_id))];
}

/** Count controls per framework */
export function getControlCounts(): Record<ComplianceFramework, number> {
  return {
    pci_dss_4: PCI_DSS_CONTROLS.length,
    iso_27001: ISO_27001_CONTROLS.length,
    soc2_type2: SOC2_CONTROLS.length,
    lfpdppp: LFPDPPP_CONTROLS.length,
    gdpr: GDPR_CONTROLS.length,
    nist_800_53: NIST_800_53_CONTROLS.length,
    nist_csf: NIST_CSF_CONTROLS.length,
    infra_baseline: INFRA_BASELINE_CONTROLS.length,
  };
}

/** Get all permissions required across ALL controls for given frameworks */
export function getRequiredPermissions(
  frameworks: ComplianceFramework[],
): string[] {
  const perms = new Set<string>();
  for (const fw of frameworks) {
    for (const ctrl of getControlsForFramework(fw)) {
      for (const p of ctrl.required_permissions) {
        perms.add(p);
      }
    }
  }
  return [...perms];
}

/** Count controls limited by missing permissions */
export function countControlsLimitedByPermissions(
  frameworks: ComplianceFramework[],
  availablePermissions: string[],
): number {
  let count = 0;
  for (const fw of frameworks) {
    for (const ctrl of getControlsForFramework(fw)) {
      const needsPerm = ctrl.required_permissions.some(
        (p) => !availablePermissions.includes(p),
      );
      if (needsPerm) count++;
    }
  }
  return count;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Preview Controls (5 sample controls for free teaser in audit report)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** IDs of the preview controls used for the free compliance preview (1 per framework) */
const PREVIEW_CONTROL_IDS: Record<ComplianceFramework, string> = {
  pci_dss_4: 'PCI-4.2.1',           // SSL mode (high impact, easy to understand)
  iso_27001: 'ISO-A.8.24',          // Use of cryptography
  soc2_type2: 'SOC2-CC6.7',         // Data transmission security
  lfpdppp: 'LFPDPPP-19.III',        // Technical encryption measures
  gdpr: 'GDPR-32.1.a',             // Encryption of personal data
  nist_800_53: 'NIST-800-53-SC-8',  // Transmission confidentiality
  nist_csf: 'NIST-CSF-PR.DS-2',    // Data-in-transit protected
  infra_baseline: 'INFRA-TLS-001',  // TLS baseline
};

/**
 * Generate the free compliance preview that appears in every Pro/Complete audit report.
 * Evaluates 5 sample controls (1 per framework) using audit data only.
 */
export function generateCompliancePreview(
  ctx: EvaluationContext,
): CompliancePreview {
  const controls: CompliancePreviewControl[] = [];

  for (const [fw, ctrlId] of Object.entries(PREVIEW_CONTROL_IDS)) {
    const framework = fw as ComplianceFramework;
    const definition = getControlById(ctrlId);
    if (!definition) continue;

    try {
      const evaluation = definition.evaluate(ctx);
      controls.push({
        framework,
        framework_name: FRAMEWORK_INFO[framework].name,
        control_id: definition.control_id,
        title: definition.title,
        clause: definition.regulatory_reference.clause,
        status: evaluation.status,
        severity: definition.severity,
        current_value: evaluation.evidence.current_value,
        expected_value: evaluation.evidence.expected_value,
      });
    } catch {
      // If evaluation fails, show as insufficient permissions
      controls.push({
        framework,
        framework_name: FRAMEWORK_INFO[framework].name,
        control_id: definition.control_id,
        title: definition.title,
        clause: definition.regulatory_reference.clause,
        status: 'insufficient_permissions',
        severity: definition.severity,
        current_value: 'N/A',
        expected_value: 'N/A',
      });
    }
  }

  return {
    controls,
    total_mappable_controls: ALL_CONTROLS.length,
    frameworks_available: ['pci_dss_4', 'iso_27001', 'soc2_type2', 'lfpdppp', 'gdpr', 'nist_800_53', 'nist_csf', 'infra_baseline'],
    requires_pro_or_complete: true,
  };
}
