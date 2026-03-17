/**
 * Anga AutoFix - Remediation Engine
 * 
 * Maps compliance controls to Cloudflare API calls for automated remediation.
 * Supports previewing changes before execution and automatic rollback on failure.
 */

import type { ControlResult, ComplianceFramework, BiStr } from '../../types/compliance';
import type { CloudflarePlanTier } from '../../types/audit';
import type {
  RemediationAction,
  RemediationPreviewResponse,
  RemediationExecutionRequest,
  RemediationExecutionResponse,
  RemediationExecutionResult,
} from '../../types/remediation';
import { REMEDIATION_CREDIT_COST } from '../../types/remediation';

// ══════════════════════════════════════════════════════════════════
// Remediation Mappings
// ══════════════════════════════════════════════════════════════════

interface RemediationMapping {
  /** Which control IDs this mapping handles */
  control_patterns: string[];
  
  /** Generate remediation action(s) for a control */
  generate: (ctrl: ControlResult, zoneId: string) => RemediationAction[];
}

const REMEDIATION_MAPPINGS: RemediationMapping[] = [
  // ════════════════════════════════════════════════════════════════════════════
  // SECURITY LEVEL - CC6.1, CC6.3, A1.2 (SOC2)
  // API: PATCH /zones/{zone_id}/settings/security_level
  // Values: off, essentially_off, low, medium, high, under_attack
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.1', 'CC6.3', 'A1.2', 'SOC2-CC6'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      // If already high or under_attack, no action needed
      if (current.includes('high') || current.includes('under_attack')) return [];
      
      return [{
        action_id: `security-level-high-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Aumentar nivel de seguridad a Alto', en: 'Increase security level to High' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/security_level`,
        body: { value: 'high' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value,
        new_value: 'high',
        impact_description: {
          es: 'Aumenta el nivel de seguridad a Alto. Esto activa verificaciones mas estrictas para visitantes sospechosos. Puede mostrar CAPTCHAs a mas usuarios.',
          en: 'Increases security level to High. This enables stricter checks for suspicious visitors. May show CAPTCHAs to more users.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/security_level`,
        rollback_body: { value: 'medium' },
        frameworks_affected: ['soc2_type2', 'nist_800_53', 'iso_27001'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/security-level/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // SSL MODE - CC6.7 (SOC2), PCI, ISO, NIST
  // API: PATCH /zones/{zone_id}/settings/ssl
  // Values: off, flexible, full, strict
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7', 'PCI-4.2', 'NIST-SC-8', 'ISO-A.10.1.1', 'SOC2-CC6.7'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('strict')) return [];
      
      return [{
        action_id: `ssl-strict-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Actualizar modo SSL a Full (Strict)', en: 'Upgrade SSL mode to Full (Strict)' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/ssl`,
        body: { value: 'strict' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: false,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value,
        new_value: 'Full (Strict)',
        impact_description: {
          es: 'IMPORTANTE: Requiere certificado SSL valido en tu servidor origen. Verifica que tu servidor tenga un certificado SSL valido antes de aplicar.',
          en: 'IMPORTANT: Requires valid SSL certificate on your origin server. Verify your server has a valid SSL certificate before applying.',
        },
        risk_level: 'medium',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/ssl`,
        rollback_body: { value: 'full' },
        frameworks_affected: ['pci_dss_4', 'iso_27001', 'nist_800_53', 'soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // MINIMUM TLS VERSION - CC6.7 (SOC2), PCI, NIST
  // API: PATCH /zones/{zone_id}/settings/min_tls_version
  // Values: 1.0, 1.1, 1.2, 1.3
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7', 'NIST-SC-8', 'PCI-4.2.1', 'ISO-A.10.1.1'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('1.2') || current.includes('1.3')) return [];
      
      return [{
        action_id: `tls-upgrade-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Actualizar version minima de TLS a 1.2', en: 'Upgrade minimum TLS version to 1.2' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/min_tls_version`,
        body: { value: '1.2' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value,
        new_value: 'TLS 1.2',
        impact_description: {
          es: 'Actualiza la version minima de TLS a 1.2. Los navegadores muy antiguos (pre-2016) no podran conectarse.',
          en: 'Updates minimum TLS version to 1.2. Very old browsers (pre-2016) will not be able to connect.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/min_tls_version`,
        rollback_body: { value: '1.0' },
        frameworks_affected: ['pci_dss_4', 'iso_27001', 'nist_800_53', 'soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // HSTS (HTTP Strict Transport Security) - CC6.7 (SOC2)
  // API: PATCH /zones/{zone_id}/settings/security_header
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7', 'NIST-SC-8', 'PCI-4.2', 'ISO-A.14.1.2'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('hsts: on') || (current.includes('hsts') && current.includes('enabled'))) return [];
      
      return [{
        action_id: `hsts-enable-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar HSTS', en: 'Enable HSTS' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/security_header`,
        body: {
          value: {
            strict_transport_security: {
              enabled: true,
              max_age: 31536000,
              include_subdomains: true,
              preload: false,
            },
          },
        },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value || 'HSTS: off',
        new_value: 'HSTS: on (max-age: 1 year)',
        impact_description: {
          es: 'Habilita HSTS para forzar HTTPS. ADVERTENCIA: Una vez habilitado, los navegadores recordaran esta configuracion por 1 año.',
          en: 'Enables HSTS to force HTTPS. WARNING: Once enabled, browsers will remember this setting for 1 year.',
        },
        risk_level: 'medium',
        reversible: false,
        frameworks_affected: ['pci_dss_4', 'iso_27001', 'nist_800_53', 'soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // ALWAYS USE HTTPS
  // API: PATCH /zones/{zone_id}/settings/always_use_https
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7', 'PCI-4.2', 'NIST-SC-8', 'ISO-A.14.1.2'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('https: on') || current.includes('always_use_https: on')) return [];
      
      return [{
        action_id: `https-redirect-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar redireccion HTTPS', en: 'Enable HTTPS redirect' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/always_use_https`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: 'off',
        new_value: 'on',
        impact_description: {
          es: 'Redirige automaticamente todo el trafico HTTP a HTTPS.',
          en: 'Automatically redirects all HTTP traffic to HTTPS.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/always_use_https`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['pci_dss_4', 'iso_27001', 'nist_800_53', 'gdpr', 'soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // DNSSEC - CC6.6 (SOC2), NIST, ISO
  // API: PATCH /zones/{zone_id}/dnssec
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.6', 'INFRA-DNS-2', 'NIST-SC-20', 'ISO-A.13.1.1'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('dnssec: active') || current.includes('dnssec: enabled')) return [];
      
      return [{
        action_id: `dnssec-enable-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/dnssec`,
        body: { status: 'active' },
        expected_response_code: 200,
        required_permissions: ['DNS:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value || 'inactive',
        new_value: 'active',
        impact_description: {
          es: 'Habilita DNSSEC. NOTA: Despues de habilitar, debes agregar el registro DS en tu registrador de dominio.',
          en: 'Enables DNSSEC. NOTE: After enabling, you must add the DS record at your domain registrar.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/dnssec`,
        rollback_body: { status: 'inactive' },
        frameworks_affected: ['nist_800_53', 'iso_27001', 'soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/dns/dnssec/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // WAF MANAGED RULES - CC6.6, A1.2 (SOC2), PCI, NIST
  // API: PUT /zones/{zone_id}/rulesets/phases/http_request_firewall_managed/entrypoint
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.6', 'A1.2', 'PCI-6.4.3', 'NIST-SI-3', 'ISO-A.12.2.1'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('waf: active') || current.includes('waf: enabled') || current.includes('waf managed: active')) return [];
      
      return [{
        action_id: `waf-managed-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar WAF Managed Rules', en: 'Enable WAF Managed Rules' },
        method: 'PUT',
        endpoint: `/zones/${zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint`,
        body: {
          rules: [
            {
              action: 'execute',
              action_parameters: {
                id: 'efb7b8c949ac4650a09736fc376e9aee',
                overrides: { enabled: true },
              },
              expression: 'true',
              description: 'Enable Cloudflare Managed Ruleset',
              enabled: true,
            },
          ],
        },
        expected_response_code: 200,
        required_permissions: ['Firewall Services:Edit'],
        requires_plan: 'pro',
        safe_to_automate: false,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value || 'WAF: inactive',
        new_value: 'WAF Managed Rules: active',
        impact_description: {
          es: 'PRECAUCION: Puede bloquear trafico legitimo. Habilita las reglas WAF administradas de Cloudflare. Monitorea despues de activar.',
          en: 'CAUTION: May block legitimate traffic. Enables Cloudflare managed WAF rules. Monitor after activation.',
        },
        risk_level: 'medium',
        reversible: true,
        frameworks_affected: ['pci_dss_4', 'nist_800_53', 'soc2_type2', 'iso_27001'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // BROWSER INTEGRITY CHECK - CC6.8 (SOC2)
  // API: PATCH /zones/{zone_id}/settings/browser_check
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.8', 'SOC2-CC6.8'],
    generate: (ctrl, zoneId) => {
      const current = ctrl.evidence.current_value.toLowerCase();
      if (current.includes('browser_check: on') || current.includes('browser integrity: on')) return [];
      
      return [{
        action_id: `browser-check-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar Browser Integrity Check', en: 'Enable Browser Integrity Check' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/browser_check`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: ctrl.evidence.current_value || 'off',
        new_value: 'on',
        impact_description: {
          es: 'Verifica la integridad del navegador y bloquea solicitudes con encabezados HTTP malformados.',
          en: 'Checks browser integrity and blocks requests with malformed HTTP headers.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/browser_check`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/browser-integrity-check/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // EMAIL OBFUSCATION - Helps with security
  // API: PATCH /zones/{zone_id}/settings/email_obfuscation
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.8'],
    generate: (ctrl, zoneId) => {
      return [{
        action_id: `email-obfuscation-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar ofuscacion de email', en: 'Enable email obfuscation' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/email_obfuscation`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: 'off',
        new_value: 'on',
        impact_description: {
          es: 'Ofusca direcciones de email en tu sitio para prevenir spam.',
          en: 'Obfuscates email addresses on your site to prevent spam.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/email_obfuscation`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // HOTLINK PROTECTION
  // API: PATCH /zones/{zone_id}/settings/hotlink_protection
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.8'],
    generate: (ctrl, zoneId) => {
      return [{
        action_id: `hotlink-protection-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar proteccion de hotlink', en: 'Enable hotlink protection' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/hotlink_protection`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: 'off',
        new_value: 'on',
        impact_description: {
          es: 'Previene que otros sitios enlacen directamente a tus imagenes.',
          en: 'Prevents other sites from directly linking to your images.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/hotlink_protection`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['soc2_type2'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/scrape-shield/hotlink-protection/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // OPPORTUNISTIC ENCRYPTION
  // API: PATCH /zones/{zone_id}/settings/opportunistic_encryption
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7'],
    generate: (ctrl, zoneId) => {
      return [{
        action_id: `opportunistic-encryption-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar Opportunistic Encryption', en: 'Enable Opportunistic Encryption' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/opportunistic_encryption`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: 'off',
        new_value: 'on',
        impact_description: {
          es: 'Permite cifrado oportunista para navegadores que lo soporten.',
          en: 'Enables opportunistic encryption for browsers that support it.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/opportunistic_encryption`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['soc2_type2', 'pci_dss_4'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/opportunistic-encryption/',
      }];
    },
  },

  // ════════════════════════════════════════════════════════════════════════════
  // AUTOMATIC HTTPS REWRITES
  // API: PATCH /zones/{zone_id}/settings/automatic_https_rewrites
  // ════════════════════════════════════════════════════════════════════════════
  {
    control_patterns: ['CC6.7'],
    generate: (ctrl, zoneId) => {
      return [{
        action_id: `auto-https-rewrites-${ctrl.control_id}`,
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: { es: 'Habilitar reescritura automatica HTTPS', en: 'Enable automatic HTTPS rewrites' },
        method: 'PATCH',
        endpoint: `/zones/${zoneId}/settings/automatic_https_rewrites`,
        body: { value: 'on' },
        expected_response_code: 200,
        required_permissions: ['Zone Settings:Edit'],
        requires_plan: 'free',
        safe_to_automate: true,
        credit_cost: REMEDIATION_CREDIT_COST,
        current_value: 'off',
        new_value: 'on',
        impact_description: {
          es: 'Reescribe automaticamente enlaces HTTP a HTTPS en tu contenido.',
          en: 'Automatically rewrites HTTP links to HTTPS in your content.',
        },
        risk_level: 'low',
        reversible: true,
        rollback_endpoint: `/zones/${zoneId}/settings/automatic_https_rewrites`,
        rollback_body: { value: 'off' },
        frameworks_affected: ['soc2_type2', 'pci_dss_4'],
        cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/',
      }];
    },
  },
];

// ══════════════════════════════════════════════════════════════════
// Engine Functions
// ══════════════════════════════════════════════════════════════════

/**
 * Generate remediation actions from a list of controls
 */
export function generateRemediationActions(
  controls: ControlResult[],
  zoneId: string,
): RemediationAction[] {
  const actions: RemediationAction[] = [];
  const processedControlIds = new Set<string>();
  
  for (const ctrl of controls) {
    // Only process failed/partial controls that can be automated
    if (ctrl.status !== 'fail' && ctrl.status !== 'partial') continue;
    if (!ctrl.remediation.can_be_automated) continue;
    
    // Find matching mapping
    for (const mapping of REMEDIATION_MAPPINGS) {
      const matches = mapping.control_patterns.some(pattern => 
        ctrl.control_id.includes(pattern) || ctrl.control_ref.includes(pattern)
      );
      
      if (matches && !processedControlIds.has(ctrl.control_id)) {
        const generatedActions = mapping.generate(ctrl, zoneId);
        actions.push(...generatedActions);
        processedControlIds.add(ctrl.control_id);
      }
    }
  }
  
  return actions;
}

/**
 * Generate preview of all available remediation actions
 */
export async function previewRemediation(
  controls: ControlResult[],
  zoneId: string,
  zoneName: string,
  apiToken: string,
  currentPlan: CloudflarePlanTier,
  availablePermissions: string[],
): Promise<RemediationPreviewResponse> {
  const actions = generateRemediationActions(controls, zoneId);
  
  // Check permissions
  const allRequiredPerms = new Set<string>();
  for (const action of actions) {
    action.required_permissions.forEach(p => allRequiredPerms.add(p));
  }
  const missingPermissions = [...allRequiredPerms].filter(
    p => !availablePermissions.includes(p)
  );
  
  // Check plan requirements
  const planOrder: Record<CloudflarePlanTier, number> = { free: 0, pro: 1, business: 2, enterprise: 3 };
  const planUpgradeRequired = actions.some(a => planOrder[a.requires_plan] > planOrder[currentPlan]);
  const requiredPlan = planUpgradeRequired
    ? actions.reduce((max, a) => planOrder[a.requires_plan] > planOrder[max] ? a.requires_plan : max, 'free' as CloudflarePlanTier)
    : undefined;
  
  // Generate warnings
  const warnings: string[] = [];
  const highRiskActions = actions.filter(a => a.risk_level === 'high');
  const mediumRiskActions = actions.filter(a => a.risk_level === 'medium');
  const irreversibleActions = actions.filter(a => !a.reversible);
  
  if (highRiskActions.length > 0) {
    warnings.push(`${highRiskActions.length} high-risk action(s) require careful review before execution.`);
  }
  if (mediumRiskActions.length > 0) {
    warnings.push(`${mediumRiskActions.length} medium-risk action(s) may affect traffic. Monitor after applying.`);
  }
  if (irreversibleActions.length > 0) {
    warnings.push(`${irreversibleActions.length} action(s) cannot be easily reversed (e.g., HSTS).`);
  }
  
  // Calculate totals
  const totalCost = actions.reduce((sum, a) => sum + a.credit_cost, 0);
  const estimatedDuration = 
    actions.length <= 3 ? '1-2 minutes' :
    actions.length <= 10 ? '3-5 minutes' : '5-10 minutes';
  
  return {
    zone_id: zoneId,
    zone_name: zoneName,
    actions,
    total_cost: totalCost,
    estimated_duration: estimatedDuration,
    permissions_check: {
      all_permissions_available: missingPermissions.length === 0,
      missing_permissions: missingPermissions,
    },
    plan_check: {
      current_plan: currentPlan,
      plan_upgrade_required: planUpgradeRequired,
      required_plan: requiredPlan,
    },
    warnings,
    summary: {
      total_actions: actions.length,
      quick_fixes: actions.filter(a => a.risk_level === 'low' && a.safe_to_automate).length,
      high_risk: highRiskActions.length + mediumRiskActions.length,
      irreversible: irreversibleActions.length,
    },
  };
}

/**
 * Execute selected remediation actions
 */
export async function executeRemediation(
  request: RemediationExecutionRequest,
  availableActions: RemediationAction[],
): Promise<RemediationExecutionResponse> {
  const executionId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  
  const results: RemediationExecutionResult[] = [];
  let creditsCharged = 0;
  let creditsRefunded = 0;
  
  // Filter to only requested actions
  const actionsToExecute = availableActions.filter(a => 
    request.action_ids.includes(a.action_id)
  );
  
  // Execute actions sequentially
  for (const action of actionsToExecute) {
    const actionStart = Date.now();
    
    try {
      const url = `https://api.cloudflare.com/client/v4${action.endpoint}`;
      
      const response = await fetch(url, {
        method: action.method,
        headers: {
          'Authorization': `Bearer ${request.api_token}`,
          'Content-Type': 'application/json',
        },
        body: action.body ? JSON.stringify(action.body) : undefined,
      });
      
      const data = await response.json() as { success: boolean; errors?: { message: string }[] };
      
      if (response.status === action.expected_response_code && data.success) {
        results.push({
          action_id: action.action_id,
          control_id: action.control_id,
          status: 'success',
          message: `Successfully applied: ${action.new_value}`,
          api_response: data as unknown as Record<string, unknown>,
          duration_ms: Date.now() - actionStart,
        });
        creditsCharged += action.credit_cost;
      } else {
        results.push({
          action_id: action.action_id,
          control_id: action.control_id,
          status: 'failed',
          message: `Failed to apply fix`,
          error: data.errors?.[0]?.message || `HTTP ${response.status}`,
          duration_ms: Date.now() - actionStart,
        });
        creditsRefunded += action.credit_cost; // Refund on failure
      }
      
    } catch (error) {
      results.push({
        action_id: action.action_id,
        control_id: action.control_id,
        status: 'failed',
        message: 'Exception during execution',
        error: error instanceof Error ? error.message : 'Unknown error',
        duration_ms: Date.now() - actionStart,
      });
      creditsRefunded += action.credit_cost;
    }
  }
  
  const completedAt = new Date().toISOString();
  
  const summary = {
    total: results.length,
    succeeded: results.filter(r => r.status === 'success').length,
    failed: results.filter(r => r.status === 'failed').length,
    skipped: results.filter(r => r.status === 'skipped').length,
  };
  
  // Generate recommendations
  const recommendations: string[] = [];
  if (summary.succeeded > 0) {
    recommendations.push('Run compliance analysis again to verify the fixes have improved your score.');
  }
  if (summary.failed > 0) {
    recommendations.push('Review failed actions - they may require manual configuration or different permissions.');
  }
  
  return {
    execution_id: executionId,
    started_at: startedAt,
    completed_at: completedAt,
    results,
    summary,
    credits_charged: creditsCharged,
    credits_refunded: creditsRefunded,
    recommendations,
  };
}
