/**
 * Anga Security — Infrastructure Baseline Framework Controls
 *
 * 16 controls covering practical Cloudflare security hardening.
 * Issuing body: Anga Security (internal framework)
 *
 * Sections: TLS (encryption), WAF (firewall), DNS (domain security),
 * HEADERS (security headers), RATE (rate limiting), DDOS (DDoS protection),
 * ACCESS (access control), CACHE (cache security)
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, getHsts, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules } from './helpers';

export const INFRA_BASELINE_CONTROLS: FrameworkControl[] = [

  // ================================================================
  // TLS — Transport Layer Security
  // ================================================================
  {
    control_id: 'INFRA-TLS-001',
    control_ref: 'TLS-001',
    framework: 'infra_baseline',
    section_id: 'tls',
    title: { es: 'TLS-001: SSL modo Full (Strict)', en: 'TLS-001: SSL Full (Strict) Mode' },
    description: {
      es: 'El modo SSL debe ser Full (Strict) para cifrar el tráfico de extremo a extremo y validar el certificado del servidor de origen.',
      en: 'SSL mode must be Full (Strict) to encrypt end-to-end traffic and validate the origin server certificate.',
    },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'TLS: Seguridad de Transporte', en: 'TLS: Transport Security' },
      clause: 'TLS-001',
      official_text: {
        es: 'La conexión entre Cloudflare y el servidor de origen debe usar SSL en modo Full (Strict) para garantizar cifrado completo y autenticación del origen.',
        en: 'The connection between Cloudflare and the origin server must use SSL in Full (Strict) mode to ensure full encryption and origin authentication.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > SSL/TLS > Overview. Seleccionar "Full (Strict)".',
        en: 'In Cloudflare: Dashboard > SSL/TLS > Overview. Select "Full (Strict)".',
      },
      source_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/',
    },
    required_data_sources: ['zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
    ],
    remediation_template: {
      summary: { es: 'Cambiar modo SSL a Full (Strict)', en: 'Change SSL mode to Full (Strict)' },
      risk_if_ignored: {
        es: 'Con modo Flexible o sin SSL, el tráfico entre Cloudflare y el origen puede ser interceptado.',
        en: 'With Flexible mode or no SSL, traffic between Cloudflare and the origin can be intercepted.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Ir a SSL/TLS > Overview', en: 'Go to SSL/TLS > Overview' },
          where: { es: 'Dashboard > SSL/TLS > Overview', en: 'Dashboard > SSL/TLS > Overview' },
          detail: { es: 'Seleccionar la opción "Full (Strict)".', en: 'Select the "Full (Strict)" option.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const sslMode = s(ctx, 'ssl');
      if (sslMode === 'strict') return ev('pass', 100, sslMode, 'strict', 'SSL Full (Strict) mode is enabled.', ['zone_settings']);
      if (sslMode === 'full') return ev('partial', 60, sslMode, 'strict', 'SSL is Full but not Strict. Origin certificate is not validated.', ['zone_settings']);
      if (sslMode === 'flexible') return ev('fail', 20, sslMode, 'strict', 'SSL Flexible mode — traffic from CF to origin is unencrypted.', ['zone_settings']);
      if (sslMode === 'off') return ev('fail', 0, 'off', 'strict', 'SSL is disabled — all traffic is unencrypted.', ['zone_settings']);
      return ev('fail', 0, sslMode ?? 'unknown', 'strict', 'SSL mode could not be determined.', ['zone_settings']);
    },
  },

  {
    control_id: 'INFRA-TLS-002',
    control_ref: 'TLS-002',
    framework: 'infra_baseline',
    section_id: 'tls',
    title: { es: 'TLS-002: Versión mínima TLS 1.2', en: 'TLS-002: Minimum TLS Version 1.2' },
    description: {
      es: 'La versión mínima de TLS aceptada debe ser 1.2 o superior para evitar protocolos obsoletos vulnerables.',
      en: 'The minimum accepted TLS version must be 1.2 or higher to avoid vulnerable legacy protocols.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'TLS: Seguridad de Transporte', en: 'TLS: Transport Security' },
      clause: 'TLS-002',
      official_text: {
        es: 'TLS 1.0 y 1.1 contienen vulnerabilidades conocidas (POODLE, BEAST). Solo se deben aceptar conexiones TLS 1.2 o superiores.',
        en: 'TLS 1.0 and 1.1 contain known vulnerabilities (POODLE, BEAST). Only TLS 1.2 or higher connections should be accepted.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > SSL/TLS > Certificados Edge > Versión TLS mínima.',
        en: 'In Cloudflare: Dashboard > SSL/TLS > Edge Certificates > Minimum TLS Version.',
      },
      source_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
    },
    required_data_sources: ['zone_settings.min_tls_version'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
    ],
    remediation_template: {
      summary: { es: 'Establecer versión mínima TLS en 1.2', en: 'Set minimum TLS version to 1.2' },
      risk_if_ignored: {
        es: 'TLS 1.0/1.1 son vulnerables a ataques POODLE y BEAST que permiten descifrar sesiones.',
        en: 'TLS 1.0/1.1 are vulnerable to POODLE and BEAST attacks that allow decrypting sessions.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Establecer TLS mínimo a 1.2', en: 'Set minimum TLS to 1.2' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: { es: 'En "Versión TLS mínima", seleccionar TLS 1.2.', en: 'Under "Minimum TLS Version", select TLS 1.2.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const minTls = s(ctx, 'min_tls_version');
      if (minTls === '1.3') return ev('pass', 100, minTls, '1.2+', 'Minimum TLS 1.3 — excellent.', ['zone_settings']);
      if (minTls === '1.2') return ev('pass', 90, minTls, '1.2+', 'Minimum TLS 1.2 — compliant.', ['zone_settings']);
      if (minTls === '1.1') return ev('fail', 30, minTls, '1.2+', 'TLS 1.1 is deprecated and vulnerable.', ['zone_settings']);
      if (minTls === '1.0') return ev('fail', 0, minTls, '1.2+', 'TLS 1.0 is deprecated and vulnerable (POODLE, BEAST).', ['zone_settings']);
      return ev('fail', 0, minTls ?? 'unknown', '1.2+', 'Minimum TLS version could not be determined.', ['zone_settings']);
    },
  },

  {
    control_id: 'INFRA-TLS-003',
    control_ref: 'TLS-003',
    framework: 'infra_baseline',
    section_id: 'tls',
    title: { es: 'TLS-003: HTTPS siempre activo', en: 'TLS-003: Always Use HTTPS' },
    description: {
      es: 'Redirigir automáticamente todo el tráfico HTTP a HTTPS para garantizar que las conexiones sean siempre cifradas.',
      en: 'Automatically redirect all HTTP traffic to HTTPS to ensure connections are always encrypted.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'TLS: Seguridad de Transporte', en: 'TLS: Transport Security' },
      clause: 'TLS-003',
      official_text: {
        es: 'Todo el tráfico web debe ser redirigido a HTTPS para evitar transmisión de datos en texto claro.',
        en: 'All web traffic must be redirected to HTTPS to avoid transmitting data in clear text.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > SSL/TLS > Certificados Edge > "Siempre usar HTTPS".',
        en: 'In Cloudflare: Dashboard > SSL/TLS > Edge Certificates > "Always Use HTTPS".',
      },
      source_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
    },
    required_data_sources: ['zone_settings.always_use_https'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar "Siempre usar HTTPS"', en: 'Enable "Always Use HTTPS"' },
      risk_if_ignored: {
        es: 'Sin redirección HTTP→HTTPS, los usuarios pueden acceder al sitio sin cifrado, exponiendo sus datos.',
        en: 'Without HTTP→HTTPS redirect, users may access the site without encryption, exposing their data.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar "Siempre usar HTTPS"', en: 'Enable "Always Use HTTPS"' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: { es: 'Activar el toggle "Siempre usar HTTPS".', en: 'Enable the "Always Use HTTPS" toggle.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const alwaysHttps = s(ctx, 'always_use_https');
      if (alwaysHttps === 'on') return ev('pass', 100, 'on', 'on', 'Always Use HTTPS is enabled.', ['zone_settings']);
      return ev('fail', 0, alwaysHttps ?? 'off', 'on', 'HTTP traffic is not automatically redirected to HTTPS.', ['zone_settings']);
    },
  },

  {
    control_id: 'INFRA-TLS-004',
    control_ref: 'TLS-004',
    framework: 'infra_baseline',
    section_id: 'tls',
    title: { es: 'TLS-004: HSTS configurado', en: 'TLS-004: HSTS Configured' },
    description: {
      es: 'HTTP Strict Transport Security (HSTS) debe estar configurado con un max-age adecuado para prevenir ataques de downgrade.',
      en: 'HTTP Strict Transport Security (HSTS) must be configured with adequate max-age to prevent downgrade attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'TLS: Seguridad de Transporte', en: 'TLS: Transport Security' },
      clause: 'TLS-004',
      official_text: {
        es: 'HSTS instruye al navegador a conectarse siempre vía HTTPS durante el período de max-age. Recomendado: al menos 6 meses (15768000s).',
        en: 'HSTS instructs browsers to always connect via HTTPS for the max-age period. Recommended: at least 6 months (15768000s).',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > SSL/TLS > Certificados Edge > HTTP Strict Transport Security (HSTS).',
        en: 'In Cloudflare: Dashboard > SSL/TLS > Edge Certificates > HTTP Strict Transport Security (HSTS).',
      },
      source_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
    ],
    remediation_template: {
      summary: { es: 'Configurar HSTS con max-age >= 6 meses', en: 'Configure HSTS with max-age >= 6 months' },
      risk_if_ignored: {
        es: 'Sin HSTS, los navegadores pueden ser engañados para conectarse vía HTTP en ataques SSL stripping.',
        en: 'Without HSTS, browsers can be tricked into connecting via HTTP in SSL stripping attacks.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar HSTS', en: 'Enable HSTS' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' },
          detail: { es: 'Activar HSTS con max-age de al menos 15768000 (6 meses).', en: 'Enable HSTS with max-age of at least 15768000 (6 months).' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      if (!hsts.enabled) return ev('fail', 0, 'disabled', 'enabled + max-age >= 15768000', 'HSTS is not enabled.', ['zone_settings']);
      if (hsts.max_age >= 31536000) return ev('pass', 100, `enabled, max-age=${hsts.max_age}`, 'enabled + max-age >= 31536000', 'HSTS configured with 1 year max-age — excellent.', ['zone_settings']);
      if (hsts.max_age >= 15768000) return ev('pass', 85, `enabled, max-age=${hsts.max_age}`, 'enabled + max-age >= 15768000', 'HSTS configured with adequate max-age (6+ months).', ['zone_settings']);
      return ev('partial', 40, `enabled, max-age=${hsts.max_age}`, 'max-age >= 15768000', `HSTS enabled but max-age too short (${hsts.max_age}s). Increase to at least 15768000.`, ['zone_settings']);
    },
  },

  // ================================================================
  // WAF — Web Application Firewall
  // ================================================================
  {
    control_id: 'INFRA-WAF-001',
    control_ref: 'WAF-001',
    framework: 'infra_baseline',
    section_id: 'waf',
    title: { es: 'WAF-001: WAF administrado activo', en: 'WAF-001: Managed WAF Active' },
    description: {
      es: 'El WAF administrado de Cloudflare con reglas OWASP debe estar activo para protección contra vulnerabilidades web comunes.',
      en: 'Cloudflare managed WAF with OWASP rules must be active to protect against common web vulnerabilities.',
    },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'WAF: Firewall de Aplicaciones Web', en: 'WAF: Web Application Firewall' },
      clause: 'WAF-001',
      official_text: {
        es: 'El firewall de aplicaciones web debe proteger contra el OWASP Top 10, incluyendo inyección SQL, XSS y RCE.',
        en: 'The web application firewall must protect against the OWASP Top 10, including SQL injection, XSS, and RCE.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Seguridad > WAF > Reglas administradas.',
        en: 'In Cloudflare: Dashboard > Security > WAF > Managed rules.',
      },
      source_url: 'https://developers.cloudflare.com/waf/managed-rules/',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-DE.CM-4', clause: 'DE.CM-4' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
    ],
    remediation_template: {
      summary: { es: 'Activar WAF administrado con reglas OWASP', en: 'Enable managed WAF with OWASP rules' },
      risk_if_ignored: {
        es: 'Sin WAF, el sitio es vulnerable a SQL injection, XSS, RCE y otras vulnerabilidades del OWASP Top 10.',
        en: 'Without WAF, the site is vulnerable to SQL injection, XSS, RCE, and other OWASP Top 10 vulnerabilities.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar Cloudflare Managed Ruleset', en: 'Enable Cloudflare Managed Ruleset' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' },
          detail: { es: 'Activar "Cloudflare Managed Ruleset" y "Cloudflare OWASP Core Ruleset".', en: 'Enable "Cloudflare Managed Ruleset" and "Cloudflare OWASP Core Ruleset".' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const managed = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);
      if (managed && owasp) return ev('pass', 100, 'managed WAF + OWASP active', 'managed WAF + OWASP', 'Managed WAF and OWASP ruleset are both active.', ['rulesets']);
      if (managed) return ev('partial', 60, 'managed WAF active, no OWASP', 'managed WAF + OWASP', 'Managed WAF is active but OWASP Core Ruleset is not enabled.', ['rulesets']);
      return ev('fail', 0, 'no managed WAF', 'managed WAF + OWASP', 'No managed WAF rules are deployed.', ['rulesets']);
    },
  },

  {
    control_id: 'INFRA-WAF-002',
    control_ref: 'WAF-002',
    framework: 'infra_baseline',
    section_id: 'waf',
    title: { es: 'WAF-002: Reglas WAF personalizadas', en: 'WAF-002: Custom WAF Rules' },
    description: {
      es: 'Deben existir reglas WAF personalizadas para protección adicional específica a la aplicación.',
      en: 'Custom WAF rules must exist for additional application-specific protection.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'WAF: Firewall de Aplicaciones Web', en: 'WAF: Web Application Firewall' },
      clause: 'WAF-002',
      official_text: {
        es: 'Las reglas WAF personalizadas permiten bloquear patrones de ataque específicos no cubiertos por las reglas administradas.',
        en: 'Custom WAF rules allow blocking specific attack patterns not covered by managed rules.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Seguridad > WAF > Reglas personalizadas.',
        en: 'In Cloudflare: Dashboard > Security > WAF > Custom rules.',
      },
      source_url: 'https://developers.cloudflare.com/waf/custom-rules/',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.2', clause: '1.3.2' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CM-6', clause: 'CM-6' },
    ],
    remediation_template: {
      summary: { es: 'Crear al menos una regla WAF personalizada', en: 'Create at least one custom WAF rule' },
      risk_if_ignored: {
        es: 'Sin reglas personalizadas, los ataques específicos a tu aplicación pueden no ser bloqueados.',
        en: 'Without custom rules, attacks specific to your application may not be blocked.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Crear regla WAF personalizada', en: 'Create custom WAF rule' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' },
          detail: { es: 'Crear reglas para bloquear bots, restringir acceso a áreas admin, o filtrar IPs maliciosas.', en: 'Create rules to block bots, restrict admin area access, or filter malicious IPs.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const customRules = getCustomWafRules(ctx);
      const activeRules = customRules.filter((r: any) => r.enabled !== false);
      if (activeRules.length >= 3) return ev('pass', 100, `${activeRules.length} custom rules`, '1+ custom rules', `${activeRules.length} active custom WAF rules found.`, ['rulesets']);
      if (activeRules.length >= 1) return ev('partial', 60, `${activeRules.length} custom rule(s)`, '3+ custom rules recommended', `Only ${activeRules.length} custom WAF rule(s). Consider adding more for better protection.`, ['rulesets']);
      return ev('fail', 0, 'no custom rules', '1+ custom rules', 'No custom WAF rules are configured.', ['rulesets']);
    },
  },

  // ================================================================
  // DNS — Domain Security
  // ================================================================
  {
    control_id: 'INFRA-DNS-001',
    control_ref: 'DNS-001',
    framework: 'infra_baseline',
    section_id: 'dns',
    title: { es: 'DNS-001: DNSSEC habilitado', en: 'DNS-001: DNSSEC Enabled' },
    description: {
      es: 'DNSSEC debe estar habilitado para proteger la integridad de las respuestas DNS y prevenir ataques de envenenamiento DNS.',
      en: 'DNSSEC must be enabled to protect DNS response integrity and prevent DNS poisoning attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'DNS: Seguridad del Dominio', en: 'DNS: Domain Security' },
      clause: 'DNS-001',
      official_text: {
        es: 'DNSSEC firma criptográficamente las respuestas DNS para prevenir su falsificación y redireccionamiento malicioso.',
        en: 'DNSSEC cryptographically signs DNS responses to prevent forgery and malicious redirection.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > DNS > Configuración > DNSSEC.',
        en: 'In Cloudflare: Dashboard > DNS > Settings > DNSSEC.',
      },
      source_url: 'https://developers.cloudflare.com/dns/dnssec/',
    },
    required_data_sources: ['dns_summary'],
    required_permissions: ['DNS:Read'],
    cross_references: [
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.AC-5', clause: 'PR.AC-5' },
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar DNSSEC en el panel de DNS', en: 'Enable DNSSEC in the DNS panel' },
      risk_if_ignored: {
        es: 'Sin DNSSEC, los atacantes pueden envenenar el caché DNS y redirigir a los usuarios a sitios maliciosos.',
        en: 'Without DNSSEC, attackers can poison the DNS cache and redirect users to malicious sites.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar DNSSEC', en: 'Enable DNSSEC' },
          where: { es: 'Dashboard > DNS > Configuración', en: 'Dashboard > DNS > Settings' },
          detail: { es: 'Hacer clic en "Habilitar DNSSEC" y agregar el registro DS en tu registrador de dominio.', en: 'Click "Enable DNSSEC" and add the DS record at your domain registrar.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/dns/dnssec/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled;
      if (dnssec === true) return ev('pass', 100, 'enabled', 'enabled', 'DNSSEC is enabled.', ['dns_summary']);
      return ev('fail', 0, 'disabled', 'enabled', 'DNSSEC is not enabled. DNS responses can be forged.', ['dns_summary']);
    },
  },

  // ================================================================
  // HEADERS — Security Headers
  // ================================================================
  {
    control_id: 'INFRA-HDR-001',
    control_ref: 'HDR-001',
    framework: 'infra_baseline',
    section_id: 'headers',
    title: { es: 'HDR-001: Content Security Policy (CSP)', en: 'HDR-001: Content Security Policy (CSP)' },
    description: {
      es: 'El header Content-Security-Policy debe estar configurado para prevenir ataques XSS y de inyección de contenido.',
      en: 'The Content-Security-Policy header must be configured to prevent XSS and content injection attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Headers: Cabeceras de Seguridad', en: 'Headers: Security Headers' },
      clause: 'HDR-001',
      official_text: {
        es: 'CSP restringe las fuentes desde las cuales el navegador puede cargar recursos, mitigando ataques XSS.',
        en: 'CSP restricts sources from which the browser can load resources, mitigating XSS attacks.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se verifica vía zone_settings security_header. Se puede configurar con Transform Rules.',
        en: 'In Cloudflare: Verified via zone_settings security_header. Can be configured with Transform Rules.',
      },
      source_url: 'https://developers.cloudflare.com/rules/transform/response-header-modification/',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Content-Security-Policy via Transform Rules', en: 'Configure Content-Security-Policy via Transform Rules' },
      risk_if_ignored: {
        es: 'Sin CSP, los ataques XSS pueden ejecutar scripts maliciosos en el contexto del navegador del usuario.',
        en: 'Without CSP, XSS attacks can execute malicious scripts in the user\'s browser context.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Crear Transform Rule para inyectar CSP', en: 'Create Transform Rule to inject CSP' },
          where: { es: 'Dashboard > Reglas > Transform Rules > Modificar headers de respuesta', en: 'Dashboard > Rules > Transform Rules > Modify response headers' },
          detail: { es: 'Agregar header Content-Security-Policy con política restrictiva. Ejemplo: default-src \'self\'', en: 'Add Content-Security-Policy header with restrictive policy. Example: default-src \'self\'' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/rules/transform/response-header-modification/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const header = s(ctx, 'security_header');
      const csp = header?.content_security_policy;
      if (csp?.enabled === true) return ev('pass', 100, 'CSP enabled', 'enabled', 'Content-Security-Policy header is configured.', ['zone_settings']);
      if (csp !== undefined) return ev('fail', 0, 'CSP disabled', 'enabled', 'Content-Security-Policy is configured but disabled.', ['zone_settings']);
      return ev('fail', 0, 'not configured', 'enabled', 'Content-Security-Policy is not configured.', ['zone_settings']);
    },
  },

  {
    control_id: 'INFRA-HDR-002',
    control_ref: 'HDR-002',
    framework: 'infra_baseline',
    section_id: 'headers',
    title: { es: 'HDR-002: X-Content-Type-Options nosniff', en: 'HDR-002: X-Content-Type-Options nosniff' },
    description: {
      es: 'El header X-Content-Type-Options con valor nosniff debe estar activo para prevenir que el navegador interprete incorrectamente el tipo MIME.',
      en: 'The X-Content-Type-Options header with nosniff must be active to prevent browsers from MIME type sniffing.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Headers: Cabeceras de Seguridad', en: 'Headers: Security Headers' },
      clause: 'HDR-002',
      official_text: {
        es: 'nosniff previene que el navegador interprete archivos como un tipo MIME diferente al declarado, evitando ataques de confusión de contenido.',
        en: 'nosniff prevents the browser from interpreting files as a different MIME type than declared, avoiding content confusion attacks.',
      },
      applicability_note: {
        es: 'En Cloudflare: Verificado vía zone_settings security_header.nosniff.',
        en: 'In Cloudflare: Verified via zone_settings security_header.nosniff.',
      },
      source_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-header/',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar nosniff en Security Headers', en: 'Enable nosniff in Security Headers' },
      risk_if_ignored: {
        es: 'Sin nosniff, el navegador puede ejecutar archivos maliciosos al interpretar su tipo MIME incorrectamente.',
        en: 'Without nosniff, the browser may execute malicious files by misinterpreting their MIME type.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar nosniff', en: 'Enable nosniff' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HTTP Strict Transport Security', en: 'Dashboard > SSL/TLS > Edge Certificates > HTTP Strict Transport Security' },
          detail: { es: 'Activar la opción "No-sniff header".', en: 'Enable the "No-sniff header" option.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-header/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      if (hsts.nosniff) return ev('pass', 100, 'nosniff: true', 'true', 'X-Content-Type-Options: nosniff is enabled.', ['zone_settings']);
      return ev('fail', 0, 'nosniff: false', 'true', 'X-Content-Type-Options nosniff is not enabled.', ['zone_settings']);
    },
  },

  // ================================================================
  // RATE — Rate Limiting
  // ================================================================
  {
    control_id: 'INFRA-RATE-001',
    control_ref: 'RATE-001',
    framework: 'infra_baseline',
    section_id: 'rate',
    title: { es: 'RATE-001: Rate limiting configurado', en: 'RATE-001: Rate Limiting Configured' },
    description: {
      es: 'Reglas de rate limiting deben estar configuradas para proteger contra ataques de fuerza bruta y DDoS a nivel aplicación.',
      en: 'Rate limiting rules must be configured to protect against brute force and application-level DDoS attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'RATE: Control de Velocidad', en: 'RATE: Rate Control' },
      clause: 'RATE-001',
      official_text: {
        es: 'El rate limiting protege los endpoints críticos (login, API, checkout) de ataques de fuerza bruta y abuso de volumen.',
        en: 'Rate limiting protects critical endpoints (login, API, checkout) from brute force and volume abuse attacks.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Seguridad > WAF > Reglas de rate limiting.',
        en: 'In Cloudflare: Dashboard > Security > WAF > Rate limiting rules.',
      },
      source_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-5', clause: 'SC-5' },
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.2', clause: '1.3.2' },
    ],
    remediation_template: {
      summary: { es: 'Crear reglas de rate limiting para endpoints críticos', en: 'Create rate limiting rules for critical endpoints' },
      risk_if_ignored: {
        es: 'Sin rate limiting, los atacantes pueden realizar ataques de fuerza bruta contra login y abusar APIs.',
        en: 'Without rate limiting, attackers can brute force login endpoints and abuse APIs.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Crear regla de rate limiting', en: 'Create rate limiting rule' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas de rate limiting', en: 'Dashboard > Security > WAF > Rate limiting rules' },
          detail: { es: 'Configurar rate limiting en /login, /api/* y /admin con umbrales razonables (ej: 10 req/min).', en: 'Configure rate limiting on /login, /api/* and /admin with reasonable thresholds (e.g. 10 req/min).' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const rlRules = getRateLimitRules(ctx);
      const activeRules = rlRules.filter((r: any) => r.enabled !== false);
      if (activeRules.length >= 2) return ev('pass', 100, `${activeRules.length} rate limit rules`, '1+ rules', `${activeRules.length} active rate limiting rules configured.`, ['rulesets']);
      if (activeRules.length === 1) return ev('partial', 60, '1 rate limit rule', '2+ rules recommended', 'Only 1 rate limiting rule. Consider adding more for critical endpoints.', ['rulesets']);
      return ev('fail', 0, 'no rate limit rules', '1+ rules', 'No rate limiting rules are configured.', ['rulesets']);
    },
  },

  // ================================================================
  // DDOS — DDoS Protection
  // ================================================================
  {
    control_id: 'INFRA-DDOS-001',
    control_ref: 'DDOS-001',
    framework: 'infra_baseline',
    section_id: 'ddos',
    title: { es: 'DDOS-001: Modo de seguridad activo', en: 'DDOS-001: Security Level Active' },
    description: {
      es: 'El nivel de seguridad de Cloudflare debe estar en Medium o superior para activar protecciones anti-DDoS y filtrado de IPs maliciosas.',
      en: 'Cloudflare security level must be Medium or higher to activate anti-DDoS protections and malicious IP filtering.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'DDOS: Protección contra DDoS', en: 'DDOS: DDoS Protection' },
      clause: 'DDOS-001',
      official_text: {
        es: 'El nivel de seguridad determina el umbral de desafío para visitantes con reputación de IP baja o IPs catalogadas como maliciosas.',
        en: 'Security level determines the challenge threshold for visitors with low IP reputation or IPs catalogued as malicious.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Seguridad > Configuración > Nivel de seguridad.',
        en: 'In Cloudflare: Dashboard > Security > Settings > Security Level.',
      },
      source_url: 'https://developers.cloudflare.com/fundamentals/reference/security-level/',
    },
    required_data_sources: ['zone_settings.security_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-5', clause: 'SC-5' },
    ],
    remediation_template: {
      summary: { es: 'Establecer nivel de seguridad en Medium o superior', en: 'Set security level to Medium or higher' },
      risk_if_ignored: {
        es: 'Un nivel de seguridad bajo permite que IPs con mala reputación accedan sin desafío.',
        en: 'A low security level allows IPs with bad reputation to access without challenge.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Cambiar nivel de seguridad', en: 'Change security level' },
          where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' },
          detail: { es: 'Seleccionar "Medium" o "High" en Nivel de seguridad.', en: 'Select "Medium" or "High" in Security Level.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/reference/security-level/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const level = s(ctx, 'security_level');
      if (level === 'high' || level === 'under_attack') return ev('pass', 100, level, 'medium+', `Security level "${level}" — maximum protection active.`, ['zone_settings']);
      if (level === 'medium') return ev('pass', 85, level, 'medium+', 'Security level "medium" — adequate protection.', ['zone_settings']);
      if (level === 'low') return ev('partial', 40, level, 'medium+', 'Security level "low" — minimal protection. Consider raising to "medium".', ['zone_settings']);
      if (level === 'essentially_off' || level === 'off') return ev('fail', 0, level, 'medium+', 'Security level is off — no IP reputation filtering active.', ['zone_settings']);
      return ev('partial', 50, level ?? 'unknown', 'medium+', 'Security level could not be determined.', ['zone_settings']);
    },
  },

  {
    control_id: 'INFRA-DDOS-002',
    control_ref: 'DDOS-002',
    framework: 'infra_baseline',
    section_id: 'ddos',
    title: { es: 'DDOS-002: Bot Fight Mode activo', en: 'DDOS-002: Bot Fight Mode Active' },
    description: {
      es: 'Bot Fight Mode debe estar activo para detectar y desafiar tráfico automatizado malicioso.',
      en: 'Bot Fight Mode must be active to detect and challenge malicious automated traffic.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'DDOS: Protección contra DDoS', en: 'DDOS: DDoS Protection' },
      clause: 'DDOS-002',
      official_text: {
        es: 'Bot Fight Mode identifica y bloquea bots maliciosos conocidos antes de que lleguen al servidor de origen.',
        en: 'Bot Fight Mode identifies and blocks known malicious bots before they reach the origin server.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Seguridad > Bots.',
        en: 'In Cloudflare: Dashboard > Security > Bots.',
      },
      source_url: 'https://developers.cloudflare.com/bots/get-started/free/',
    },
    required_data_sources: ['zone_settings.bot_fight_mode'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_csf', control_id: 'NIST-CSF-DE.CM-4', clause: 'DE.CM-4' },
    ],
    remediation_template: {
      summary: { es: 'Activar Bot Fight Mode', en: 'Enable Bot Fight Mode' },
      risk_if_ignored: {
        es: 'Sin protección contra bots, el sitio es vulnerable a scraping, credential stuffing y ataques automatizados.',
        en: 'Without bot protection, the site is vulnerable to scraping, credential stuffing, and automated attacks.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar Bot Fight Mode', en: 'Enable Bot Fight Mode' },
          where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' },
          detail: { es: 'Activar el toggle "Bot Fight Mode".', en: 'Enable the "Bot Fight Mode" toggle.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/bots/get-started/free/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const bfm = s(ctx, 'bot_fight_mode');
      if (bfm === 'on') return ev('pass', 100, 'on', 'on', 'Bot Fight Mode is active.', ['zone_settings']);
      return ev('fail', 0, bfm ?? 'off', 'on', 'Bot Fight Mode is not enabled.', ['zone_settings']);
    },
  },

  // ================================================================
  // ACCESS — Access Control
  // ================================================================
  {
    control_id: 'INFRA-ACC-001',
    control_ref: 'ACC-001',
    framework: 'infra_baseline',
    section_id: 'access',
    title: { es: 'ACC-001: HTTPS automático activado', en: 'ACC-001: Automatic HTTPS Rewrites' },
    description: {
      es: 'Las reescrituras automáticas de HTTPS deben estar activas para asegurar que todos los recursos de la página se carguen via HTTPS.',
      en: 'Automatic HTTPS rewrites must be active to ensure all page resources load over HTTPS.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'ACCESS: Control de Acceso', en: 'ACCESS: Access Control' },
      clause: 'ACC-001',
      official_text: {
        es: 'Las reescrituras automáticas de HTTPS modifican URLs de recursos mixtos para cargarlos via HTTPS, previniendo advertencias de contenido mixto.',
        en: 'Automatic HTTPS rewrites modify mixed content resource URLs to load them over HTTPS, preventing mixed content warnings.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > SSL/TLS > Certificados Edge > Reescrituras HTTPS automáticas.',
        en: 'In Cloudflare: Dashboard > SSL/TLS > Edge Certificates > Automatic HTTPS Rewrites.',
      },
      source_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/',
    },
    required_data_sources: ['zone_settings.automatic_https_rewrites'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CM-6', clause: 'CM-6' },
    ],
    remediation_template: {
      summary: { es: 'Activar reescrituras HTTPS automáticas', en: 'Enable automatic HTTPS rewrites' },
      risk_if_ignored: {
        es: 'Sin reescrituras automáticas, el contenido mixto puede exponer recursos a través de conexiones no cifradas.',
        en: 'Without automatic rewrites, mixed content may expose resources through unencrypted connections.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar reescrituras HTTPS automáticas', en: 'Enable automatic HTTPS rewrites' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: { es: 'Activar "Reescrituras HTTPS automáticas".', en: 'Enable "Automatic HTTPS Rewrites".' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const rewrites = s(ctx, 'automatic_https_rewrites');
      if (rewrites === 'on') return ev('pass', 100, 'on', 'on', 'Automatic HTTPS Rewrites are enabled.', ['zone_settings']);
      return ev('fail', 0, rewrites ?? 'off', 'on', 'Automatic HTTPS Rewrites are not enabled. Mixed content may occur.', ['zone_settings']);
    },
  },

  // ================================================================
  // CACHE — Cache Security
  // ================================================================
  {
    control_id: 'INFRA-CACHE-001',
    control_ref: 'CACHE-001',
    framework: 'infra_baseline',
    section_id: 'cache',
    title: { es: 'CACHE-001: Headers de seguridad en cache', en: 'CACHE-001: Security Headers in Cache' },
    description: {
      es: 'El cache de Cloudflare no debe almacenar páginas con datos sensibles sin el header Cache-Control: no-store.',
      en: 'Cloudflare cache must not store pages with sensitive data without Cache-Control: no-store header.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CACHE: Seguridad del Cache', en: 'CACHE: Cache Security' },
      clause: 'CACHE-001',
      official_text: {
        es: 'Las páginas con contenido sensible (panel admin, perfil de usuario, checkout) deben incluir Cache-Control: no-store para evitar su almacenamiento en caché.',
        en: 'Pages with sensitive content (admin panel, user profile, checkout) must include Cache-Control: no-store to prevent caching.',
      },
      applicability_note: {
        es: 'En Cloudflare: Verificar nivel de cache configurado. Nivel "Standard" es el correcto para la mayoría de sitios.',
        en: 'In Cloudflare: Verify configured cache level. "Standard" level is correct for most sites.',
      },
      source_url: 'https://developers.cloudflare.com/cache/concepts/cache-control/',
    },
    required_data_sources: ['zone_settings.cache_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'gdpr', control_id: 'GDPR-25.1', clause: 'Art. 25(1)' },
    ],
    remediation_template: {
      summary: { es: 'Verificar configuración de cache y nivel correcto', en: 'Verify cache configuration and correct level' },
      risk_if_ignored: {
        es: 'Un cache agresivo puede exponer datos personales de un usuario a otros visitantes.',
        en: 'Aggressive caching may expose one user\'s personal data to other visitors.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Verificar nivel de cache', en: 'Verify cache level' },
          where: { es: 'Dashboard > Cache > Configuración', en: 'Dashboard > Cache > Configuration' },
          detail: { es: 'Usar nivel "Standard". Agregar Cache Rules para excluir páginas sensibles.', en: 'Use "Standard" level. Add Cache Rules to exclude sensitive pages.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/cache/concepts/cache-control/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const cacheLevel = s(ctx, 'cache_level');
      if (cacheLevel === 'aggressive') return ev('partial', 40, cacheLevel, 'standard', 'Cache level is "aggressive" — may cache sensitive pages. Review Cache Rules.', ['zone_settings']);
      if (cacheLevel === 'basic') return ev('partial', 60, cacheLevel, 'standard', 'Cache level is "basic" — conservative but may miss performance.', ['zone_settings']);
      if (cacheLevel === 'simplified' || cacheLevel === 'standard') return ev('pass', 90, cacheLevel, 'standard', 'Cache level is appropriate.', ['zone_settings']);
      return ev('partial', 60, cacheLevel ?? 'unknown', 'standard', 'Cache level could not be determined.', ['zone_settings']);
    },
  },

  // ================================================================
  // AUDIT — Logging & Monitoring
  // ================================================================
  {
    control_id: 'INFRA-LOG-001',
    control_ref: 'LOG-001',
    framework: 'infra_baseline',
    section_id: 'logging',
    title: { es: 'LOG-001: Logs de seguridad configurados', en: 'LOG-001: Security Logging Configured' },
    description: {
      es: 'Los logs de firewall y HTTP deben estar configurados vía Logpush para auditoría y detección de incidentes.',
      en: 'Firewall and HTTP logs must be configured via Logpush for auditing and incident detection.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'LOG: Registro y Monitoreo', en: 'LOG: Logging and Monitoring' },
      clause: 'LOG-001',
      official_text: {
        es: 'Los registros de actividad de seguridad son esenciales para detectar incidentes, investigar brechas y cumplir con requisitos regulatorios de auditoría.',
        en: 'Security activity logs are essential for detecting incidents, investigating breaches, and meeting regulatory audit requirements.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Analytics & Logs > Logpush.',
        en: 'In Cloudflare: Dashboard > Analytics & Logs > Logpush.',
      },
      source_url: 'https://developers.cloudflare.com/logs/about/',
    },
    required_data_sources: ['logpush_jobs'],
    required_permissions: ['Logs:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-AU-2', clause: 'AU-2' },
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush para logs de firewall y HTTP', en: 'Configure Logpush for firewall and HTTP logs' },
      risk_if_ignored: {
        es: 'Sin logging, los ataques no pueden ser detectados, investigados ni cumplir con requisitos de auditoría regulatoria.',
        en: 'Without logging, attacks cannot be detected, investigated, or meet regulatory audit requirements.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Crear job de Logpush', en: 'Create Logpush job' },
          where: { es: 'Dashboard > Analytics & Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' },
          detail: { es: 'Configurar Logpush para firewall_events y http_requests hacia R2 o un SIEM.', en: 'Configure Logpush for firewall_events and http_requests to R2 or a SIEM.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/about/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const logpush = ctx.enriched_data?.logpush_jobs;
      if (!logpush) {
        if (!ctx.available_permissions.includes('Logs:Read')) {
          return ev('insufficient_permissions', 0, 'N/A', 'Requires permission: Logs:Read', 'Token lacks Logs:Read permission to evaluate logging configuration.', ['logpush_jobs']);
        }
        return ev('fail', 0, 'no logpush data', '1+ logpush jobs', 'No Logpush data available. Logging may not be configured.', ['logpush_jobs']);
      }
      const jobs = Array.isArray(logpush) ? logpush : [];
      const activeJobs = jobs.filter((j: any) => j.enabled !== false);
      const hasFirewall = activeJobs.some((j: any) => (j.dataset || '').includes('firewall'));
      const hasHttp = activeJobs.some((j: any) => (j.dataset || '').includes('http'));
      if (activeJobs.length > 0 && (hasFirewall || hasHttp)) return ev('pass', 100, `${activeJobs.length} logpush jobs (firewall: ${hasFirewall}, http: ${hasHttp})`, '1+ active logpush', 'Logpush logging is configured with relevant datasets.', ['logpush_jobs']);
      if (activeJobs.length > 0) return ev('partial', 60, `${activeJobs.length} logpush job(s), no firewall/http logs`, 'firewall + http logs', 'Logpush is configured but missing firewall or HTTP log datasets.', ['logpush_jobs']);
      return ev('fail', 0, 'no active logpush jobs', '1+ active jobs', 'No active Logpush jobs found.', ['logpush_jobs']);
    },
  },

  // ================================================================
  // PRIVACY — Privacy & Data Protection
  // ================================================================
  {
    control_id: 'INFRA-PRIV-001',
    control_ref: 'PRIV-001',
    framework: 'infra_baseline',
    section_id: 'privacy',
    title: { es: 'PRIV-001: Email Obfuscation activo', en: 'PRIV-001: Email Obfuscation Active' },
    description: {
      es: 'La ofuscación de email de Cloudflare debe estar activa para prevenir que los scrapers recolecten direcciones de email del sitio.',
      en: 'Cloudflare email obfuscation must be active to prevent scrapers from harvesting email addresses from the site.',
    },
    severity: 'low',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PRIV: Privacidad y Protección de Datos', en: 'PRIV: Privacy and Data Protection' },
      clause: 'PRIV-001',
      official_text: {
        es: 'La ofuscación de email reemplaza las direcciones de email visibles en HTML con código JavaScript obfuscado para dificultar su recolección automatizada.',
        en: 'Email obfuscation replaces visible email addresses in HTML with obfuscated JavaScript code to hinder automated harvesting.',
      },
      applicability_note: {
        es: 'En Cloudflare: Dashboard > Scrape Shield > Email Address Obfuscation.',
        en: 'In Cloudflare: Dashboard > Scrape Shield > Email Address Obfuscation.',
      },
      source_url: 'https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/',
    },
    required_data_sources: ['zone_settings.email_obfuscation'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'gdpr', control_id: 'GDPR-25.1', clause: 'Art. 25(1)' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19(III)' },
    ],
    remediation_template: {
      summary: { es: 'Activar Email Obfuscation', en: 'Enable Email Obfuscation' },
      risk_if_ignored: {
        es: 'Sin ofuscación, los emails del sitio pueden ser recolectados por bots y usados para spam o phishing.',
        en: 'Without obfuscation, site emails can be harvested by bots and used for spam or phishing.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Activar Email Obfuscation', en: 'Enable Email Obfuscation' },
          where: { es: 'Dashboard > Scrape Shield', en: 'Dashboard > Scrape Shield' },
          detail: { es: 'Activar "Email Address Obfuscation".', en: 'Enable "Email Address Obfuscation".' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const obf = s(ctx, 'email_obfuscation');
      if (obf === 'on') return ev('pass', 100, 'on', 'on', 'Email obfuscation is enabled.', ['zone_settings']);
      return ev('fail', 0, obf ?? 'off', 'on', 'Email obfuscation is not enabled. Emails may be scraped.', ['zone_settings']);
    },
  },
];
