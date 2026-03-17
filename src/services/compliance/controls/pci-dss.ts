/**
 * Anga Security \u2014 PCI DSS 4.0 Framework Controls
 *
 * 19 controls mapped to Cloudflare configurations across:
 * req_1 (Network Security), req_4 (Cryptography), req_6 (Secure Systems),
 * req_7 (Access Control), req_8 (Authentication), req_10 (Logging),
 * req_11 (Security Testing)
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules, getHsts } from './helpers';

export const PCI_DSS_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // Requirement 1: Network Security Controls
  // ================================================================
  {
    control_id: 'PCI-1.3.1',
    control_ref: 'Requirement 1.3.1',
    framework: 'pci_dss_4',
    section_id: 'req_1',
    title: { es: 'Segmentaci\u00f3n de red y control de tr\u00e1fico', en: 'Network segmentation and traffic control' },
    description: { es: 'Controles de seguridad de red que restringen el tr\u00e1fico entrante y saliente', en: 'Network security controls that restrict inbound and outbound traffic' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 1: Instalar y mantener controles de seguridad de red', en: 'Requirement 1: Install and Maintain Network Security Controls' },
      clause: '1.3.1',
      official_text: { es: 'Los controles de seguridad de red se instalan y mantienen para restringir el tr\u00e1fico de entrada y salida al entorno de datos del titular de tarjeta', en: 'Network security controls are installed and maintained to restrict inbound and outbound traffic to the cardholder data environment' },
      applicability_note: { es: 'En Cloudflare: WAF, reglas de firewall, DNSSEC y reglas de acceso IP act\u00faan como controles de segmentaci\u00f3n de red', en: 'In Cloudflare: WAF, firewall rules, DNSSEC and IP access rules act as network segmentation controls' },
    },
    required_data_sources: ['rulesets', 'dns_summary', 'ip_access_rules'],
    required_permissions: ['Firewall Services:Read', 'DNS:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar DNSSEC y configurar reglas de acceso IP para restringir tr\u00e1fico', en: 'Enable DNSSEC and configure IP access rules to restrict traffic' },
      risk_if_ignored: { es: 'Sin segmentaci\u00f3n de red, atacantes pueden acceder directamente a sistemas internos', en: 'Without network segmentation, attackers can directly access internal systems' },
      steps: [
        { order: 1, action: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' }, where: { es: 'Dashboard > DNS > Configuraci\u00f3n', en: 'Dashboard > DNS > Settings' }, detail: { es: 'Activar DNSSEC para proteger la integridad de las consultas DNS', en: 'Activate DNSSEC to protect DNS query integrity' } },
        { order: 2, action: { es: 'Configurar reglas de acceso IP', en: 'Configure IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'A\u00f1adir reglas para bloquear o desafiar IPs sospechosas', en: 'Add rules to block or challenge suspicious IPs' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/dns/dnssec/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const waf = hasManagedWaf(ctx);
      const ipRules = ctx.enriched_data.ip_access_rules;
      const hasIpRules = ipRules ? ipRules.total > 0 : false;
      const checks = [dnssec, waf, hasIpRules];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `DNSSEC: on, WAF: active, IP rules: ${ipRules?.total || 0}`, 'DNSSEC + WAF + IP access rules', 'All network segmentation controls are active.', ['dns_summary', 'rulesets', 'ip_access_rules']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `DNSSEC: ${dnssec ? 'on' : 'off'}, WAF: ${waf ? 'active' : 'inactive'}, IP rules: ${hasIpRules ? 'configured' : 'none'}`, 'DNSSEC + WAF + IP access rules', `${passed}/3 network segmentation controls active.`, ['dns_summary', 'rulesets', 'ip_access_rules']);
      return ev('fail', 0, 'No network segmentation controls active', 'DNSSEC + WAF + IP access rules', 'None of the expected network segmentation controls are active.', ['dns_summary', 'rulesets', 'ip_access_rules']);
    },
  },
  {
    control_id: 'PCI-1.3.2',
    control_ref: 'Requirement 1.3.2',
    framework: 'pci_dss_4',
    section_id: 'req_1',
    title: { es: 'Restricci\u00f3n de tr\u00e1fico entrante', en: 'Restrict inbound traffic' },
    description: { es: 'El tr\u00e1fico entrante al entorno de datos se restringe a lo necesario', en: 'Inbound traffic to the data environment is restricted to what is necessary' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 1: Instalar y mantener controles de seguridad de red', en: 'Requirement 1: Install and Maintain Network Security Controls' },
      clause: '1.3.2',
      official_text: { es: 'El tr\u00e1fico entrante desde redes no confiables al CDE se restringe a comunicaciones autorizadas', en: 'Inbound traffic from untrusted networks to the CDE is restricted to authorized communications' },
      applicability_note: { es: 'En Cloudflare: Las reglas de rate limiting y reglas WAF personalizadas restringen el tr\u00e1fico entrante no deseado', en: 'In Cloudflare: Rate limiting rules and custom WAF rules restrict unwanted inbound traffic' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.20', clause: 'A.8.20' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
    ],
    remediation_template: {
      summary: { es: 'Configurar rate limiting y reglas WAF personalizadas', en: 'Configure rate limiting and custom WAF rules' },
      risk_if_ignored: { es: 'Tr\u00e1fico malicioso sin restricci\u00f3n puede comprometer sistemas', en: 'Unrestricted malicious traffic can compromise systems' },
      steps: [
        { order: 1, action: { es: 'Crear reglas de rate limiting', en: 'Create rate limiting rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas de limitaci\u00f3n', en: 'Dashboard > Security > WAF > Rate limiting rules' }, detail: { es: 'Definir l\u00edmites de solicitudes por IP/ruta', en: 'Define request limits per IP/path' } },
        { order: 2, action: { es: 'A\u00f1adir reglas WAF personalizadas', en: 'Add custom WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' }, detail: { es: 'Bloquear patrones de tr\u00e1fico no deseado', en: 'Block unwanted traffic patterns' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const customRules = getCustomWafRules(ctx);
      const rateLimits = getRateLimitRules(ctx);
      const total = customRules.length + rateLimits.length;
      if (total >= 5) return ev('pass', 100, `${customRules.length} custom rules, ${rateLimits.length} rate limits`, '\u22655 traffic restriction rules', 'Robust inbound traffic restrictions configured.', ['rulesets']);
      if (total >= 1) return ev('partial', 50, `${customRules.length} custom rules, ${rateLimits.length} rate limits`, '\u22655 traffic restriction rules', 'Some traffic restriction rules present but coverage could improve.', ['rulesets']);
      return ev('fail', 0, 'No custom WAF or rate limiting rules', '\u22655 traffic restriction rules', 'No inbound traffic restriction rules configured.', ['rulesets']);
    },
  },

  // ================================================================
  // Requirement 4: Protect Data with Strong Cryptography in Transit
  // ================================================================
  {
    control_id: 'PCI-4.2.1',
    control_ref: 'Requirement 4.2.1',
    framework: 'pci_dss_4',
    section_id: 'req_4',
    title: { es: 'Cifrado fuerte en tr\u00e1nsito', en: 'Strong cryptography in transit' },
    description: { es: 'Se utiliza criptograf\u00eda fuerte cuando se transmiten datos sensibles', en: 'Strong cryptography is used when transmitting sensitive data' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 4: Proteger datos con criptograf\u00eda fuerte durante la transmisi\u00f3n', en: 'Requirement 4: Protect Data with Strong Cryptography During Transmission' },
      clause: '4.2.1',
      official_text: { es: 'Se utiliza criptograf\u00eda fuerte siempre que se transmitan datos del titular de tarjeta por redes p\u00fablicas abiertas', en: 'Strong cryptography is used whenever cardholder data is transmitted over open, public networks' },
      applicability_note: { es: 'En Cloudflare: El modo SSL debe ser Full (Strict) para cifrado de extremo a extremo verificado', en: 'In Cloudflare: SSL mode must be Full (Strict) for verified end-to-end encryption' },
    },
    required_data_sources: ['zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19.III' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Cambiar modo SSL a Full (Strict)', en: 'Change SSL mode to Full (Strict)' },
      risk_if_ignored: { es: 'Datos transmitidos sin cifrado verificado pueden ser interceptados por atacantes', en: 'Data transmitted without verified encryption can be intercepted by attackers' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL/TLS en modo Full (Strict)', en: 'Set SSL/TLS to Full (Strict) mode' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar "Completo (estricto)" para validar certificado de origen', en: 'Select "Full (strict)" to validate origin certificate' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      if (ssl === 'strict' || ssl === 'full_strict') return ev('pass', 100, `SSL mode: ${ssl}`, 'Full (Strict)', 'End-to-end encryption with certificate validation is active.', ['zone_settings.ssl']);
      if (ssl === 'full') return ev('partial', 50, `SSL mode: ${ssl}`, 'Full (Strict)', 'Encryption active but origin certificate not validated. Upgrade to Full (Strict).', ['zone_settings.ssl']);
      return ev('fail', 0, `SSL mode: ${ssl || 'unknown'}`, 'Full (Strict)', 'SSL mode does not provide adequate encryption for PCI DSS compliance.', ['zone_settings.ssl']);
    },
  },
  {
    control_id: 'PCI-4.2.1.1',
    control_ref: 'Requirement 4.2.1.1',
    framework: 'pci_dss_4',
    section_id: 'req_4',
    title: { es: 'Inventario de certificados', en: 'Certificate inventory' },
    description: { es: 'Se mantiene un inventario de certificados de confianza', en: 'An inventory of trusted certificates is maintained' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 4: Proteger datos con criptograf\u00eda fuerte durante la transmisi\u00f3n', en: 'Requirement 4: Protect Data with Strong Cryptography During Transmission' },
      clause: '4.2.1.1',
      official_text: { es: 'Se mantiene un inventario de claves y certificados de confianza usados para proteger datos en tr\u00e1nsito', en: 'An inventory of trusted keys and certificates used to protect data in transit is maintained' },
      applicability_note: { es: 'En Cloudflare: Certificados de borde gestionados autom\u00e1ticamente. Verificar que ninguno est\u00e9 expirado o pr\u00f3ximo a expirar', en: 'In Cloudflare: Edge certificates managed automatically. Verify none are expired or expiring soon' },
    },
    required_data_sources: ['edge_certificates'],
    required_permissions: ['SSL and Certificates:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
    ],
    remediation_template: {
      summary: { es: 'Verificar y renovar certificados expirados o pr\u00f3ximos a expirar', en: 'Verify and renew expired or soon-to-expire certificates' },
      risk_if_ignored: { es: 'Certificados expirados causan errores de conexi\u00f3n y p\u00e9rdida de cifrado', en: 'Expired certificates cause connection errors and loss of encryption' },
      steps: [
        { order: 1, action: { es: 'Revisar certificados de borde', en: 'Review edge certificates' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Verificar que todos los certificados est\u00e9n activos y no pr\u00f3ximos a expirar', en: 'Verify all certificates are active and not close to expiring' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.edge_certificates, 'SSL and Certificates:Read', ['edge_certificates']);
      if (check) return check;
      const certs = ctx.enriched_data.edge_certificates!;
      if (certs.any_expired) return ev('fail', 0, `${certs.total} certs, expired found`, 'All certificates valid', 'One or more edge certificates are expired.', ['edge_certificates'], certs);
      if (certs.any_expiring_soon) return ev('partial', 60, `${certs.total} certs, some expiring within 30 days`, 'All certificates valid with >30 days', 'Certificates exist but some expire within 30 days.', ['edge_certificates'], certs);
      if (certs.total > 0) return ev('pass', 100, `${certs.total} valid certificates`, 'Valid certificate inventory', 'All edge certificates are valid and not expiring soon.', ['edge_certificates'], certs);
      return ev('fail', 0, 'No certificates found', 'Active certificate inventory', 'No edge certificates found for this zone.', ['edge_certificates']);
    },
  },
  {
    control_id: 'PCI-4.2.1.2',
    control_ref: 'Requirement 4.2.1.2',
    framework: 'pci_dss_4',
    section_id: 'req_4',
    title: { es: 'Suites de cifrado fuertes', en: 'Strong cipher suites' },
    description: { es: 'Solo se utilizan suites de cifrado fuertes y aprobadas', en: 'Only strong, approved cipher suites are used' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 4: Proteger datos con criptograf\u00eda fuerte durante la transmisi\u00f3n', en: 'Requirement 4: Protect Data with Strong Cryptography During Transmission' },
      clause: '4.2.1.2',
      official_text: { es: 'Solo se utilizan suites de cifrado fuertes para proteger la transmisi\u00f3n de datos del titular', en: 'Only strong cipher suites are used to protect cardholder data transmission' },
      applicability_note: { es: 'En Cloudflare: Verificar que no se hayan configurado cifrados d\u00e9biles. Los valores predeterminados de CF son compatibles con PCI DSS', en: 'In Cloudflare: Verify no weak ciphers configured. CF defaults are PCI DSS compliant' },
    },
    required_data_sources: ['cipher_suites'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Eliminar cifrados d\u00e9biles y usar solo los aprobados por PCI DSS', en: 'Remove weak ciphers and use only PCI DSS approved ones' },
      risk_if_ignored: { es: 'Cifrados d\u00e9biles permiten descifrar tr\u00e1fico interceptado', en: 'Weak ciphers allow decryption of intercepted traffic' },
      steps: [
        { order: 1, action: { es: 'Verificar configuraci\u00f3n de cifrados', en: 'Verify cipher configuration' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde > Opciones adicionales', en: 'Dashboard > SSL/TLS > Edge Certificates > Additional options' }, detail: { es: 'Asegurar que solo cifrados AEAD/ECDHE est\u00e9n habilitados', en: 'Ensure only AEAD/ECDHE ciphers are enabled' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ciphers = ctx.enriched_data.cipher_suites;
      if (!ciphers) return ev('fail', 0, 'No cipher data', 'PCI DSS compliant ciphers', 'Unable to determine cipher suite configuration.', ['cipher_suites']);
      if (ciphers.pci_dss_compliant && ciphers.weak_ciphers.length === 0) return ev('pass', 100, `PCI compliant, no weak ciphers`, 'PCI DSS compliant, no weak ciphers', 'All cipher suites are PCI DSS compliant.', ['cipher_suites'], ciphers);
      if (ciphers.weak_ciphers.length > 0) return ev('fail', 0, `Weak ciphers: ${ciphers.weak_ciphers.join(', ')}`, 'No weak ciphers', `${ciphers.weak_ciphers.length} weak cipher(s) detected.`, ['cipher_suites'], ciphers);
      return ev('partial', 50, 'Non-standard cipher configuration', 'PCI DSS compliant ciphers only', 'Cipher configuration is not fully PCI DSS compliant.', ['cipher_suites'], ciphers);
    },
  },
  {
    control_id: 'PCI-4.2.2',
    control_ref: 'Requirement 4.2.2',
    framework: 'pci_dss_4',
    section_id: 'req_4',
    title: { es: 'Versi\u00f3n m\u00ednima TLS 1.2', en: 'Minimum TLS version 1.2' },
    description: { es: 'TLS 1.2 o superior se utiliza para todas las conexiones', en: 'TLS 1.2 or higher is used for all connections' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 4: Proteger datos con criptograf\u00eda fuerte durante la transmisi\u00f3n', en: 'Requirement 4: Protect Data with Strong Cryptography During Transmission' },
      clause: '4.2.2',
      official_text: { es: 'Protocolos de criptograf\u00eda fuerte verificados: solo se aceptan versiones seguras (TLS 1.2+)', en: 'Strong cryptography protocols verified: only secure versions accepted (TLS 1.2+)' },
      applicability_note: { es: 'En Cloudflare: La versi\u00f3n m\u00ednima de TLS debe configurarse en 1.2 o superior', en: 'In Cloudflare: Minimum TLS version must be set to 1.2 or higher' },
    },
    required_data_sources: ['zone_settings.min_tls_version'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.21', clause: 'A.8.21' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Establecer versi\u00f3n m\u00ednima de TLS en 1.2', en: 'Set minimum TLS version to 1.2' },
      risk_if_ignored: { es: 'TLS 1.0/1.1 tienen vulnerabilidades conocidas que permiten descifrar tr\u00e1fico', en: 'TLS 1.0/1.1 have known vulnerabilities that allow traffic decryption' },
      steps: [
        { order: 1, action: { es: 'Configurar TLS m\u00ednimo', en: 'Configure minimum TLS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Establecer "Versi\u00f3n m\u00ednima de TLS" en 1.2', en: 'Set "Minimum TLS Version" to 1.2' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls = s(ctx, 'min_tls_version');
      if (tls === '1.3') return ev('pass', 100, `TLS minimum: ${tls}`, 'TLS 1.2+', 'Minimum TLS version set to 1.3 (exceeds requirement).', ['zone_settings.min_tls_version']);
      if (tls === '1.2') return ev('pass', 100, `TLS minimum: ${tls}`, 'TLS 1.2+', 'Minimum TLS version meets PCI DSS requirement.', ['zone_settings.min_tls_version']);
      return ev('fail', 0, `TLS minimum: ${tls || 'unknown'}`, 'TLS 1.2+', `TLS ${tls || 'unknown'} is below PCI DSS minimum. Upgrade to 1.2+.`, ['zone_settings.min_tls_version']);
    },
  },

  // ================================================================
  // Requirement 6: Develop and Maintain Secure Systems
  // ================================================================
  {
    control_id: 'PCI-6.4.1',
    control_ref: 'Requirement 6.4.1',
    framework: 'pci_dss_4',
    section_id: 'req_6',
    title: { es: 'Despliegue de WAF', en: 'WAF deployment' },
    description: { es: 'Un WAF se despliega frente a aplicaciones web p\u00fablicas', en: 'A WAF is deployed in front of public-facing web applications' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 6: Desarrollar y mantener sistemas y software seguros', en: 'Requirement 6: Develop and Maintain Secure Systems and Software' },
      clause: '6.4.1',
      official_text: { es: 'Las aplicaciones web p\u00fablicas est\u00e1n protegidas contra ataques conocidos mediante un WAF o soluci\u00f3n equivalente', en: 'Public-facing web applications are protected against known attacks using a WAF or equivalent solution' },
      applicability_note: { es: 'En Cloudflare: Verificar que las reglas WAF administradas est\u00e9n desplegadas y activas', en: 'In Cloudflare: Verify managed WAF rules are deployed and active' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.25', clause: 'A.8.25' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.IV', clause: 'Art. 36.IV' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Activar reglas WAF administradas de Cloudflare', en: 'Activate Cloudflare managed WAF rules' },
      risk_if_ignored: { es: 'Sin WAF, las aplicaciones web est\u00e1n expuestas a SQLi, XSS y otros ataques OWASP Top 10', en: 'Without WAF, web applications are exposed to SQLi, XSS and other OWASP Top 10 attacks' },
      steps: [
        { order: 1, action: { es: 'Activar reglas WAF administradas', en: 'Enable managed WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar el conjunto de reglas administradas de Cloudflare', en: 'Deploy the Cloudflare managed ruleset' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      if (waf) return ev('pass', 100, 'Managed WAF rules deployed', 'Managed WAF active', 'Cloudflare managed WAF rules are deployed and active.', ['rulesets']);
      return ev('fail', 0, 'No managed WAF rules', 'Managed WAF active', 'No managed WAF rules detected. Web applications are not protected.', ['rulesets']);
    },
  },
  {
    control_id: 'PCI-6.4.2',
    control_ref: 'Requirement 6.4.2',
    framework: 'pci_dss_4',
    section_id: 'req_6',
    title: { es: 'Reglas OWASP activas', en: 'OWASP rules active' },
    description: { es: 'Reglas WAF OWASP Core Rule Set est\u00e1n activas', en: 'WAF OWASP Core Rule Set rules are active' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 6: Desarrollar y mantener sistemas y software seguros', en: 'Requirement 6: Develop and Maintain Secure Systems and Software' },
      clause: '6.4.2',
      official_text: { es: 'Las herramientas automatizadas de evaluaci\u00f3n de seguridad detectan y previenen ataques web comunes', en: 'Automated security assessment tools detect and prevent common web attacks' },
      applicability_note: { es: 'En Cloudflare: El OWASP Core Rule Set proporciona detecci\u00f3n de ataques comunes como SQLi, XSS, LFI, RFI', en: 'In Cloudflare: OWASP Core Rule Set provides detection of common attacks like SQLi, XSS, LFI, RFI' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.28', clause: 'A.8.28' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
    ],
    remediation_template: {
      summary: { es: 'Activar el conjunto de reglas OWASP en el WAF', en: 'Activate the OWASP ruleset in the WAF' },
      risk_if_ignored: { es: 'Sin reglas OWASP, ataques comunes como inyecci\u00f3n SQL no ser\u00e1n detectados', en: 'Without OWASP rules, common attacks like SQL injection will not be detected' },
      steps: [
        { order: 1, action: { es: 'Activar OWASP Core Rule Set', en: 'Enable OWASP Core Rule Set' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar "Cloudflare OWASP Core Ruleset"', en: 'Deploy "Cloudflare OWASP Core Ruleset"' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      if (hasOwaspRules(ctx)) return ev('pass', 100, 'OWASP ruleset active', 'OWASP CRS active', 'OWASP Core Rule Set is deployed and active.', ['rulesets']);
      if (hasManagedWaf(ctx)) return ev('partial', 40, 'Managed WAF active but OWASP not detected', 'OWASP CRS active', 'Managed WAF is active but OWASP Core Rule Set was not detected.', ['rulesets']);
      return ev('fail', 0, 'No OWASP rules', 'OWASP CRS active', 'OWASP Core Rule Set is not deployed.', ['rulesets']);
    },
  },
  {
    control_id: 'PCI-6.4.3',
    control_ref: 'Requirement 6.4.3',
    framework: 'pci_dss_4',
    section_id: 'req_6',
    title: { es: 'Reglas WAF personalizadas', en: 'Custom WAF rules' },
    description: { es: 'Reglas WAF personalizadas aplicadas seg\u00fan necesidades espec\u00edficas', en: 'Custom WAF rules applied based on specific needs' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 6: Desarrollar y mantener sistemas y software seguros', en: 'Requirement 6: Develop and Maintain Secure Systems and Software' },
      clause: '6.4.3',
      official_text: { es: 'Se implementan controles adicionales espec\u00edficos de la aplicaci\u00f3n seg\u00fan sea necesario', en: 'Additional application-specific controls are implemented as needed' },
      applicability_note: { es: 'En Cloudflare: Reglas WAF personalizadas proporcionan protecci\u00f3n espec\u00edfica para la aplicaci\u00f3n', en: 'In Cloudflare: Custom WAF rules provide application-specific protection' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.26', clause: 'A.8.26' },
    ],
    remediation_template: {
      summary: { es: 'Crear reglas WAF personalizadas para la aplicaci\u00f3n', en: 'Create custom WAF rules for the application' },
      risk_if_ignored: { es: 'Las reglas gen\u00e9ricas pueden no cubrir amenazas espec\u00edficas de la aplicaci\u00f3n', en: 'Generic rules may not cover application-specific threats' },
      steps: [
        { order: 1, action: { es: 'Crear reglas personalizadas', en: 'Create custom rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' }, detail: { es: 'A\u00f1adir reglas que bloqueen patrones espec\u00edficos de ataque a la aplicaci\u00f3n', en: 'Add rules blocking application-specific attack patterns' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const rules = getCustomWafRules(ctx);
      if (rules.length >= 3) return ev('pass', 100, `${rules.length} custom WAF rules`, '\u22653 custom rules', 'Adequate custom WAF rules configured.', ['rulesets']);
      if (rules.length >= 1) return ev('partial', 50, `${rules.length} custom WAF rule(s)`, '\u22653 custom rules', 'Some custom rules present but more are recommended.', ['rulesets']);
      return ev('fail', 0, 'No custom WAF rules', '\u22653 custom rules', 'No custom WAF rules configured.', ['rulesets']);
    },
  },
  {
    control_id: 'PCI-6.5.5',
    control_ref: 'Requirement 6.5.5',
    framework: 'pci_dss_4',
    section_id: 'req_6',
    title: { es: 'Integridad de scripts (Page Shield)', en: 'Script integrity (Page Shield)' },
    description: { es: 'Monitoreo de integridad de scripts del lado del cliente', en: 'Client-side script integrity monitoring' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 6: Desarrollar y mantener sistemas y software seguros', en: 'Requirement 6: Develop and Maintain Secure Systems and Software' },
      clause: '6.5.5',
      official_text: { es: 'Se implementan controles para detectar y prevenir la manipulaci\u00f3n de scripts del lado del cliente', en: 'Controls are implemented to detect and prevent client-side script tampering' },
      applicability_note: { es: 'En Cloudflare: Page Shield monitorea scripts de terceros y detecta scripts maliciosos', en: 'In Cloudflare: Page Shield monitors third-party scripts and detects malicious scripts' },
    },
    required_data_sources: ['page_shield'],
    required_permissions: ['Page Shield:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.28', clause: 'A.8.28' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Page Shield para monitorear scripts del lado del cliente', en: 'Enable Page Shield to monitor client-side scripts' },
      risk_if_ignored: { es: 'Scripts maliciosos de terceros pueden robar datos de tarjetas (ataques Magecart)', en: 'Malicious third-party scripts can steal card data (Magecart attacks)' },
      steps: [
        { order: 1, action: { es: 'Activar Page Shield', en: 'Enable Page Shield' }, where: { es: 'Dashboard > Seguridad > Page Shield', en: 'Dashboard > Security > Page Shield' }, detail: { es: 'Habilitar el monitoreo de scripts y revisar alertas', en: 'Enable script monitoring and review alerts' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/page-shield/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      min_plan: 'business',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.page_shield, 'Page Shield:Read', ['page_shield']);
      if (check) return check;
      const ps = ctx.enriched_data.page_shield!;
      if (ps.malicious_scripts > 0) return ev('fail', 20, `Page Shield active, ${ps.malicious_scripts} malicious script(s) detected`, 'No malicious scripts', `${ps.malicious_scripts} malicious script(s) detected by Page Shield.`, ['page_shield'], ps);
      if (ps.enabled && ps.total_scripts > 0) return ev('pass', 100, `Page Shield active, monitoring ${ps.total_scripts} scripts`, 'Page Shield active', `Page Shield is monitoring ${ps.total_scripts} scripts with no malicious detections.`, ['page_shield'], ps);
      return ev('partial', 50, 'Page Shield enabled but no scripts monitored', 'Active script monitoring', 'Page Shield is enabled but no scripts are being monitored.', ['page_shield'], ps);
    },
  },

  // ================================================================
  // Requirement 7: Restrict Access
  // ================================================================
  {
    control_id: 'PCI-7.2.1',
    control_ref: 'Requirement 7.2.1',
    framework: 'pci_dss_4',
    section_id: 'req_7',
    title: { es: 'Nivel de seguridad de acceso', en: 'Access security level' },
    description: { es: 'Control de acceso configurado para verificar visitantes', en: 'Access control configured to verify visitors' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 7: Restringir acceso a componentes del sistema', en: 'Requirement 7: Restrict Access to System Components' },
      clause: '7.2.1',
      official_text: { es: 'Se implementa un sistema de control de acceso que restringe el acceso seg\u00fan la necesidad de conocer del usuario', en: 'An access control system is implemented that restricts access based on user need to know' },
      applicability_note: { es: 'En Cloudflare: El nivel de seguridad determina cu\u00e1ndo se presenta un desaf\u00edo a los visitantes', en: 'In Cloudflare: Security level determines when visitors are presented with a challenge' },
    },
    required_data_sources: ['zone_settings.security_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.IV', clause: 'Art. 19.IV' },
    ],
    remediation_template: {
      summary: { es: 'Aumentar el nivel de seguridad a High o superior', en: 'Increase security level to High or above' },
      risk_if_ignored: { es: 'Un nivel de seguridad bajo permite que bots y atacantes accedan sin desaf\u00edo', en: 'A low security level allows bots and attackers to access without challenge' },
      steps: [
        { order: 1, action: { es: 'Ajustar nivel de seguridad', en: 'Adjust security level' }, where: { es: 'Dashboard > Seguridad > Configuraci\u00f3n', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer nivel en "Alto" o "Estoy bajo ataque" seg\u00fan necesidad', en: 'Set level to "High" or "I\'m Under Attack" as needed' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/security-level/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const level = s(ctx, 'security_level');
      if (level === 'high' || level === 'under_attack') return ev('pass', 100, `Security level: ${level}`, 'High or Under Attack', 'Security level provides strong access control.', ['zone_settings.security_level']);
      if (level === 'medium') return ev('partial', 50, `Security level: ${level}`, 'High or above', 'Security level is medium. Consider increasing to High.', ['zone_settings.security_level']);
      return ev('fail', 0, `Security level: ${level || 'unknown'}`, 'High or above', 'Security level is too low for PCI DSS compliance.', ['zone_settings.security_level']);
    },
  },
  {
    control_id: 'PCI-7.2.6',
    control_ref: 'Requirement 7.2.6',
    framework: 'pci_dss_4',
    section_id: 'req_7',
    title: { es: 'Restricciones de acceso por IP', en: 'IP-based access restrictions' },
    description: { es: 'Restricciones de acceso basadas en IP configuradas', en: 'IP-based access restrictions configured' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 7: Restringir acceso a componentes del sistema', en: 'Requirement 7: Restrict Access to System Components' },
      clause: '7.2.6',
      official_text: { es: 'El acceso a los componentes del sistema y los datos del titular de tarjeta est\u00e1 restringido seg\u00fan sea necesario', en: 'Access to system components and cardholder data is restricted as necessary' },
      applicability_note: { es: 'En Cloudflare: Las reglas de acceso IP permiten bloquear, desafiar o permitir tr\u00e1fico por IP/pa\u00eds/ASN', en: 'In Cloudflare: IP access rules allow blocking, challenging or allowing traffic by IP/country/ASN' },
    },
    required_data_sources: ['ip_access_rules'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.3', clause: 'CC6.3' },
    ],
    remediation_template: {
      summary: { es: 'Configurar reglas de acceso IP para restringir tr\u00e1fico no deseado', en: 'Configure IP access rules to restrict unwanted traffic' },
      risk_if_ignored: { es: 'Sin restricciones IP, cualquier direcci\u00f3n puede acceder a los sistemas', en: 'Without IP restrictions, any address can access the systems' },
      steps: [
        { order: 1, action: { es: 'A\u00f1adir reglas de acceso IP', en: 'Add IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'Bloquear pa\u00edses/IPs no deseados y crear lista de permitidos', en: 'Block unwanted countries/IPs and create allowlist' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/ip-access-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.ip_access_rules, 'Firewall Services:Read', ['ip_access_rules']);
      if (check) return check;
      const rules = ctx.enriched_data.ip_access_rules!;
      if (rules.total >= 3) return ev('pass', 100, `${rules.total} IP access rules configured`, '\u22653 IP access rules', 'Adequate IP-based access restrictions in place.', ['ip_access_rules'], rules);
      if (rules.total >= 1) return ev('partial', 50, `${rules.total} IP access rule(s)`, '\u22653 IP access rules', 'Some IP rules present but more are recommended.', ['ip_access_rules'], rules);
      return ev('fail', 0, 'No IP access rules', '\u22653 IP access rules', 'No IP-based access restrictions configured.', ['ip_access_rules']);
    },
  },

  // ================================================================
  // Requirement 8: Authentication
  // ================================================================
  {
    control_id: 'PCI-8.3.1',
    control_ref: 'Requirement 8.3.1',
    framework: 'pci_dss_4',
    section_id: 'req_8',
    title: { es: 'Autenticaci\u00f3n mutua TLS (mTLS)', en: 'Mutual TLS authentication (mTLS)' },
    description: { es: 'Autenticaci\u00f3n mutua TLS entre Cloudflare y el origen', en: 'Mutual TLS authentication between Cloudflare and origin' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 8: Identificar usuarios y autenticar acceso', en: 'Requirement 8: Identify Users and Authenticate Access' },
      clause: '8.3.1',
      official_text: { es: 'Todos los accesos a componentes del sistema se autentican mediante al menos un factor de autenticaci\u00f3n', en: 'All access to system components is authenticated using at least one authentication factor' },
      applicability_note: { es: 'En Cloudflare: Authenticated Origin Pulls (mTLS) verifica que las solicitudes al origen provienen de Cloudflare', en: 'In Cloudflare: Authenticated Origin Pulls (mTLS) verifies that requests to origin come from Cloudflare' },
    },
    required_data_sources: ['authenticated_origin_pulls'],
    required_permissions: ['SSL and Certificates:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.I', clause: 'Art. 36.I' },
      { framework: 'gdpr', control_id: 'GDPR-25.1', clause: 'Art. 25(1)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Authenticated Origin Pulls para verificaci\u00f3n mutua TLS', en: 'Enable Authenticated Origin Pulls for mutual TLS verification' },
      risk_if_ignored: { es: 'Sin mTLS, el origen acepta solicitudes de cualquier fuente, no solo de Cloudflare', en: 'Without mTLS, the origin accepts requests from any source, not just Cloudflare' },
      steps: [
        { order: 1, action: { es: 'Habilitar Authenticated Origin Pulls', en: 'Enable Authenticated Origin Pulls' }, where: { es: 'Dashboard > SSL/TLS > Servidor de origen', en: 'Dashboard > SSL/TLS > Origin Server' }, detail: { es: 'Activar "Authenticated Origin Pulls" y configurar certificados', en: 'Enable "Authenticated Origin Pulls" and configure certificates' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.authenticated_origin_pulls, 'SSL and Certificates:Read', ['authenticated_origin_pulls']);
      if (check) return check;
      const aop = ctx.enriched_data.authenticated_origin_pulls!;
      if (aop.enabled) return ev('pass', 100, 'mTLS (Authenticated Origin Pulls) enabled', 'mTLS enabled', 'Origin authentication via mutual TLS is active.', ['authenticated_origin_pulls']);
      return ev('fail', 0, 'mTLS disabled', 'mTLS enabled', 'Authenticated Origin Pulls is not enabled. Origin accepts unverified requests.', ['authenticated_origin_pulls']);
    },
  },
  {
    control_id: 'PCI-8.6.1',
    control_ref: 'Requirement 8.6.1',
    framework: 'pci_dss_4',
    section_id: 'req_8',
    title: { es: 'Gesti\u00f3n de bots', en: 'Bot management' },
    description: { es: 'Gesti\u00f3n de bots para identificar y controlar tr\u00e1fico automatizado', en: 'Bot management to identify and control automated traffic' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 8: Identificar usuarios y autenticar acceso', en: 'Requirement 8: Identify Users and Authenticate Access' },
      clause: '8.6.1',
      official_text: { es: 'Se gestionan las cuentas de sistema y aplicaci\u00f3n para minimizar el acceso no autorizado automatizado', en: 'System and application accounts are managed to minimize unauthorized automated access' },
      applicability_note: { es: 'En Cloudflare: Bot Management identifica y controla tr\u00e1fico automatizado usando ML, JA3/JA4 fingerprinting', en: 'In Cloudflare: Bot Management identifies and controls automated traffic using ML, JA3/JA4 fingerprinting' },
    },
    required_data_sources: ['zone_settings.bot_management', 'bot_scores'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.7', clause: 'A.8.7' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.III', clause: 'Art. 36.III' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Cloudflare Bot Management', en: 'Enable Cloudflare Bot Management' },
      risk_if_ignored: { es: 'Tr\u00e1fico automatizado malicioso puede realizar credential stuffing y scraping', en: 'Malicious automated traffic can perform credential stuffing and scraping' },
      steps: [
        { order: 1, action: { es: 'Habilitar Bot Management', en: 'Enable Bot Management' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Activar Bot Management (requiere plan Enterprise) o Bot Fight Mode (gratuito)', en: 'Enable Bot Management (requires Enterprise plan) or Bot Fight Mode (free)' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/bots/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const bm = s(ctx, 'bot_management');
      const botScores = ctx.audit_data.bot_scores;
      if (bm?.enabled === true || bm?.enable_js === true) return ev('pass', 100, 'Bot Management enabled', 'Bot Management active', 'Cloudflare Bot Management is active.', ['zone_settings.bot_management']);
      if (botScores && botScores.total_requests > 0) return ev('partial', 50, 'Bot scoring available but management not fully enabled', 'Bot Management active', 'Bot score data exists but full Bot Management may not be enabled.', ['zone_settings.bot_management', 'bot_scores']);
      return ev('fail', 0, 'Bot Management not enabled', 'Bot Management active', 'No bot management detected. Automated attacks are not being controlled.', ['zone_settings.bot_management']);
    },
  },

  // ================================================================
  // Requirement 10: Logging and Monitoring
  // ================================================================
  {
    control_id: 'PCI-10.2.1',
    control_ref: 'Requirement 10.2.1',
    framework: 'pci_dss_4',
    section_id: 'req_10',
    title: { es: 'Registro de auditor\u00eda activo', en: 'Audit logging active' },
    description: { es: 'Los registros de auditor\u00eda est\u00e1n habilitados para todos los componentes del sistema', en: 'Audit logs are enabled for all system components' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 10: Registrar y monitorear todo acceso', en: 'Requirement 10: Log and Monitor All Access' },
      clause: '10.2.1',
      official_text: { es: 'Los registros de auditor\u00eda est\u00e1n habilitados y activos para todos los componentes del sistema', en: 'Audit logs are enabled and active for all system components' },
      applicability_note: { es: 'En Cloudflare: Los Audit Logs de cuenta registran todos los cambios de configuraci\u00f3n y acciones administrativas', en: 'In Cloudflare: Account Audit Logs record all configuration changes and administrative actions' },
    },
    required_data_sources: ['audit_logs'],
    required_permissions: ['Account Access: Audit Logs'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.V', clause: 'Art. 19.V' },
      { framework: 'gdpr', control_id: 'GDPR-5.2', clause: 'Art. 5(2)' },
    ],
    remediation_template: {
      summary: { es: 'Verificar que los Audit Logs de cuenta est\u00e9n accesibles', en: 'Verify that account Audit Logs are accessible' },
      risk_if_ignored: { es: 'Sin registros de auditor\u00eda, es imposible detectar accesos no autorizados o cambios maliciosos', en: 'Without audit logs, it is impossible to detect unauthorized access or malicious changes' },
      steps: [
        { order: 1, action: { es: 'Verificar Audit Logs', en: 'Verify Audit Logs' }, where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Confirmar que los eventos de auditor\u00eda est\u00e1n registr\u00e1ndose correctamente', en: 'Confirm audit events are being recorded correctly' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/setup/account/account-audit-logs/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.audit_logs, 'Account Access: Audit Logs', ['audit_logs']);
      if (check) return check;
      const logs = ctx.enriched_data.audit_logs!;
      if (logs.available && logs.recent_count > 0) return ev('pass', 100, `Audit logs active, ${logs.recent_count} recent events`, 'Audit logs active with events', 'Audit logging is active and recording events.', ['audit_logs'], logs);
      if (logs.available) return ev('partial', 50, 'Audit logs available but no recent events', 'Active audit logging', 'Audit log system is available but no recent events found.', ['audit_logs'], logs);
      return ev('fail', 0, 'Audit logs not available', 'Active audit logging', 'Audit logging is not available or accessible.', ['audit_logs']);
    },
  },
  {
    control_id: 'PCI-10.2.2',
    control_ref: 'Requirement 10.2.2',
    framework: 'pci_dss_4',
    section_id: 'req_10',
    title: { es: 'Exportaci\u00f3n de logs (Logpush)', en: 'Log export (Logpush)' },
    description: { es: 'Logs de seguridad exportados a almacenamiento externo', en: 'Security logs exported to external storage' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 10: Registrar y monitorear todo acceso', en: 'Requirement 10: Log and Monitor All Access' },
      clause: '10.2.2',
      official_text: { es: 'Los registros capturan todas las acciones de cualquier individuo con acceso administrativo', en: 'Logs capture all actions by any individual with administrative access' },
      applicability_note: { es: 'En Cloudflare: Logpush exporta logs de firewall, HTTP y auditor\u00eda a almacenamiento externo para retenci\u00f3n y an\u00e1lisis', en: 'In Cloudflare: Logpush exports firewall, HTTP and audit logs to external storage for retention and analysis' },
    },
    required_data_sources: ['logpush_jobs'],
    required_permissions: ['Logs:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
      { framework: 'gdpr', control_id: 'GDPR-33.2', clause: 'Art. 33(2)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush para exportar logs de seguridad', en: 'Configure Logpush to export security logs' },
      risk_if_ignored: { es: 'Sin exportaci\u00f3n de logs, no hay registro permanente para investigaciones forenses', en: 'Without log export, there is no permanent record for forensic investigations' },
      steps: [
        { order: 1, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Crear jobs de Logpush para firewall_events y http_requests como m\u00ednimo', en: 'Create Logpush jobs for firewall_events and http_requests at minimum' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.logpush_jobs, 'Logs:Read', ['logpush_jobs']);
      if (check) return check;
      const lp = ctx.enriched_data.logpush_jobs!;
      if (lp.has_firewall_logs && lp.has_http_logs) return ev('pass', 100, `${lp.total} Logpush jobs (firewall + HTTP active)`, 'Firewall + HTTP log export', 'Security logs are being exported for retention and analysis.', ['logpush_jobs'], lp);
      if (lp.total > 0) return ev('partial', 50, `${lp.total} Logpush job(s), missing: ${!lp.has_firewall_logs ? 'firewall' : ''} ${!lp.has_http_logs ? 'HTTP' : ''}`, 'Firewall + HTTP log export', 'Logpush is configured but not all critical log types are exported.', ['logpush_jobs'], lp);
      return ev('fail', 0, 'No Logpush jobs configured', 'Firewall + HTTP log export', 'No log export configured. Security events are not being preserved.', ['logpush_jobs']);
    },
  },
  {
    control_id: 'PCI-10.4.1',
    control_ref: 'Requirement 10.4.1',
    framework: 'pci_dss_4',
    section_id: 'req_10',
    title: { es: 'Alertas de seguridad configuradas', en: 'Security alerts configured' },
    description: { es: 'Alertas de seguridad configuradas para eventos cr\u00edticos', en: 'Security alerts configured for critical events' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 10: Registrar y monitorear todo acceso', en: 'Requirement 10: Log and Monitor All Access' },
      clause: '10.4.1',
      official_text: { es: 'Los registros de auditor\u00eda se revisan al menos una vez al d\u00eda para identificar anomal\u00edas o actividad sospechosa', en: 'Audit logs are reviewed at least once daily to identify anomalies or suspicious activity' },
      applicability_note: { es: 'En Cloudflare: Las pol\u00edticas de notificaci\u00f3n alertan autom\u00e1ticamente sobre eventos de seguridad cr\u00edticos', en: 'In Cloudflare: Notification policies automatically alert on critical security events' },
    },
    required_data_sources: ['notification_policies'],
    required_permissions: ['Notifications:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.V', clause: 'Art. 36.V' },
      { framework: 'gdpr', control_id: 'GDPR-33.1', clause: 'Art. 33(1)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar notificaciones para eventos de seguridad', en: 'Configure notifications for security events' },
      risk_if_ignored: { es: 'Sin alertas, los incidentes de seguridad pueden pasar desapercibidos durante d\u00edas', en: 'Without alerts, security incidents can go unnoticed for days' },
      steps: [
        { order: 1, action: { es: 'Configurar alertas de seguridad', en: 'Configure security alerts' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Crear pol\u00edticas para alertas DDoS, WAF, SSL y eventos de seguridad', en: 'Create policies for DDoS, WAF, SSL and security event alerts' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/notifications/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.notification_policies, 'Notifications:Read', ['notification_policies']);
      if (check) return check;
      const np = ctx.enriched_data.notification_policies!;
      if (np.has_security_alerts && np.has_ddos_alerts) return ev('pass', 100, `${np.total} alert policies (security + DDoS active)`, 'Security + DDoS alerts', 'Comprehensive security alert policies are configured.', ['notification_policies'], np);
      if (np.total > 0) return ev('partial', 50, `${np.total} alert policies`, 'Security + DDoS alerts', 'Some alert policies exist but security-specific alerts may be missing.', ['notification_policies'], np);
      return ev('fail', 0, 'No notification policies', 'Security + DDoS alerts', 'No security alert policies configured.', ['notification_policies']);
    },
  },
  {
    control_id: 'PCI-10.7.1',
    control_ref: 'Requirement 10.7.1',
    framework: 'pci_dss_4',
    section_id: 'req_10',
    title: { es: 'Retenci\u00f3n de logs', en: 'Log retention' },
    description: { es: 'Los logs se retienen por al menos 12 meses', en: 'Logs are retained for at least 12 months' },
    severity: 'high',
    evaluation_method: 'partial',
    regulatory_reference: {
      section: { es: 'Requisito 10: Registrar y monitorear todo acceso', en: 'Requirement 10: Log and Monitor All Access' },
      clause: '10.7.1',
      official_text: { es: 'El historial de registros de auditor\u00eda se retiene por al menos 12 meses, con los 3 meses m\u00e1s recientes disponibles inmediatamente', en: 'Audit log history is retained for at least 12 months, with the most recent 3 months immediately available' },
      applicability_note: { es: 'En Cloudflare: Logpush env\u00eda logs a almacenamiento externo donde la retenci\u00f3n depende del destino configurado', en: 'In Cloudflare: Logpush sends logs to external storage where retention depends on the configured destination' },
    },
    required_data_sources: ['logpush_jobs'],
    required_permissions: ['Logs:Read'],
    cross_references: [
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
      { framework: 'gdpr', control_id: 'GDPR-33.2', clause: 'Art. 33(2)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush con destino que soporte retenci\u00f3n de 12+ meses', en: 'Configure Logpush with destination supporting 12+ month retention' },
      risk_if_ignored: { es: 'Sin retenci\u00f3n adecuada, investigaciones forenses quedan incompletas', en: 'Without adequate retention, forensic investigations remain incomplete' },
      steps: [
        { order: 1, action: { es: 'Verificar Logpush activo', en: 'Verify Logpush active' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Verificar que los logs se env\u00edan a un destino con retenci\u00f3n de 12+ meses', en: 'Verify logs are sent to a destination with 12+ month retention' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.logpush_jobs, 'Logs:Read', ['logpush_jobs']);
      if (check) return check;
      const lp = ctx.enriched_data.logpush_jobs!;
      if (lp.total > 0 && lp.jobs.some(j => j.enabled)) return ev('partial', 60, `${lp.total} Logpush jobs active (retention depends on destination)`, '12+ months retention', 'Logpush is active. Verify that the destination retains logs for 12+ months (manual verification required).', ['logpush_jobs'], lp);
      return ev('fail', 0, 'No Logpush configured', '12+ months retention with Logpush', 'No log export configured. Cannot ensure log retention compliance.', ['logpush_jobs']);
    },
  },

  // ================================================================
  // Requirement 11: Security Testing
  // ================================================================
  {
    control_id: 'PCI-11.6.1',
    control_ref: 'Requirement 11.6.1',
    framework: 'pci_dss_4',
    section_id: 'req_11',
    title: { es: 'Monitoreo de disponibilidad', en: 'Availability monitoring' },
    description: { es: 'Monitoreo activo de la disponibilidad del sistema', en: 'Active system availability monitoring' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Requisito 11: Probar la seguridad regularmente', en: 'Requirement 11: Test Security Regularly' },
      clause: '11.6.1',
      official_text: { es: 'Se implementa un mecanismo de detecci\u00f3n de cambios para alertar al personal sobre modificaciones no autorizadas', en: 'A change-detection mechanism is deployed to alert personnel to unauthorized modification' },
      applicability_note: { es: 'En Cloudflare: Health Checks monitoran la disponibilidad del origen y detectan interrupciones', en: 'In Cloudflare: Health Checks monitor origin availability and detect outages' },
    },
    required_data_sources: ['health_checks'],
    required_permissions: ['Health Checks:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'soc2_type2', control_id: 'SOC2-A1.1', clause: 'A1.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.VI', clause: 'Art. 36.VI' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Health Checks para monitorear disponibilidad del origen', en: 'Configure Health Checks to monitor origin availability' },
      risk_if_ignored: { es: 'Sin monitoreo, ca\u00eddas del servicio pueden pasar desapercibidas afectando la disponibilidad', en: 'Without monitoring, service outages can go unnoticed affecting availability' },
      steps: [
        { order: 1, action: { es: 'Crear Health Checks', en: 'Create Health Checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Configurar verificaciones de salud HTTP/HTTPS para endpoints cr\u00edticos', en: 'Configure HTTP/HTTPS health checks for critical endpoints' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const check = enrichedOrPerm(ctx, ctx.enriched_data.health_checks, 'Health Checks:Read', ['health_checks']);
      if (check) return check;
      const hc = ctx.enriched_data.health_checks!;
      if (hc.total > 0 && hc.all_healthy) return ev('pass', 100, `${hc.total} health checks, all healthy`, 'Active health monitoring', 'Health checks are configured and all endpoints are healthy.', ['health_checks'], hc);
      if (hc.total > 0) return ev('partial', 60, `${hc.total} health checks, some unhealthy`, 'All checks healthy', 'Health checks exist but some endpoints are unhealthy.', ['health_checks'], hc);
      return ev('fail', 0, 'No health checks configured', 'Active health monitoring', 'No health checks configured for availability monitoring.', ['health_checks']);
    },
  },
];
