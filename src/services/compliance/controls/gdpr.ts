/**
 * Anga Security \u2014 GDPR (EU 2016/679) Framework Controls
 *
 * 12 controls across 4 articles mapped to Cloudflare configurations:
 * Art. 5 (Processing Principles), Art. 25 (Data Protection by Design),
 * Art. 32 (Security of Processing), Art. 33 (Breach Notification)
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules, getHsts } from './helpers';

export const GDPR_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // Article 5: Processing Principles
  // ================================================================
  {
    control_id: 'GDPR-5.1.d',
    control_ref: 'Article 5(1)(d)',
    framework: 'gdpr',
    section_id: 'art_5',
    title: { es: 'Principio de exactitud de datos', en: 'Data accuracy principle' },
    description: { es: 'Los datos personales deben ser exactos y mantenerse actualizados, utilizando DNSSEC para proteger la integridad de los datos', en: 'Personal data must be accurate and kept up to date, using DNSSEC to protect data integrity' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 5: Principios relativos al tratamiento', en: 'Article 5: Principles relating to processing' },
      clause: '5(1)(d)',
      official_text: { es: 'exactos y, cuando sea necesario, actualizados', en: 'accurate and, where necessary, kept up to date' },
      applicability_note: { es: 'En Cloudflare: DNSSEC protege la integridad de las consultas DNS, asegurando que los datos no sean manipulados en tr\u00e1nsito', en: 'In Cloudflare: DNSSEC protects DNS query integrity, ensuring data is not tampered with in transit' },
    },
    required_data_sources: ['dns_summary'],
    required_permissions: ['DNS:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar DNSSEC para proteger la integridad de datos DNS', en: 'Enable DNSSEC to protect DNS data integrity' },
      risk_if_ignored: { es: 'Sin DNSSEC, las respuestas DNS pueden ser falsificadas, redirigiendo usuarios a sitios maliciosos', en: 'Without DNSSEC, DNS responses can be spoofed, redirecting users to malicious sites' },
      steps: [
        { order: 1, action: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' }, where: { es: 'Dashboard > DNS > Configuraci\u00f3n', en: 'Dashboard > DNS > Settings' }, detail: { es: 'Activar DNSSEC y agregar el registro DS en el registrador del dominio', en: 'Activate DNSSEC and add the DS record at the domain registrar' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/dns/dnssec/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      if (dnssec) return ev('pass', 100, 'DNSSEC enabled', 'DNSSEC active', 'DNSSEC is enabled, protecting DNS data integrity as required by Art. 5(1)(d).', ['dns_summary']);
      return ev('fail', 0, 'DNSSEC disabled', 'DNSSEC active', 'DNSSEC is not enabled. DNS responses can be tampered with, compromising data integrity.', ['dns_summary']);
    },
  },
  {
    control_id: 'GDPR-5.1.f',
    control_ref: 'Article 5(1)(f)',
    framework: 'gdpr',
    section_id: 'art_5',
    title: { es: 'Integridad y confidencialidad', en: 'Integrity and confidentiality' },
    description: { es: 'Los datos personales deben procesarse con seguridad apropiada, incluyendo cifrado SSL/TLS y HTTPS forzado', en: 'Personal data must be processed with appropriate security, including SSL/TLS encryption and enforced HTTPS' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 5: Principios relativos al tratamiento', en: 'Article 5: Principles relating to processing' },
      clause: '5(1)(f)',
      official_text: { es: 'tratados de manera que se garantice una seguridad adecuada de los datos personales, incluida la protecci\u00f3n contra el tratamiento no autorizado o il\u00edcito y contra su p\u00e9rdida accidental', en: 'processed in a manner that ensures appropriate security of the personal data, including protection against unauthorised or unlawful processing and against accidental loss' },
      applicability_note: { es: 'En Cloudflare: El modo SSL/TLS, Always HTTPS y la configuraci\u00f3n de cifrado protegen los datos en tr\u00e1nsito', en: 'In Cloudflare: SSL/TLS mode, Always HTTPS and encryption configuration protect data in transit' },
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.always_use_https'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19.III' },
    ],
    remediation_template: {
      summary: { es: 'Configurar SSL/TLS en modo Full (Strict) y habilitar Always HTTPS', en: 'Configure SSL/TLS to Full (Strict) mode and enable Always HTTPS' },
      risk_if_ignored: { es: 'Sin cifrado adecuado, datos personales pueden ser interceptados en tr\u00e1nsito', en: 'Without adequate encryption, personal data can be intercepted in transit' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL/TLS en Full (Strict)', en: 'Set SSL/TLS to Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar modo "Completo (estricto)" para cifrado de extremo a extremo verificado', en: 'Select "Full (strict)" mode for verified end-to-end encryption' } },
        { order: 2, action: { es: 'Habilitar Always HTTPS', en: 'Enable Always HTTPS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar "Usar siempre HTTPS" para redirigir todo el tr\u00e1fico HTTP', en: 'Enable "Always Use HTTPS" to redirect all HTTP traffic' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const alwaysHttps = s(ctx, 'always_use_https') === 'on';
      const sslStrict = ssl === 'strict' || ssl === 'full_strict';
      const sslFull = ssl === 'full';
      if (sslStrict && alwaysHttps) return ev('pass', 100, `SSL: ${ssl}, Always HTTPS: on`, 'Full (Strict) + Always HTTPS', 'End-to-end encryption with forced HTTPS ensures data integrity and confidentiality.', ['zone_settings.ssl', 'zone_settings.always_use_https']);
      if (sslStrict || (sslFull && alwaysHttps)) return ev('partial', 60, `SSL: ${ssl}, Always HTTPS: ${alwaysHttps ? 'on' : 'off'}`, 'Full (Strict) + Always HTTPS', 'Encryption is partially configured. Enable both Full (Strict) SSL and Always HTTPS.', ['zone_settings.ssl', 'zone_settings.always_use_https']);
      if (sslFull) return ev('partial', 40, `SSL: ${ssl}, Always HTTPS: ${alwaysHttps ? 'on' : 'off'}`, 'Full (Strict) + Always HTTPS', 'SSL is Full but not Strict. Origin certificate is not validated.', ['zone_settings.ssl', 'zone_settings.always_use_https']);
      return ev('fail', 0, `SSL: ${ssl || 'unknown'}, Always HTTPS: ${alwaysHttps ? 'on' : 'off'}`, 'Full (Strict) + Always HTTPS', 'Insufficient encryption for GDPR Art. 5(1)(f) compliance.', ['zone_settings.ssl', 'zone_settings.always_use_https']);
    },
  },
  {
    control_id: 'GDPR-5.2',
    control_ref: 'Article 5(2)',
    framework: 'gdpr',
    section_id: 'art_5',
    title: { es: 'Responsabilidad proactiva', en: 'Accountability' },
    description: { es: 'El responsable del tratamiento debe poder demostrar el cumplimiento mediante registros de auditor\u00eda', en: 'The controller must be able to demonstrate compliance through audit logs' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 5: Principios relativos al tratamiento', en: 'Article 5: Principles relating to processing' },
      clause: '5(2)',
      official_text: { es: 'El responsable del tratamiento ser\u00e1 responsable del cumplimiento y capaz de demostrarlo', en: 'The controller shall be responsible for, and be able to demonstrate compliance with' },
      applicability_note: { es: 'En Cloudflare: Los Audit Logs de cuenta registran todos los cambios de configuraci\u00f3n, proporcionando evidencia de cumplimiento', en: 'In Cloudflare: Account Audit Logs record all configuration changes, providing compliance evidence' },
    },
    required_data_sources: ['audit_logs', 'logpush_jobs'],
    required_permissions: ['Account Access: Audit Logs', 'Logs:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.V', clause: 'Art. 19.V' },
    ],
    remediation_template: {
      summary: { es: 'Verificar que los Audit Logs est\u00e9n activos y configurar Logpush para retenci\u00f3n', en: 'Verify Audit Logs are active and configure Logpush for retention' },
      risk_if_ignored: { es: 'Sin registros de auditor\u00eda, es imposible demostrar cumplimiento ante una autoridad de protecci\u00f3n de datos', en: 'Without audit logs, it is impossible to demonstrate compliance to a data protection authority' },
      steps: [
        { order: 1, action: { es: 'Verificar Audit Logs', en: 'Verify Audit Logs' }, where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Confirmar que los eventos de auditor\u00eda se registran correctamente', en: 'Confirm audit events are being recorded correctly' } },
        { order: 2, action: { es: 'Configurar Logpush para retenci\u00f3n', en: 'Configure Logpush for retention' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Exportar logs a almacenamiento externo para retenci\u00f3n a largo plazo', en: 'Export logs to external storage for long-term retention' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/setup/account/account-audit-logs/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const auditOk = ctx.enriched_data.audit_logs?.available === true && ctx.enriched_data.audit_logs.recent_count > 0;
      const logpushOk = ctx.enriched_data.logpush_jobs?.total ? ctx.enriched_data.logpush_jobs.total > 0 : false;
      if (auditOk && logpushOk) return ev('pass', 100, `Audit logs active, ${ctx.enriched_data.logpush_jobs!.total} Logpush jobs`, 'Audit logs + Logpush', 'Comprehensive accountability logging in place for GDPR Art. 5(2).', ['audit_logs', 'logpush_jobs']);
      if (auditOk || logpushOk) return ev('partial', 50, `Audit logs: ${auditOk ? 'active' : 'inactive'}, Logpush: ${logpushOk ? 'active' : 'inactive'}`, 'Both audit logs + Logpush', 'Partial accountability logging. Enable both for full demonstrable compliance.', ['audit_logs', 'logpush_jobs']);
      const hasPerm1 = ctx.available_permissions.includes('Account Access: Audit Logs');
      const hasPerm2 = ctx.available_permissions.includes('Logs:Read');
      if (!hasPerm1 && !hasPerm2) return ev('insufficient_permissions', 0, 'N/A', 'Audit Logs + Logpush', 'Token lacks Account Access: Audit Logs and Logs:Read permissions.', ['audit_logs', 'logpush_jobs']);
      return ev('fail', 0, 'No active logging detected', 'Audit logs + Logpush', 'No accountability logging available. Cannot demonstrate GDPR compliance.', ['audit_logs', 'logpush_jobs']);
    },
  },

  // ================================================================
  // Article 25: Data Protection by Design and by Default
  // ================================================================
  {
    control_id: 'GDPR-25.1',
    control_ref: 'Article 25(1)',
    framework: 'gdpr',
    section_id: 'art_25',
    title: { es: 'Protecci\u00f3n de datos desde el dise\u00f1o', en: 'Data protection by design' },
    description: { es: 'Implementar medidas t\u00e9cnicas apropiadas como mTLS, encabezados de seguridad y configuraciones seguras por defecto', en: 'Implement appropriate technical measures such as mTLS, security headers and secure defaults' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 25: Protecci\u00f3n de datos desde el dise\u00f1o y por defecto', en: 'Article 25: Data protection by design and by default' },
      clause: '25(1)',
      official_text: { es: 'el responsable del tratamiento aplicar\u00e1 medidas t\u00e9cnicas y organizativas apropiadas dise\u00f1adas para aplicar los principios de protecci\u00f3n de datos', en: 'the controller shall...implement appropriate technical and organisational measures...designed to implement data-protection principles' },
      applicability_note: { es: 'En Cloudflare: mTLS (Authenticated Origin Pulls), encabezados de seguridad y configuraciones seguras por defecto implementan protecci\u00f3n por dise\u00f1o', en: 'In Cloudflare: mTLS (Authenticated Origin Pulls), security headers and secure defaults implement protection by design' },
    },
    required_data_sources: ['authenticated_origin_pulls', 'zone_settings.security_header'],
    required_permissions: ['SSL and Certificates:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-8.3.1', clause: '8.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.I', clause: 'Art. 36.I' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar mTLS y configurar encabezados de seguridad', en: 'Enable mTLS and configure security headers' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n por dise\u00f1o, las vulnerabilidades se descubren reactivamente en lugar de prevenirse', en: 'Without protection by design, vulnerabilities are discovered reactively instead of prevented' },
      steps: [
        { order: 1, action: { es: 'Habilitar Authenticated Origin Pulls (mTLS)', en: 'Enable Authenticated Origin Pulls (mTLS)' }, where: { es: 'Dashboard > SSL/TLS > Servidor de origen', en: 'Dashboard > SSL/TLS > Origin Server' }, detail: { es: 'Activar autenticaci\u00f3n mutua TLS entre Cloudflare y el origen', en: 'Enable mutual TLS authentication between Cloudflare and origin' } },
        { order: 2, action: { es: 'Configurar encabezados de seguridad', en: 'Configure security headers' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Habilitar HSTS y X-Content-Type-Options: nosniff', en: 'Enable HSTS and X-Content-Type-Options: nosniff' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const aopCheck = enrichedOrPerm(ctx, ctx.enriched_data.authenticated_origin_pulls, 'SSL and Certificates:Read', ['authenticated_origin_pulls']);
      const aopEnabled = !aopCheck && ctx.enriched_data.authenticated_origin_pulls?.enabled === true;
      const hsts = getHsts(ctx);
      const hstsEnabled = hsts.enabled && hsts.max_age >= 86400;
      const nosniff = hsts.nosniff;
      const checks = [aopEnabled, hstsEnabled, nosniff];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `mTLS: on, HSTS: on (max_age=${hsts.max_age}), nosniff: on`, 'mTLS + HSTS + nosniff', 'Data protection by design measures are fully implemented.', ['authenticated_origin_pulls', 'zone_settings.security_header']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `mTLS: ${aopEnabled ? 'on' : 'off'}, HSTS: ${hstsEnabled ? 'on' : 'off'}, nosniff: ${nosniff ? 'on' : 'off'}`, 'mTLS + HSTS + nosniff', `${passed}/3 data protection by design measures active.`, ['authenticated_origin_pulls', 'zone_settings.security_header']);
      if (aopCheck) return aopCheck;
      return ev('fail', 0, 'No data protection by design measures active', 'mTLS + HSTS + nosniff', 'No technical measures for data protection by design are configured.', ['authenticated_origin_pulls', 'zone_settings.security_header']);
    },
  },
  {
    control_id: 'GDPR-25.2',
    control_ref: 'Article 25(2)',
    framework: 'gdpr',
    section_id: 'art_25',
    title: { es: 'Protecci\u00f3n de datos por defecto', en: 'Data protection by default' },
    description: { es: 'Configuraciones de seguridad estrictas por defecto: TLS m\u00ednimo, SSL estricto y HSTS', en: 'Strict security settings by default: minimum TLS, strict SSL and HSTS' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 25: Protecci\u00f3n de datos desde el dise\u00f1o y por defecto', en: 'Article 25: Data protection by design and by default' },
      clause: '25(2)',
      official_text: { es: 'el responsable del tratamiento aplicar\u00e1 las medidas t\u00e9cnicas y organizativas apropiadas para garantizar que, por defecto, solo se traten los datos personales necesarios', en: 'the controller shall implement appropriate technical and organisational measures for ensuring that, by default, only personal data which are necessary...' },
      applicability_note: { es: 'En Cloudflare: TLS m\u00ednimo 1.2+, SSL estricto y HSTS con subdomains garantizan seguridad por defecto', en: 'In Cloudflare: Minimum TLS 1.2+, strict SSL and HSTS with subdomains ensure security by default' },
    },
    required_data_sources: ['zone_settings.min_tls_version', 'zone_settings.ssl', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.2', clause: '4.2.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.21', clause: 'A.8.21' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
    ],
    remediation_template: {
      summary: { es: 'Configurar TLS m\u00ednimo 1.2, SSL estricto y HSTS completo', en: 'Configure minimum TLS 1.2, strict SSL and full HSTS' },
      risk_if_ignored: { es: 'Configuraciones por defecto d\u00e9biles permiten conexiones inseguras a datos personales', en: 'Weak default settings allow insecure connections to personal data' },
      steps: [
        { order: 1, action: { es: 'Establecer TLS m\u00ednimo 1.2', en: 'Set minimum TLS 1.2' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Configurar la versi\u00f3n m\u00ednima de TLS en 1.2 o superior', en: 'Set the minimum TLS version to 1.2 or higher' } },
        { order: 2, action: { es: 'Configurar SSL en Full (Strict)', en: 'Set SSL to Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Asegurar cifrado de extremo a extremo con validaci\u00f3n de certificado', en: 'Ensure end-to-end encryption with certificate validation' } },
        { order: 3, action: { es: 'Habilitar HSTS con subdominios', en: 'Enable HSTS with subdomains' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar HSTS con max-age \u226512 meses e incluir subdominios', en: 'Enable HSTS with max-age \u226512 months and include subdomains' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls = s(ctx, 'min_tls_version');
      const ssl = s(ctx, 'ssl');
      const hsts = getHsts(ctx);
      const tlsOk = tls === '1.2' || tls === '1.3';
      const sslOk = ssl === 'strict' || ssl === 'full_strict';
      const hstsOk = hsts.enabled && hsts.max_age >= 15552000 && hsts.include_subdomains;
      const checks = [tlsOk, sslOk, hstsOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `TLS min: ${tls}, SSL: ${ssl}, HSTS: on (max_age=${hsts.max_age}, subdomains)`, 'TLS 1.2+ / Full Strict / HSTS', 'Secure defaults fully configured for data protection by default.', ['zone_settings.min_tls_version', 'zone_settings.ssl', 'zone_settings.security_header']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `TLS min: ${tls || 'unknown'}, SSL: ${ssl || 'unknown'}, HSTS: ${hsts.enabled ? 'on' : 'off'}`, 'TLS 1.2+ / Full Strict / HSTS', `${passed}/3 secure defaults active. Strengthen all settings for Art. 25(2).`, ['zone_settings.min_tls_version', 'zone_settings.ssl', 'zone_settings.security_header']);
      return ev('fail', 0, `TLS min: ${tls || 'unknown'}, SSL: ${ssl || 'unknown'}, HSTS: off`, 'TLS 1.2+ / Full Strict / HSTS', 'Security defaults are not configured. Personal data may be exposed through insecure connections.', ['zone_settings.min_tls_version', 'zone_settings.ssl', 'zone_settings.security_header']);
    },
  },

  // ================================================================
  // Article 32: Security of Processing
  // ================================================================
  {
    control_id: 'GDPR-32.1.a',
    control_ref: 'Article 32(1)(a)',
    framework: 'gdpr',
    section_id: 'art_32',
    title: { es: 'Cifrado de datos personales', en: 'Encryption of personal data' },
    description: { es: 'Seudonimizaci\u00f3n y cifrado de datos personales mediante SSL estricto, suites de cifrado y certificados', en: 'Pseudonymisation and encryption of personal data through strict SSL, cipher suites and certificates' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 32: Seguridad del tratamiento', en: 'Article 32: Security of processing' },
      clause: '32(1)(a)',
      official_text: { es: 'la seudonimizaci\u00f3n y el cifrado de datos personales', en: 'the pseudonymisation and encryption of personal data' },
      applicability_note: { es: 'En Cloudflare: Modo SSL estricto, suites de cifrado fuertes y certificados v\u00e1lidos aseguran el cifrado de datos en tr\u00e1nsito', en: 'In Cloudflare: Strict SSL mode, strong cipher suites and valid certificates ensure encryption of data in transit' },
    },
    required_data_sources: ['zone_settings.ssl', 'cipher_suites', 'edge_certificates'],
    required_permissions: ['Zone:Read', 'SSL and Certificates:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1.2', clause: '4.2.1.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19.III' },
    ],
    remediation_template: {
      summary: { es: 'Configurar SSL estricto, verificar cifrados fuertes y certificados v\u00e1lidos', en: 'Configure strict SSL, verify strong ciphers and valid certificates' },
      risk_if_ignored: { es: 'Sin cifrado adecuado, datos personales pueden ser interceptados violando el GDPR', en: 'Without adequate encryption, personal data can be intercepted violating GDPR' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL Full (Strict)', en: 'Set SSL Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar modo Completo (estricto) para cifrado verificado de extremo a extremo', en: 'Select Full (strict) mode for verified end-to-end encryption' } },
        { order: 2, action: { es: 'Verificar suites de cifrado', en: 'Verify cipher suites' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Asegurar que solo se usen cifrados fuertes (AEAD/ECDHE)', en: 'Ensure only strong ciphers are used (AEAD/ECDHE)' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const sslStrict = ssl === 'strict' || ssl === 'full_strict';
      const ciphers = ctx.enriched_data.cipher_suites;
      const ciphersOk = ciphers ? ciphers.weak_ciphers.length === 0 : true;
      const certs = ctx.enriched_data.edge_certificates;
      const certsOk = certs ? certs.total > 0 && !certs.any_expired : true;
      const checks = [sslStrict, ciphersOk, certsOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `SSL: ${ssl}, ciphers: strong, certs: valid`, 'Strict SSL + strong ciphers + valid certs', 'Encryption of personal data meets GDPR Art. 32(1)(a) requirements.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
      if (sslStrict) return ev('partial', 70, `SSL: ${ssl}, ciphers: ${ciphersOk ? 'ok' : 'weak found'}, certs: ${certsOk ? 'ok' : 'issues'}`, 'Strict SSL + strong ciphers + valid certs', 'SSL is strict but cipher or certificate issues detected.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `SSL: ${ssl || 'unknown'}, ciphers: ${ciphersOk ? 'ok' : 'weak found'}, certs: ${certsOk ? 'ok' : 'issues'}`, 'Strict SSL + strong ciphers + valid certs', 'Partial encryption configuration. Upgrade SSL mode and verify ciphers.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
      return ev('fail', 0, `SSL: ${ssl || 'unknown'}`, 'Strict SSL + strong ciphers + valid certs', 'Encryption configuration does not meet GDPR Art. 32(1)(a) requirements.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
    },
  },
  {
    control_id: 'GDPR-32.1.b',
    control_ref: 'Article 32(1)(b)',
    framework: 'gdpr',
    section_id: 'art_32',
    title: { es: 'Confidencialidad e integridad', en: 'Confidentiality and integrity' },
    description: { es: 'Garantizar la confidencialidad e integridad continuas de los sistemas mediante WAF, control de acceso y reglas IP', en: 'Ensure ongoing confidentiality and integrity of systems through WAF, access control and IP rules' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 32: Seguridad del tratamiento', en: 'Article 32: Security of processing' },
      clause: '32(1)(b)',
      official_text: { es: 'la capacidad de garantizar la confidencialidad, integridad, disponibilidad y resiliencia permanentes de los sistemas y servicios de tratamiento', en: 'the ability to ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services' },
      applicability_note: { es: 'En Cloudflare: WAF administrado, reglas WAF personalizadas y reglas de acceso IP protegen la confidencialidad e integridad de los sistemas', en: 'In Cloudflare: Managed WAF, custom WAF rules and IP access rules protect the confidentiality and integrity of systems' },
    },
    required_data_sources: ['rulesets', 'ip_access_rules'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.IV', clause: 'Art. 36.IV' },
    ],
    remediation_template: {
      summary: { es: 'Activar WAF administrado y configurar reglas de acceso IP', en: 'Activate managed WAF and configure IP access rules' },
      risk_if_ignored: { es: 'Sin WAF ni control de acceso, los sistemas est\u00e1n expuestos a ataques que comprometen datos personales', en: 'Without WAF or access control, systems are exposed to attacks that compromise personal data' },
      steps: [
        { order: 1, action: { es: 'Activar WAF administrado', en: 'Enable managed WAF' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar el conjunto de reglas administradas de Cloudflare', en: 'Deploy the Cloudflare managed ruleset' } },
        { order: 2, action: { es: 'Configurar reglas de acceso IP', en: 'Configure IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'A\u00f1adir reglas para bloquear tr\u00e1fico no autorizado', en: 'Add rules to block unauthorized traffic' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const customRules = getCustomWafRules(ctx);
      const ipRules = ctx.enriched_data.ip_access_rules;
      const hasIpRules = ipRules ? ipRules.total > 0 : false;
      const checks = [waf, customRules.length > 0, hasIpRules];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `WAF: active, custom rules: ${customRules.length}, IP rules: ${ipRules?.total || 0}`, 'WAF + custom rules + IP rules', 'Comprehensive confidentiality and integrity controls active.', ['rulesets', 'ip_access_rules']);
      if (waf) return ev('partial', 60, `WAF: active, custom rules: ${customRules.length}, IP rules: ${hasIpRules ? ipRules!.total : 0}`, 'WAF + custom rules + IP rules', 'WAF is active but additional access controls recommended for full coverage.', ['rulesets', 'ip_access_rules']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `WAF: ${waf ? 'active' : 'inactive'}, custom rules: ${customRules.length}, IP rules: ${hasIpRules ? ipRules!.total : 0}`, 'WAF + custom rules + IP rules', `${passed}/3 confidentiality/integrity controls active.`, ['rulesets', 'ip_access_rules']);
      return ev('fail', 0, 'No WAF or access control configured', 'WAF + custom rules + IP rules', 'No confidentiality or integrity controls detected. Systems processing personal data are unprotected.', ['rulesets', 'ip_access_rules']);
    },
  },
  {
    control_id: 'GDPR-32.1.c',
    control_ref: 'Article 32(1)(c)',
    framework: 'gdpr',
    section_id: 'art_32',
    title: { es: 'Disponibilidad y resiliencia', en: 'Availability and resilience' },
    description: { es: 'Capacidad de restaurar la disponibilidad y el acceso a datos personales mediante health checks, protecci\u00f3n DDoS y rate limiting', en: 'Ability to restore availability and access to personal data through health checks, DDoS protection and rate limiting' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 32: Seguridad del tratamiento', en: 'Article 32: Security of processing' },
      clause: '32(1)(c)',
      official_text: { es: 'la capacidad de restaurar la disponibilidad y el acceso a los datos personales de forma r\u00e1pida en caso de incidente f\u00edsico o t\u00e9cnico', en: 'the ability to restore the availability and access to personal data in a timely manner in the event of a physical or technical incident' },
      applicability_note: { es: 'En Cloudflare: Health Checks, protecci\u00f3n DDoS integrada y reglas de rate limiting proporcionan resiliencia y disponibilidad', en: 'In Cloudflare: Health Checks, built-in DDoS protection and rate limiting rules provide resilience and availability' },
    },
    required_data_sources: ['health_checks', 'rulesets'],
    required_permissions: ['Health Checks:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-11.6.1', clause: '11.6.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.6', clause: 'A.8.6' },
      { framework: 'soc2_type2', control_id: 'SOC2-A1.1', clause: 'A1.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.VI', clause: 'Art. 36.VI' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Health Checks y reglas de rate limiting para garantizar disponibilidad', en: 'Configure Health Checks and rate limiting rules to ensure availability' },
      risk_if_ignored: { es: 'Sin monitoreo y protecci\u00f3n, ataques DDoS o fallos pueden hacer inaccesibles los datos personales', en: 'Without monitoring and protection, DDoS attacks or failures can make personal data inaccessible' },
      steps: [
        { order: 1, action: { es: 'Crear Health Checks', en: 'Create Health Checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Configurar verificaciones de salud para endpoints cr\u00edticos', en: 'Configure health checks for critical endpoints' } },
        { order: 2, action: { es: 'Configurar rate limiting', en: 'Configure rate limiting' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas de limitaci\u00f3n', en: 'Dashboard > Security > WAF > Rate limiting rules' }, detail: { es: 'Proteger contra agotamiento de recursos por abuso', en: 'Protect against resource exhaustion from abuse' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hc = ctx.enriched_data.health_checks;
      const rl = getRateLimitRules(ctx);
      const hasHC = hc ? hc.total > 0 : false;
      const hasRL = rl.length > 0;
      if (hasHC && hasRL) return ev('pass', 100, `${hc!.total} health checks, ${rl.length} rate limit rules`, 'Health Checks + Rate Limiting', 'Availability and resilience controls are configured for Art. 32(1)(c).', ['health_checks', 'rulesets']);
      if (hasHC || hasRL) return ev('partial', 50, `Health checks: ${hasHC ? hc!.total : 0}, Rate limits: ${rl.length}`, 'Both Health Checks + Rate Limiting', 'Partial availability controls. Configure both for full resilience.', ['health_checks', 'rulesets']);
      if (!ctx.available_permissions.includes('Health Checks:Read')) return ev('insufficient_permissions', 0, 'N/A', 'Health Checks + Rate Limiting', 'Token lacks Health Checks:Read permission to evaluate availability controls.', ['health_checks', 'rulesets']);
      return ev('fail', 0, 'No availability controls configured', 'Health Checks + Rate Limiting', 'No health checks or rate limiting configured. Personal data availability is at risk.', ['health_checks', 'rulesets']);
    },
  },
  {
    control_id: 'GDPR-32.1.d',
    control_ref: 'Article 32(1)(d)',
    framework: 'gdpr',
    section_id: 'art_32',
    title: { es: 'Pruebas y evaluaci\u00f3n', en: 'Testing and assessment' },
    description: { es: 'Proceso de pruebas y evaluaci\u00f3n regulares de medidas de seguridad mediante Page Shield, monitoreo WAF y escaneo de seguridad', en: 'Process for regularly testing and assessing security measures through Page Shield, WAF monitoring and security scanning' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 32: Seguridad del tratamiento', en: 'Article 32: Security of processing' },
      clause: '32(1)(d)',
      official_text: { es: 'un proceso de verificaci\u00f3n, evaluaci\u00f3n y valoraci\u00f3n regulares de la eficacia de las medidas t\u00e9cnicas y organizativas', en: 'a process for regularly testing, assessing and evaluating the effectiveness of technical and organisational measures' },
      applicability_note: { es: 'En Cloudflare: Page Shield monitorea scripts de terceros, WAF administrado se actualiza continuamente y OWASP detecta vulnerabilidades', en: 'In Cloudflare: Page Shield monitors third-party scripts, managed WAF is continuously updated and OWASP detects vulnerabilities' },
    },
    required_data_sources: ['page_shield', 'rulesets'],
    required_permissions: ['Page Shield:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.5.5', clause: '6.5.5' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.28', clause: 'A.8.28' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.1', clause: 'CC7.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.V', clause: 'Art. 36.V' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Page Shield y verificar que el WAF OWASP est\u00e9 activo', en: 'Enable Page Shield and verify OWASP WAF is active' },
      risk_if_ignored: { es: 'Sin pruebas regulares, vulnerabilidades pueden pasar desapercibidas comprometiendo datos personales', en: 'Without regular testing, vulnerabilities can go unnoticed compromising personal data' },
      steps: [
        { order: 1, action: { es: 'Activar Page Shield', en: 'Enable Page Shield' }, where: { es: 'Dashboard > Seguridad > Page Shield', en: 'Dashboard > Security > Page Shield' }, detail: { es: 'Habilitar monitoreo continuo de scripts del lado del cliente', en: 'Enable continuous monitoring of client-side scripts' } },
        { order: 2, action: { es: 'Verificar OWASP Core Rule Set', en: 'Verify OWASP Core Rule Set' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Confirmar que el OWASP CRS est\u00e1 activo para detecci\u00f3n continua de vulnerabilidades', en: 'Confirm OWASP CRS is active for continuous vulnerability detection' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/page-shield/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      min_plan: 'business',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ps = ctx.enriched_data.page_shield;
      const owasp = hasOwaspRules(ctx);
      const psActive = ps?.enabled === true;
      if (psActive && owasp) return ev('pass', 100, `Page Shield active (${ps!.total_scripts} scripts), OWASP active`, 'Page Shield + OWASP', 'Regular testing and assessment measures are active for Art. 32(1)(d).', ['page_shield', 'rulesets']);
      if (psActive || owasp) return ev('partial', 50, `Page Shield: ${psActive ? 'on' : 'off'}, OWASP: ${owasp ? 'on' : 'off'}`, 'Both Page Shield + OWASP', 'Partial testing coverage. Enable both for comprehensive assessment.', ['page_shield', 'rulesets']);
      if (!ctx.available_permissions.includes('Page Shield:Read')) return ev('insufficient_permissions', 0, 'N/A', 'Page Shield + OWASP', 'Token lacks Page Shield:Read permission.', ['page_shield', 'rulesets']);
      return ev('fail', 0, 'No testing or assessment tools active', 'Page Shield + OWASP', 'No regular testing or assessment tools configured for security measures.', ['page_shield', 'rulesets']);
    },
  },
  {
    control_id: 'GDPR-32.2',
    control_ref: 'Article 32(2)',
    framework: 'gdpr',
    section_id: 'art_32',
    title: { es: 'Proceso de evaluaci\u00f3n de riesgos', en: 'Risk assessment process' },
    description: { es: 'Proceso organizacional de evaluaci\u00f3n de riesgos para determinar el nivel de seguridad adecuado', en: 'Organizational risk assessment process to determine the appropriate level of security' },
    severity: 'medium',
    evaluation_method: 'manual_flag',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 32: Seguridad del tratamiento', en: 'Article 32: Security of processing' },
      clause: '32(2)',
      official_text: { es: 'Al evaluar el nivel adecuado de seguridad, se tendr\u00e1n en cuenta en particular los riesgos que presente el tratamiento', en: 'In assessing the appropriate level of security account shall be taken in particular of the risks that are presented by processing' },
      applicability_note: { es: 'Este es un proceso organizacional que no puede verificarse autom\u00e1ticamente mediante configuraciones de Cloudflare. Requiere validaci\u00f3n manual de que existe un proceso formal de evaluaci\u00f3n de riesgos', en: 'This is an organizational process that cannot be automatically verified through Cloudflare configurations. Requires manual validation that a formal risk assessment process exists' },
    },
    required_data_sources: [],
    required_permissions: [],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.8', clause: 'A.8.8' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.1', clause: 'CC7.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.V', clause: 'Art. 19.V' },
    ],
    remediation_template: {
      summary: { es: 'Documentar un proceso formal de evaluaci\u00f3n de riesgos', en: 'Document a formal risk assessment process' },
      risk_if_ignored: { es: 'Sin evaluaci\u00f3n de riesgos, las medidas de seguridad pueden ser insuficientes o desproporcionadas', en: 'Without risk assessment, security measures may be insufficient or disproportionate' },
      steps: [
        { order: 1, action: { es: 'Crear proceso de evaluaci\u00f3n de riesgos', en: 'Create risk assessment process' }, where: { es: 'Documentaci\u00f3n interna de la organizaci\u00f3n', en: 'Internal organization documentation' }, detail: { es: 'Documentar un proceso formal que eval\u00fae riesgos del tratamiento de datos personales y determine medidas de seguridad adecuadas', en: 'Document a formal process that assesses risks of personal data processing and determines appropriate security measures' } },
        { order: 2, action: { es: 'Realizar evaluaci\u00f3n peri\u00f3dica', en: 'Conduct periodic assessment' }, where: { es: 'Seg\u00fan pol\u00edtica interna', en: 'Per internal policy' }, detail: { es: 'Ejecutar la evaluaci\u00f3n de riesgos al menos anualmente y ante cambios significativos', en: 'Execute risk assessment at least annually and upon significant changes' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/reference/policies-compliances/',
      estimated_effort: 'days',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (_ctx) => {
      return ev('manual_required', 0, 'Requires manual verification', 'Documented risk assessment process', 'Art. 32(2) requires an organizational risk assessment process. This cannot be verified automatically through Cloudflare configurations. Mark as verified once your organization has a documented risk assessment process.', []);
    },
  },

  // ================================================================
  // Article 33: Breach Notification
  // ================================================================
  {
    control_id: 'GDPR-33.1',
    control_ref: 'Article 33(1)',
    framework: 'gdpr',
    section_id: 'art_33',
    title: { es: 'Capacidad de notificaci\u00f3n de brechas', en: 'Breach notification capability' },
    description: { es: 'Pol\u00edticas de notificaci\u00f3n y alertas de seguridad configuradas para detectar brechas en 72 horas', en: 'Notification policies and security alerts configured to detect breaches within 72 hours' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 33: Notificaci\u00f3n de violaciones de seguridad', en: 'Article 33: Notification of personal data breaches' },
      clause: '33(1)',
      official_text: { es: 'el responsable del tratamiento la notificar\u00e1 a la autoridad de control sin dilaci\u00f3n indebida y, de ser posible, a m\u00e1s tardar 72 horas despu\u00e9s de que haya tenido constancia de ella', en: 'the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the supervisory authority' },
      applicability_note: { es: 'En Cloudflare: Las pol\u00edticas de notificaci\u00f3n con alertas de seguridad y DDoS permiten detectar incidentes r\u00e1pidamente para cumplir con el plazo de 72 horas', en: 'In Cloudflare: Notification policies with security and DDoS alerts enable rapid incident detection to meet the 72-hour deadline' },
    },
    required_data_sources: ['notification_policies'],
    required_permissions: ['Notifications:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.4.1', clause: '10.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.V', clause: 'Art. 36.V' },
    ],
    remediation_template: {
      summary: { es: 'Configurar alertas de seguridad y DDoS para detecci\u00f3n temprana de brechas', en: 'Configure security and DDoS alerts for early breach detection' },
      risk_if_ignored: { es: 'Sin alertas, las brechas pueden pasar desapercibidas m\u00e1s de 72 horas, violando el GDPR', en: 'Without alerts, breaches can go unnoticed for more than 72 hours, violating GDPR' },
      steps: [
        { order: 1, action: { es: 'Configurar alertas de seguridad', en: 'Configure security alerts' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Crear pol\u00edticas para alertas DDoS, WAF, SSL y eventos de seguridad', en: 'Create policies for DDoS, WAF, SSL and security event alerts' } },
        { order: 2, action: { es: 'Verificar destinatarios', en: 'Verify recipients' }, where: { es: 'Dashboard > Notificaciones > Destinos', en: 'Dashboard > Notifications > Destinations' }, detail: { es: 'Asegurar que las alertas lleguen al equipo de respuesta a incidentes', en: 'Ensure alerts reach the incident response team' } },
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
      if (np.has_security_alerts && np.has_ddos_alerts) return ev('pass', 100, `${np.total} alert policies (security + DDoS active)`, 'Security + DDoS alerts', 'Breach notification capability meets GDPR Art. 33(1) \u2014 security and DDoS alerts enable detection within 72 hours.', ['notification_policies'], np);
      if (np.has_security_alerts || np.has_ddos_alerts) return ev('partial', 60, `${np.total} alert policies (security: ${np.has_security_alerts ? 'yes' : 'no'}, DDoS: ${np.has_ddos_alerts ? 'yes' : 'no'})`, 'Security + DDoS alerts', 'Some alert policies exist but both security and DDoS alerts are needed for full breach detection capability.', ['notification_policies'], np);
      if (np.total > 0) return ev('partial', 30, `${np.total} alert policies but no security-specific alerts`, 'Security + DDoS alerts', 'Alert policies exist but none are security-specific. Configure security and DDoS alerts.', ['notification_policies'], np);
      return ev('fail', 0, 'No notification policies', 'Security + DDoS alerts', 'No notification policies configured. Breaches may not be detected within the 72-hour GDPR requirement.', ['notification_policies']);
    },
  },
  {
    control_id: 'GDPR-33.2',
    control_ref: 'Article 33(2)',
    framework: 'gdpr',
    section_id: 'art_33',
    title: { es: 'Documentaci\u00f3n de brechas', en: 'Breach documentation' },
    description: { es: 'Registros de auditor\u00eda y Logpush configurados para documentaci\u00f3n forense de brechas de datos', en: 'Audit logs and Logpush configured for forensic documentation of data breaches' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art\u00edculo 33: Notificaci\u00f3n de violaciones de seguridad', en: 'Article 33: Notification of personal data breaches' },
      clause: '33(2)',
      official_text: { es: 'El encargado del tratamiento notificar\u00e1 al responsable sin dilaci\u00f3n indebida tras tener conocimiento de una violaci\u00f3n de datos personales', en: 'The processor shall notify the controller without undue delay after becoming aware of a personal data breach' },
      applicability_note: { es: 'En Cloudflare: Audit Logs y Logpush proporcionan la documentaci\u00f3n forense necesaria para investigar y reportar brechas de datos personales', en: 'In Cloudflare: Audit Logs and Logpush provide the forensic documentation necessary to investigate and report personal data breaches' },
    },
    required_data_sources: ['audit_logs', 'logpush_jobs'],
    required_permissions: ['Account Access: Audit Logs', 'Logs:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.2', clause: '10.2.2' },
      { framework: 'pci_dss_4', control_id: 'PCI-10.7.1', clause: '10.7.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Audit Logs y Logpush para documentaci\u00f3n forense', en: 'Configure Audit Logs and Logpush for forensic documentation' },
      risk_if_ignored: { es: 'Sin documentaci\u00f3n forense, es imposible investigar brechas y cumplir con los requisitos de notificaci\u00f3n del GDPR', en: 'Without forensic documentation, it is impossible to investigate breaches and comply with GDPR notification requirements' },
      steps: [
        { order: 1, action: { es: 'Verificar Audit Logs activos', en: 'Verify Audit Logs active' }, where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Confirmar que los eventos de auditor\u00eda se registran correctamente', en: 'Confirm audit events are being recorded correctly' } },
        { order: 2, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Exportar logs de firewall y HTTP para retenci\u00f3n forense', en: 'Export firewall and HTTP logs for forensic retention' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const auditOk = ctx.enriched_data.audit_logs?.available === true && ctx.enriched_data.audit_logs.recent_count > 0;
      const logpushOk = ctx.enriched_data.logpush_jobs?.total ? ctx.enriched_data.logpush_jobs.total > 0 : false;
      const hasFirewallLogs = ctx.enriched_data.logpush_jobs?.has_firewall_logs === true;
      if (auditOk && logpushOk && hasFirewallLogs) return ev('pass', 100, `Audit logs active, Logpush active with firewall logs`, 'Audit logs + Logpush (firewall)', 'Forensic documentation capability meets GDPR Art. 33(2) requirements.', ['audit_logs', 'logpush_jobs']);
      if (auditOk && logpushOk) return ev('partial', 70, `Audit logs active, Logpush active (no firewall logs)`, 'Audit logs + Logpush (firewall)', 'Logging active but firewall logs not exported. Add firewall event Logpush for breach investigation.', ['audit_logs', 'logpush_jobs']);
      if (auditOk || logpushOk) return ev('partial', 40, `Audit logs: ${auditOk ? 'active' : 'inactive'}, Logpush: ${logpushOk ? 'active' : 'inactive'}`, 'Both audit logs + Logpush', 'Partial breach documentation. Enable both for full forensic capability.', ['audit_logs', 'logpush_jobs']);
      const hasPerm1 = ctx.available_permissions.includes('Account Access: Audit Logs');
      const hasPerm2 = ctx.available_permissions.includes('Logs:Read');
      if (!hasPerm1 && !hasPerm2) return ev('insufficient_permissions', 0, 'N/A', 'Audit Logs + Logpush', 'Token lacks Account Access: Audit Logs and Logs:Read permissions.', ['audit_logs', 'logpush_jobs']);
      return ev('fail', 0, 'No forensic logging configured', 'Audit logs + Logpush', 'No audit logs or Logpush configured. Cannot document breaches as required by GDPR Art. 33(2).', ['audit_logs', 'logpush_jobs']);
    },
  },
];
