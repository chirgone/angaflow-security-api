/**
 * Anga Security \u2014 LFPDPPP Framework Controls
 *
 * Ley Federal de Protecci\u00f3n de Datos Personales en Posesi\u00f3n de los Particulares
 * y su Reglamento.
 *
 * 12 controls in 1 section: medidas_seguridad (Arts. 19 y 36)
 *
 * Art. 19 LFPDPPP: Medidas de seguridad administrativas, t\u00e9cnicas y f\u00edsicas.
 * Art. 36 Reglamento: Medidas de seguridad espec\u00edficas para protecci\u00f3n
 * de datos personales.
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules, getHsts } from './helpers';

export const LFPDPPP_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // Art\u00edculo 19 LFPDPPP \u2014 Medidas de Seguridad Generales
  // ================================================================

  // 1. LFPDPPP-19.I \u2014 Administrative security measures (manual)
  {
    control_id: 'LFPDPPP-19.I',
    control_ref: 'Art\u00edculo 19, fracci\u00f3n I',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Medidas de seguridad administrativas', en: 'Administrative security measures' },
    description: { es: 'Pol\u00edticas y procedimientos internos de seguridad para el tratamiento de datos personales', en: 'Internal security policies and procedures for personal data processing' },
    severity: 'high',
    evaluation_method: 'manual_flag',
    regulatory_reference: {
      section: { es: 'Art. 19 LFPDPPP: Medidas de Seguridad', en: 'Art. 19 LFPDPPP: Security Measures' },
      clause: '19.I',
      official_text: { es: 'Todo responsable que lleve a cabo tratamiento de datos personales deber\u00e1 establecer y mantener medidas de seguridad administrativas para la protecci\u00f3n de los datos personales', en: 'Every data controller that processes personal data shall establish and maintain administrative security measures for the protection of personal data' },
      applicability_note: { es: 'Requiere verificaci\u00f3n manual: la existencia de pol\u00edticas de seguridad documentadas, programas de capacitaci\u00f3n y asignaci\u00f3n de responsabilidades no puede determinarse a trav\u00e9s de la API de Cloudflare', en: 'Requires manual verification: the existence of documented security policies, training programs and assignment of responsibilities cannot be determined through the Cloudflare API' },
    },
    required_data_sources: [],
    required_permissions: [],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'gdpr', control_id: 'GDPR-25.1', clause: 'Art. 25(1)' },
    ],
    remediation_template: {
      summary: { es: 'Documentar pol\u00edticas de seguridad y procedimientos de tratamiento de datos personales', en: 'Document security policies and personal data processing procedures' },
      risk_if_ignored: { es: 'Sin pol\u00edticas administrativas, el INAI puede determinar incumplimiento del art\u00edculo 19 de la LFPDPPP e imponer sanciones', en: 'Without administrative policies, INAI may determine non-compliance with article 19 of LFPDPPP and impose sanctions' },
      steps: [
        { order: 1, action: { es: 'Elaborar pol\u00edtica de seguridad de datos personales', en: 'Create personal data security policy' }, where: { es: 'Documentaci\u00f3n interna de la organizaci\u00f3n', en: 'Organization internal documentation' }, detail: { es: 'Incluir inventario de datos, clasificaci\u00f3n, roles y responsabilidades conforme al art\u00edculo 61 del Reglamento', en: 'Include data inventory, classification, roles and responsibilities per article 61 of the Regulation' } },
        { order: 2, action: { es: 'Implementar programa de capacitaci\u00f3n', en: 'Implement training program' }, where: { es: 'Recursos Humanos / Cumplimiento', en: 'HR / Compliance' }, detail: { es: 'Capacitar a todo el personal que trate datos personales sobre sus obligaciones bajo la LFPDPPP', en: 'Train all personnel who process personal data on their obligations under LFPDPPP' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/reference/policies-compliances/',
      estimated_effort: 'days',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (_ctx) => {
      return ev(
        'manual_required',
        0,
        'Requiere verificaci\u00f3n manual',
        'Pol\u00edticas de seguridad administrativas documentadas',
        'Las medidas de seguridad administrativas (pol\u00edticas, capacitaci\u00f3n, asignaci\u00f3n de responsabilidades) deben verificarse manualmente fuera de la configuraci\u00f3n de Cloudflare.',
        [],
      );
    },
  },

  // 2. LFPDPPP-19.II \u2014 Physical security measures (manual)
  {
    control_id: 'LFPDPPP-19.II',
    control_ref: 'Art\u00edculo 19, fracci\u00f3n II',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Medidas de seguridad f\u00edsicas', en: 'Physical security measures' },
    description: { es: 'Controles de acceso f\u00edsico a los equipos e instalaciones donde se tratan datos personales', en: 'Physical access controls to equipment and facilities where personal data is processed' },
    severity: 'medium',
    evaluation_method: 'manual_flag',
    regulatory_reference: {
      section: { es: 'Art. 19 LFPDPPP: Medidas de Seguridad', en: 'Art. 19 LFPDPPP: Security Measures' },
      clause: '19.II',
      official_text: { es: 'Todo responsable que lleve a cabo tratamiento de datos personales deber\u00e1 establecer y mantener medidas de seguridad f\u00edsicas que permitan proteger los datos personales', en: 'Every data controller that processes personal data shall establish and maintain physical security measures to protect personal data' },
      applicability_note: { es: 'Cuando se utiliza infraestructura en la nube (Cloudflare), la seguridad f\u00edsica del centro de datos es responsabilidad del proveedor de servicios en la nube. Verificar los certificados de cumplimiento de Cloudflare (SOC 2, ISO 27001) como evidencia', en: 'When using cloud infrastructure (Cloudflare), physical data center security is the cloud provider responsibility. Verify Cloudflare compliance certificates (SOC 2, ISO 27001) as evidence' },
    },
    required_data_sources: [],
    required_permissions: [],
    cross_references: [
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.4', clause: 'CC6.4' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.12', clause: 'A.8.12' },
    ],
    remediation_template: {
      summary: { es: 'Verificar certificaciones de seguridad f\u00edsica del proveedor de nube y documentar controles propios', en: 'Verify cloud provider physical security certifications and document own controls' },
      risk_if_ignored: { es: 'Sin evidencia de medidas f\u00edsicas, se incumple la fracci\u00f3n II del art\u00edculo 19 y puede resultar en sanciones del INAI', en: 'Without evidence of physical measures, fraction II of article 19 is violated and may result in INAI sanctions' },
      steps: [
        { order: 1, action: { es: 'Obtener certificaciones SOC 2 e ISO 27001 de Cloudflare', en: 'Obtain SOC 2 and ISO 27001 certifications from Cloudflare' }, where: { es: 'https://www.cloudflare.com/trust-hub/compliance-resources/', en: 'https://www.cloudflare.com/trust-hub/compliance-resources/' }, detail: { es: 'Descargar y archivar los certificados vigentes como evidencia documental', en: 'Download and archive current certificates as documentary evidence' } },
        { order: 2, action: { es: 'Documentar controles f\u00edsicos de oficinas propias', en: 'Document physical controls of own offices' }, where: { es: 'Documentaci\u00f3n interna', en: 'Internal documentation' }, detail: { es: 'Incluir control de acceso, c\u00e1maras de seguridad, bit\u00e1coras de visitantes donde aplique', en: 'Include access control, security cameras, visitor logs where applicable' } },
      ],
      cloudflare_doc_url: 'https://www.cloudflare.com/trust-hub/compliance-resources/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (_ctx) => {
      return ev(
        'manual_required',
        0,
        'Requiere verificaci\u00f3n manual / N/A para infraestructura en la nube',
        'Controles de seguridad f\u00edsica documentados o certificaciones del proveedor',
        'Las medidas de seguridad f\u00edsicas deben verificarse manualmente. Para infraestructura en la nube, las certificaciones del proveedor (Cloudflare SOC 2, ISO 27001) sirven como evidencia.',
        [],
      );
    },
  },

  // 3. LFPDPPP-19.III \u2014 Technical encryption measures
  {
    control_id: 'LFPDPPP-19.III',
    control_ref: 'Art\u00edculo 19, fracci\u00f3n III',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Medidas t\u00e9cnicas de cifrado', en: 'Technical encryption measures' },
    description: { es: 'Mecanismos de cifrado para la protecci\u00f3n de datos personales en tr\u00e1nsito y almacenamiento', en: 'Encryption mechanisms for the protection of personal data in transit and at rest' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 19 LFPDPPP: Medidas de Seguridad', en: 'Art. 19 LFPDPPP: Security Measures' },
      clause: '19.III',
      official_text: { es: 'Todo responsable deber\u00e1 establecer y mantener medidas de seguridad t\u00e9cnicas que permitan proteger los datos personales contra da\u00f1o, p\u00e9rdida, alteraci\u00f3n, destrucci\u00f3n, o el uso, acceso o tratamiento no autorizado', en: 'Every data controller shall establish and maintain technical security measures that protect personal data against damage, loss, alteration, destruction, or unauthorized use, access or processing' },
      applicability_note: { es: 'En Cloudflare: El modo SSL Full (Strict), la versi\u00f3n m\u00ednima de TLS y las suites de cifrado verifican la protecci\u00f3n t\u00e9cnica en tr\u00e1nsito', en: 'In Cloudflare: SSL Full (Strict) mode, minimum TLS version and cipher suites verify technical protection in transit' },
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.min_tls_version', 'cipher_suites'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar SSL/TLS en modo Full (Strict) y TLS m\u00ednimo 1.2', en: 'Configure SSL/TLS in Full (Strict) mode and minimum TLS 1.2' },
      risk_if_ignored: { es: 'Sin cifrado adecuado, los datos personales pueden ser interceptados en tr\u00e1nsito, constituyendo una vulneraci\u00f3n conforme al art\u00edculo 63 de la LFPDPPP', en: 'Without adequate encryption, personal data can be intercepted in transit, constituting a breach per article 63 of LFPDPPP' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL/TLS en modo Full (Strict)', en: 'Set SSL/TLS to Full (Strict) mode' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar "Completo (estricto)" para cifrado de extremo a extremo verificado', en: 'Select "Full (strict)" for verified end-to-end encryption' } },
        { order: 2, action: { es: 'Establecer TLS m\u00ednimo en 1.2', en: 'Set minimum TLS to 1.2' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Establecer versi\u00f3n m\u00ednima de TLS en 1.2 para rechazar protocolos inseguros', en: 'Set minimum TLS version to 1.2 to reject insecure protocols' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const tls = s(ctx, 'min_tls_version');
      const ciphers = ctx.enriched_data.cipher_suites;
      const sslOk = ssl === 'strict' || ssl === 'full_strict';
      const tlsOk = tls === '1.2' || tls === '1.3';
      const cipherOk = ciphers ? ciphers.weak_ciphers.length === 0 : true;
      const checks = [sslOk, tlsOk, cipherOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `SSL: ${ssl}, TLS min: ${tls}, cifrados d\u00e9biles: 0`, 'SSL Full (Strict) + TLS 1.2+ + sin cifrados d\u00e9biles', 'Todas las medidas t\u00e9cnicas de cifrado est\u00e1n correctamente configuradas.', ['zone_settings.ssl', 'zone_settings.min_tls_version', 'cipher_suites']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `SSL: ${ssl || 'unknown'}, TLS min: ${tls || 'unknown'}, cifrados d\u00e9biles: ${ciphers?.weak_ciphers?.length ?? 'N/A'}`, 'SSL Full (Strict) + TLS 1.2+ + sin cifrados d\u00e9biles', `${passed}/3 controles t\u00e9cnicos de cifrado activos.`, ['zone_settings.ssl', 'zone_settings.min_tls_version', 'cipher_suites']);
      return ev('fail', 0, `SSL: ${ssl || 'off'}, TLS min: ${tls || 'unknown'}`, 'SSL Full (Strict) + TLS 1.2+ + sin cifrados d\u00e9biles', 'Las medidas t\u00e9cnicas de cifrado no cumplen con los requisitos del art\u00edculo 19.', ['zone_settings.ssl', 'zone_settings.min_tls_version', 'cipher_suites']);
    },
  },

  // 4. LFPDPPP-19.IV \u2014 Access control mechanisms
  {
    control_id: 'LFPDPPP-19.IV',
    control_ref: 'Art\u00edculo 19, fracci\u00f3n IV',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Mecanismos de control de acceso', en: 'Access control mechanisms' },
    description: { es: 'Controles de acceso l\u00f3gico que limitan el acceso a datos personales a personal autorizado', en: 'Logical access controls that restrict access to personal data to authorized personnel' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 19 LFPDPPP: Medidas de Seguridad', en: 'Art. 19 LFPDPPP: Security Measures' },
      clause: '19.IV',
      official_text: { es: 'El responsable deber\u00e1 establecer mecanismos que permitan identificar a quienes tengan acceso a los datos personales, as\u00ed como restringir dicho acceso \u00fanicamente a las personas autorizadas', en: 'The data controller shall establish mechanisms to identify who has access to personal data, as well as restrict such access only to authorized persons' },
      applicability_note: { es: 'En Cloudflare: Reglas de acceso IP, nivel de seguridad de la zona y Authenticated Origin Pulls (mTLS) act\u00faan como controles de acceso l\u00f3gico', en: 'In Cloudflare: IP access rules, zone security level and Authenticated Origin Pulls (mTLS) act as logical access controls' },
    },
    required_data_sources: ['ip_access_rules', 'zone_settings.security_level', 'authenticated_origin_pulls'],
    required_permissions: ['Firewall Services:Read', 'Zone:Read', 'SSL and Certificates:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-7.2.1', clause: '7.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar reglas de acceso IP, nivel de seguridad y mTLS', en: 'Configure IP access rules, security level and mTLS' },
      risk_if_ignored: { es: 'Sin controles de acceso, cualquier persona podr\u00eda acceder a los datos personales, violando el principio de confidencialidad del art\u00edculo 6 de la LFPDPPP', en: 'Without access controls, anyone could access personal data, violating the confidentiality principle of article 6 of LFPDPPP' },
      steps: [
        { order: 1, action: { es: 'Configurar reglas de acceso IP', en: 'Configure IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'Restringir el acceso por IP, pa\u00eds o ASN para limitar la exposici\u00f3n', en: 'Restrict access by IP, country or ASN to limit exposure' } },
        { order: 2, action: { es: 'Elevar nivel de seguridad', en: 'Increase security level' }, where: { es: 'Dashboard > Seguridad > Configuraci\u00f3n', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer nivel de seguridad en "Alto" o "Bajo ataque" seg\u00fan sea necesario', en: 'Set security level to "High" or "Under Attack" as needed' } },
        { order: 3, action: { es: 'Habilitar mTLS', en: 'Enable mTLS' }, where: { es: 'Dashboard > SSL/TLS > Servidor de origen', en: 'Dashboard > SSL/TLS > Origin Server' }, detail: { es: 'Activar Authenticated Origin Pulls para autenticaci\u00f3n mutua', en: 'Enable Authenticated Origin Pulls for mutual authentication' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/ip-access-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ipRules = ctx.enriched_data.ip_access_rules;
      const hasIpRules = ipRules ? ipRules.total > 0 : false;
      const secLevel = s(ctx, 'security_level');
      const secOk = secLevel === 'high' || secLevel === 'under_attack' || secLevel === 'medium';
      const aop = ctx.enriched_data.authenticated_origin_pulls;
      const mtlsOk = aop?.enabled === true;
      const checks = [hasIpRules, secOk, mtlsOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `IP rules: ${ipRules?.total || 0}, Security: ${secLevel}, mTLS: on`, 'IP rules + security level alto/medio + mTLS', 'Todos los controles de acceso l\u00f3gico est\u00e1n activos.', ['ip_access_rules', 'zone_settings.security_level', 'authenticated_origin_pulls']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `IP rules: ${hasIpRules ? 'configured' : 'none'}, Security: ${secLevel || 'unknown'}, mTLS: ${mtlsOk ? 'on' : 'off'}`, 'IP rules + security level alto/medio + mTLS', `${passed}/3 controles de acceso activos.`, ['ip_access_rules', 'zone_settings.security_level', 'authenticated_origin_pulls']);
      return ev('fail', 0, 'No access controls configured', 'IP rules + security level alto/medio + mTLS', 'Ning\u00fan control de acceso l\u00f3gico est\u00e1 configurado.', ['ip_access_rules', 'zone_settings.security_level', 'authenticated_origin_pulls']);
    },
  },

  // 5. LFPDPPP-19.V \u2014 Audit trail / logging
  {
    control_id: 'LFPDPPP-19.V',
    control_ref: 'Art\u00edculo 19, fracci\u00f3n V',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Registro de auditor\u00eda y bit\u00e1coras', en: 'Audit trail and logging' },
    description: { es: 'Bit\u00e1coras de acceso y operaciones realizadas sobre datos personales', en: 'Access logs and records of operations performed on personal data' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 19 LFPDPPP: Medidas de Seguridad', en: 'Art. 19 LFPDPPP: Security Measures' },
      clause: '19.V',
      official_text: { es: 'El responsable deber\u00e1 llevar un registro de los medios de almacenamiento de los datos personales y mantener bit\u00e1coras de acceso, operaci\u00f3n y gesti\u00f3n', en: 'The data controller shall maintain a record of personal data storage media and keep access, operation and management logs' },
      applicability_note: { es: 'En Cloudflare: Audit logs de la cuenta y Logpush para exportaci\u00f3n de logs de acceso HTTP y eventos de seguridad', en: 'In Cloudflare: Account audit logs and Logpush for exporting HTTP access logs and security events' },
    },
    required_data_sources: ['audit_logs', 'logpush_jobs'],
    required_permissions: ['Account Access: Audit Logs', 'Logs:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
      { framework: 'gdpr', control_id: 'GDPR-5.2', clause: 'Art. 5(2)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar audit logs y configurar Logpush para exportaci\u00f3n de bit\u00e1coras', en: 'Enable audit logs and configure Logpush for log export' },
      risk_if_ignored: { es: 'Sin bit\u00e1coras de auditor\u00eda, es imposible demostrar cumplimiento ante el INAI en caso de investigaci\u00f3n o vulneraci\u00f3n de datos', en: 'Without audit logs, it is impossible to demonstrate compliance to INAI in case of investigation or data breach' },
      steps: [
        { order: 1, action: { es: 'Verificar que los audit logs est\u00e9n habilitados', en: 'Verify audit logs are enabled' }, where: { es: 'Dashboard > Gestionar cuenta > Registro de auditor\u00eda', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Los audit logs est\u00e1n disponibles para todos los planes; verificar que sean accesibles', en: 'Audit logs are available on all plans; verify they are accessible' } },
        { order: 2, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Crear trabajos de Logpush para HTTP requests y eventos de firewall a un destino de almacenamiento', en: 'Create Logpush jobs for HTTP requests and firewall events to a storage destination' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const auditLogs = ctx.enriched_data.audit_logs;
      const logpush = ctx.enriched_data.logpush_jobs;
      const hasAuditLogs = auditLogs?.available === true && auditLogs.recent_count > 0;
      const hasLogpush = logpush ? logpush.total > 0 : false;
      if (hasAuditLogs && hasLogpush) return ev('pass', 100, `Audit logs: ${auditLogs!.recent_count} recientes, Logpush: ${logpush!.total} trabajos`, 'Audit logs + Logpush activos', 'Bit\u00e1coras de auditor\u00eda y exportaci\u00f3n de logs est\u00e1n correctamente configurados.', ['audit_logs', 'logpush_jobs']);
      if (hasAuditLogs || hasLogpush) return ev('partial', 50, `Audit logs: ${hasAuditLogs ? 'active' : 'inactive'}, Logpush: ${hasLogpush ? 'active' : 'inactive'}`, 'Audit logs + Logpush activos', 'Solo una de las dos fuentes de bit\u00e1coras est\u00e1 configurada.', ['audit_logs', 'logpush_jobs']);
      // Check permissions before returning fail
      const auditCheck = enrichedOrPerm(ctx, auditLogs, 'Account Access: Audit Logs', ['audit_logs']);
      if (auditCheck) return auditCheck;
      return ev('fail', 0, 'Sin bit\u00e1coras de auditor\u00eda ni Logpush', 'Audit logs + Logpush activos', 'No se detectaron bit\u00e1coras de auditor\u00eda ni trabajos de Logpush configurados.', ['audit_logs', 'logpush_jobs']);
    },
  },

  // ================================================================
  // Art\u00edculo 36 Reglamento \u2014 Medidas de Seguridad Espec\u00edficas
  // ================================================================

  // 6. LFPDPPP-36.I \u2014 Security breach notification preparedness
  {
    control_id: 'LFPDPPP-36.I',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n I del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Preparaci\u00f3n para notificaci\u00f3n de vulneraciones', en: 'Security breach notification preparedness' },
    description: { es: 'Pol\u00edticas de notificaci\u00f3n y alertas configuradas para detectar y comunicar vulneraciones de seguridad', en: 'Notification policies and alerts configured to detect and communicate security breaches' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.I',
      official_text: { es: 'El responsable deber\u00e1 contar con una pol\u00edtica de notificaci\u00f3n de vulneraciones de seguridad que incluya procedimientos para la comunicaci\u00f3n oportuna al titular y a la autoridad', en: 'The data controller shall have a security breach notification policy that includes procedures for timely communication to the data subject and to the authority' },
      applicability_note: { es: 'En Cloudflare: Las pol\u00edticas de notificaci\u00f3n (alertas de seguridad, SSL, DDoS) permiten detectar incidentes oportunamente para cumplir con el art\u00edculo 20 de la LFPDPPP', en: 'In Cloudflare: Notification policies (security, SSL, DDoS alerts) enable timely incident detection to comply with article 20 of LFPDPPP' },
    },
    required_data_sources: ['notification_policies'],
    required_permissions: ['Notifications:Read'],
    cross_references: [
      { framework: 'gdpr', control_id: 'GDPR-33.1', clause: 'Art. 33(1)' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
    ],
    remediation_template: {
      summary: { es: 'Configurar pol\u00edticas de notificaci\u00f3n de alertas de seguridad en Cloudflare', en: 'Configure security alert notification policies in Cloudflare' },
      risk_if_ignored: { es: 'Sin alertas configuradas, las vulneraciones de seguridad pueden pasar desapercibidas, incumpliendo la obligaci\u00f3n de notificaci\u00f3n al titular (art. 20 LFPDPPP)', en: 'Without configured alerts, security breaches may go undetected, violating the data subject notification obligation (art. 20 LFPDPPP)' },
      steps: [
        { order: 1, action: { es: 'Configurar alertas de seguridad', en: 'Configure security alerts' }, where: { es: 'Dashboard > Notificaciones > Crear', en: 'Dashboard > Notifications > Create' }, detail: { es: 'Crear alertas para eventos de seguridad, certificados SSL y ataques DDoS', en: 'Create alerts for security events, SSL certificates and DDoS attacks' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/notifications/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const notif = ctx.enriched_data.notification_policies;
      const check = enrichedOrPerm(ctx, notif, 'Notifications:Read', ['notification_policies']);
      if (check) return check;
      const hasSec = notif!.has_security_alerts;
      const hasSsl = notif!.has_ssl_alerts;
      const hasDdos = notif!.has_ddos_alerts;
      const checks = [hasSec, hasSsl, hasDdos];
      const passed = checks.filter(Boolean).length;
      if (passed >= 2) return ev('pass', 100, `${notif!.total} pol\u00edticas: seguridad=${hasSec}, SSL=${hasSsl}, DDoS=${hasDdos}`, '\u22652 tipos de alertas de seguridad', 'Pol\u00edticas de notificaci\u00f3n adecuadas para detecci\u00f3n oportuna de vulneraciones.', ['notification_policies'], notif);
      if (passed === 1) return ev('partial', 40, `${notif!.total} pol\u00edticas: seguridad=${hasSec}, SSL=${hasSsl}, DDoS=${hasDdos}`, '\u22652 tipos de alertas de seguridad', 'Se detect\u00f3 solo un tipo de alerta. Se recomienda cobertura m\u00e1s amplia.', ['notification_policies'], notif);
      return ev('fail', 0, `${notif!.total} pol\u00edticas, sin alertas de seguridad cr\u00edticas`, '\u22652 tipos de alertas de seguridad', 'No se detectaron alertas de seguridad, SSL ni DDoS configuradas.', ['notification_policies'], notif);
    },
  },

  // 7. LFPDPPP-36.II \u2014 Incident response
  {
    control_id: 'LFPDPPP-36.II',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n II del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Respuesta a incidentes de seguridad', en: 'Security incident response' },
    description: { es: 'Mecanismos automatizados de protecci\u00f3n contra ataques web y DDoS', en: 'Automated protection mechanisms against web attacks and DDoS' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.II',
      official_text: { es: 'El responsable deber\u00e1 llevar a cabo acciones correctivas y de mejora de las medidas de seguridad, incluyendo mecanismos de respuesta autom\u00e1tica ante incidentes', en: 'The data controller shall carry out corrective and improvement actions for security measures, including automated incident response mechanisms' },
      applicability_note: { es: 'En Cloudflare: El WAF administrado y la protecci\u00f3n DDoS proporcionan respuesta autom\u00e1tica a ataques web y volum\u00e9tricos', en: 'In Cloudflare: Managed WAF and DDoS protection provide automated response to web and volumetric attacks' },
    },
    required_data_sources: ['rulesets', 'zone_settings.security_level'],
    required_permissions: ['Firewall Services:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.25', clause: 'A.8.25' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.4', clause: 'CC7.4' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
    ],
    remediation_template: {
      summary: { es: 'Activar WAF administrado y verificar protecci\u00f3n DDoS', en: 'Activate managed WAF and verify DDoS protection' },
      risk_if_ignored: { es: 'Sin mecanismos de respuesta, los ataques pueden causar vulneraciones masivas de datos personales que constituyan delito conforme al art\u00edculo 67 de la LFPDPPP', en: 'Without response mechanisms, attacks can cause massive personal data breaches that constitute a crime per article 67 of LFPDPPP' },
      steps: [
        { order: 1, action: { es: 'Activar reglas WAF administradas', en: 'Enable managed WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar el conjunto de reglas administradas de Cloudflare para respuesta autom\u00e1tica a ataques', en: 'Deploy Cloudflare managed ruleset for automated attack response' } },
        { order: 2, action: { es: 'Verificar protecci\u00f3n DDoS', en: 'Verify DDoS protection' }, where: { es: 'Dashboard > Seguridad > DDoS', en: 'Dashboard > Security > DDoS' }, detail: { es: 'Confirmar que la protecci\u00f3n DDoS est\u00e1 activa (habilitada por defecto en Cloudflare)', en: 'Confirm DDoS protection is active (enabled by default on Cloudflare)' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const secLevel = s(ctx, 'security_level');
      const secOk = secLevel && secLevel !== 'off' && secLevel !== 'essentially_off';
      if (waf && secOk) return ev('pass', 100, `WAF: activo, Nivel seguridad: ${secLevel}`, 'WAF activo + protecci\u00f3n DDoS', 'Mecanismos de respuesta autom\u00e1tica ante incidentes correctamente configurados.', ['rulesets', 'zone_settings.security_level']);
      if (waf || secOk) return ev('partial', 50, `WAF: ${waf ? 'activo' : 'inactivo'}, Nivel seguridad: ${secLevel || 'unknown'}`, 'WAF activo + protecci\u00f3n DDoS', 'Respuesta parcial: se requiere tanto WAF como nivel de seguridad adecuado.', ['rulesets', 'zone_settings.security_level']);
      return ev('fail', 0, 'Sin WAF ni protecci\u00f3n activa', 'WAF activo + protecci\u00f3n DDoS', 'No se detectaron mecanismos de respuesta autom\u00e1tica ante incidentes.', ['rulesets', 'zone_settings.security_level']);
    },
  },

  // 8. LFPDPPP-36.III \u2014 Vulnerability management
  {
    control_id: 'LFPDPPP-36.III',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n III del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Gesti\u00f3n de vulnerabilidades', en: 'Vulnerability management' },
    description: { es: 'Protecci\u00f3n proactiva contra vulnerabilidades conocidas mediante reglas WAF administradas y protecci\u00f3n contra bots', en: 'Proactive protection against known vulnerabilities via managed WAF rules and bot protection' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.III',
      official_text: { es: 'El responsable deber\u00e1 realizar revisiones o auditor\u00edas peri\u00f3dicas para identificar vulnerabilidades en el tratamiento de datos personales e implementar acciones preventivas y correctivas', en: 'The data controller shall conduct periodic reviews or audits to identify vulnerabilities in personal data processing and implement preventive and corrective actions' },
      applicability_note: { es: 'En Cloudflare: Las reglas WAF administradas (incluyendo OWASP CRS) y la protecci\u00f3n contra bots mitigan vulnerabilidades conocidas de forma continua', en: 'In Cloudflare: Managed WAF rules (including OWASP CRS) and bot protection mitigate known vulnerabilities continuously' },
    },
    required_data_sources: ['rulesets', 'zone_settings.security_level'],
    required_permissions: ['Firewall Services:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.28', clause: 'A.8.28' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.1', clause: 'CC7.1' },
    ],
    remediation_template: {
      summary: { es: 'Activar reglas WAF OWASP y configurar detecci\u00f3n de bots', en: 'Activate OWASP WAF rules and configure bot detection' },
      risk_if_ignored: { es: 'Sin gesti\u00f3n de vulnerabilidades, los datos personales quedan expuestos a ataques conocidos como inyecci\u00f3n SQL, XSS y explotaci\u00f3n automatizada', en: 'Without vulnerability management, personal data is exposed to known attacks like SQL injection, XSS and automated exploitation' },
      steps: [
        { order: 1, action: { es: 'Activar OWASP Core Rule Set', en: 'Enable OWASP Core Rule Set' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar el conjunto de reglas OWASP para detecci\u00f3n de vulnerabilidades comunes', en: 'Deploy OWASP ruleset for common vulnerability detection' } },
        { order: 2, action: { es: 'Configurar modo de protecci\u00f3n contra bots', en: 'Configure bot protection mode' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Habilitar Bot Fight Mode para bloquear tr\u00e1fico automatizado malicioso', en: 'Enable Bot Fight Mode to block malicious automated traffic' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);
      const botMode = s(ctx, 'security_level');
      const botOk = botMode && botMode !== 'off' && botMode !== 'essentially_off';
      const checks = [waf, owasp, botOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `WAF: activo, OWASP: activo, Bot protection: ${botMode}`, 'WAF + OWASP + protecci\u00f3n contra bots', 'Gesti\u00f3n completa de vulnerabilidades con WAF, OWASP y protecci\u00f3n contra bots.', ['rulesets', 'zone_settings.security_level']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `WAF: ${waf ? 'on' : 'off'}, OWASP: ${owasp ? 'on' : 'off'}, Bot: ${botOk ? botMode : 'off'}`, 'WAF + OWASP + protecci\u00f3n contra bots', `${passed}/3 controles de gesti\u00f3n de vulnerabilidades activos.`, ['rulesets', 'zone_settings.security_level']);
      return ev('fail', 0, 'Sin protecci\u00f3n WAF ni detecci\u00f3n de bots', 'WAF + OWASP + protecci\u00f3n contra bots', 'No se detectaron mecanismos de gesti\u00f3n de vulnerabilidades.', ['rulesets', 'zone_settings.security_level']);
    },
  },

  // 9. LFPDPPP-36.IV \u2014 Network security
  {
    control_id: 'LFPDPPP-36.IV',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n IV del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Seguridad de la red', en: 'Network security' },
    description: { es: 'Controles de seguridad perimetral: firewall, DNSSEC y reglas WAF personalizadas', en: 'Perimeter security controls: firewall, DNSSEC and custom WAF rules' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.IV',
      official_text: { es: 'El responsable deber\u00e1 implementar medidas de seguridad en las redes de comunicaci\u00f3n por las que se transmitan o almacenen datos personales, incluyendo firewalls y mecanismos de detecci\u00f3n de intrusos', en: 'The data controller shall implement security measures on communication networks through which personal data is transmitted or stored, including firewalls and intrusion detection mechanisms' },
      applicability_note: { es: 'En Cloudflare: Reglas de firewall personalizadas, DNSSEC y reglas WAF act\u00faan como controles de seguridad perimetral de red', en: 'In Cloudflare: Custom firewall rules, DNSSEC and WAF rules act as network perimeter security controls' },
    },
    required_data_sources: ['rulesets', 'dns_summary'],
    required_permissions: ['Firewall Services:Read', 'DNS:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar reglas WAF personalizadas y habilitar DNSSEC', en: 'Configure custom WAF rules and enable DNSSEC' },
      risk_if_ignored: { es: 'Sin seguridad perimetral, la red queda expuesta a accesos no autorizados y ataques de envenenamiento DNS', en: 'Without perimeter security, the network is exposed to unauthorized access and DNS poisoning attacks' },
      steps: [
        { order: 1, action: { es: 'Crear reglas WAF personalizadas', en: 'Create custom WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' }, detail: { es: 'Definir reglas para bloquear patrones de tr\u00e1fico sospechoso', en: 'Define rules to block suspicious traffic patterns' } },
        { order: 2, action: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' }, where: { es: 'Dashboard > DNS > Configuraci\u00f3n', en: 'Dashboard > DNS > Settings' }, detail: { es: 'Activar DNSSEC para proteger la integridad de las consultas DNS', en: 'Activate DNSSEC to protect DNS query integrity' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const customRules = getCustomWafRules(ctx);
      const rateLimits = getRateLimitRules(ctx);
      const hasCustom = customRules.length > 0;
      const hasRateLimits = rateLimits.length > 0;
      const checks = [dnssec, hasCustom, hasRateLimits];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `DNSSEC: on, Reglas WAF: ${customRules.length}, Rate limits: ${rateLimits.length}`, 'DNSSEC + reglas WAF + rate limiting', 'Controles de seguridad de red completos.', ['dns_summary', 'rulesets']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `DNSSEC: ${dnssec ? 'on' : 'off'}, Reglas WAF: ${customRules.length}, Rate limits: ${rateLimits.length}`, 'DNSSEC + reglas WAF + rate limiting', `${passed}/3 controles de seguridad de red activos.`, ['dns_summary', 'rulesets']);
      return ev('fail', 0, 'Sin DNSSEC, reglas WAF ni rate limiting', 'DNSSEC + reglas WAF + rate limiting', 'No se detectaron controles de seguridad de red.', ['dns_summary', 'rulesets']);
    },
  },

  // 10. LFPDPPP-36.V \u2014 Continuous monitoring
  {
    control_id: 'LFPDPPP-36.V',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n V del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Monitoreo continuo', en: 'Continuous monitoring' },
    description: { es: 'Vigilancia continua de la disponibilidad y seguridad de los sistemas que tratan datos personales', en: 'Continuous monitoring of the availability and security of systems that process personal data' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.V',
      official_text: { es: 'El responsable deber\u00e1 realizar un monitoreo continuo y pruebas peri\u00f3dicas de la efectividad de las medidas de seguridad implementadas', en: 'The data controller shall perform continuous monitoring and periodic testing of the effectiveness of the implemented security measures' },
      applicability_note: { es: 'En Cloudflare: Health checks monitorean la disponibilidad del origen y las pol\u00edticas de notificaci\u00f3n alertan sobre degradaciones', en: 'In Cloudflare: Health checks monitor origin availability and notification policies alert on degradations' },
    },
    required_data_sources: ['health_checks', 'notification_policies'],
    required_permissions: ['Health Checks:Read', 'Notifications:Read'],
    cross_references: [
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.1', clause: 'CC7.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'pci_dss_4', control_id: 'PCI-11.4.1', clause: '11.4.1' },
    ],
    remediation_template: {
      summary: { es: 'Configurar health checks y pol\u00edticas de notificaci\u00f3n', en: 'Configure health checks and notification policies' },
      risk_if_ignored: { es: 'Sin monitoreo continuo, las fallas de seguridad y disponibilidad pueden pasar desapercibidas por tiempo prolongado', en: 'Without continuous monitoring, security and availability failures may go undetected for extended periods' },
      steps: [
        { order: 1, action: { es: 'Crear health checks', en: 'Create health checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Configurar health checks HTTP/HTTPS para monitorear la disponibilidad del servidor de origen', en: 'Configure HTTP/HTTPS health checks to monitor origin server availability' } },
        { order: 2, action: { es: 'Crear alertas de notificaci\u00f3n', en: 'Create notification alerts' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Configurar alertas por email o webhook para eventos cr\u00edticos', en: 'Configure email or webhook alerts for critical events' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hc = ctx.enriched_data.health_checks;
      const notif = ctx.enriched_data.notification_policies;
      const hasHealthChecks = hc ? hc.total > 0 : false;
      const hasNotif = notif ? notif.total > 0 : false;
      if (hasHealthChecks && hasNotif) return ev('pass', 100, `Health checks: ${hc!.total}, Notificaciones: ${notif!.total}`, 'Health checks + notificaciones activas', 'Monitoreo continuo correctamente configurado con health checks y notificaciones.', ['health_checks', 'notification_policies']);
      if (hasHealthChecks || hasNotif) return ev('partial', 50, `Health checks: ${hc?.total ?? 0}, Notificaciones: ${notif?.total ?? 0}`, 'Health checks + notificaciones activas', 'Monitoreo parcial: se recomienda configurar tanto health checks como notificaciones.', ['health_checks', 'notification_policies']);
      // Check permissions
      const hcCheck = enrichedOrPerm(ctx, hc, 'Health Checks:Read', ['health_checks']);
      if (hcCheck) return hcCheck;
      return ev('fail', 0, 'Sin health checks ni notificaciones', 'Health checks + notificaciones activas', 'No se detect\u00f3 monitoreo continuo configurado.', ['health_checks', 'notification_policies']);
    },
  },

  // 11. LFPDPPP-36.VI \u2014 Availability and resilience
  {
    control_id: 'LFPDPPP-36.VI',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n VI del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Disponibilidad y resiliencia', en: 'Availability and resilience' },
    description: { es: 'Capacidad de restaurar la disponibilidad y el acceso a los datos personales de forma oportuna ante un incidente', en: 'Ability to restore availability and access to personal data in a timely manner after an incident' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.VI',
      official_text: { es: 'El responsable deber\u00e1 garantizar la disponibilidad de los datos personales y la capacidad de restaurar el acceso a los mismos de manera oportuna en caso de incidente f\u00edsico o t\u00e9cnico', en: 'The data controller shall guarantee the availability of personal data and the ability to restore access to them in a timely manner in the event of a physical or technical incident' },
      applicability_note: { es: 'En Cloudflare: Los health checks detectan ca\u00eddas del origen y la protecci\u00f3n DDoS garantiza disponibilidad durante ataques volum\u00e9tricos', en: 'In Cloudflare: Health checks detect origin outages and DDoS protection ensures availability during volumetric attacks' },
    },
    required_data_sources: ['health_checks', 'zone_settings.security_level'],
    required_permissions: ['Health Checks:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
      { framework: 'soc2_type2', control_id: 'SOC2-A1.2', clause: 'A1.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.14', clause: 'A.8.14' },
    ],
    remediation_template: {
      summary: { es: 'Configurar health checks y verificar protecci\u00f3n DDoS', en: 'Configure health checks and verify DDoS protection' },
      risk_if_ignored: { es: 'Sin garant\u00edas de disponibilidad, los titulares de datos podr\u00edan perder acceso a sus datos personales en caso de incidente, incumpliendo el principio de calidad (art. 11 LFPDPPP)', en: 'Without availability guarantees, data subjects may lose access to their personal data during an incident, violating the quality principle (art. 11 LFPDPPP)' },
      steps: [
        { order: 1, action: { es: 'Configurar health checks', en: 'Configure health checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Crear health checks con intervalos frecuentes para detecci\u00f3n r\u00e1pida de ca\u00eddas', en: 'Create health checks with frequent intervals for fast outage detection' } },
        { order: 2, action: { es: 'Verificar protecci\u00f3n DDoS', en: 'Verify DDoS protection' }, where: { es: 'Dashboard > Seguridad > DDoS', en: 'Dashboard > Security > DDoS' }, detail: { es: 'Confirmar configuraci\u00f3n de protecci\u00f3n DDoS y sensibilidad de detecci\u00f3n', en: 'Confirm DDoS protection configuration and detection sensitivity' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hc = ctx.enriched_data.health_checks;
      const hasHealthChecks = hc ? hc.total > 0 : false;
      const allHealthy = hc?.all_healthy === true;
      const secLevel = s(ctx, 'security_level');
      const ddosOk = secLevel && secLevel !== 'off' && secLevel !== 'essentially_off';
      if (hasHealthChecks && allHealthy && ddosOk) return ev('pass', 100, `Health checks: ${hc!.total} (todos sanos), DDoS: ${secLevel}`, 'Health checks sanos + protecci\u00f3n DDoS', 'Disponibilidad y resiliencia correctamente configuradas.', ['health_checks', 'zone_settings.security_level']);
      if (hasHealthChecks || ddosOk) {
        const score = (hasHealthChecks ? 1 : 0) + (allHealthy ? 1 : 0) + (ddosOk ? 1 : 0);
        return ev('partial', Math.round((score / 3) * 100), `Health checks: ${hc?.total ?? 0} (${allHealthy ? 'sanos' : 'con problemas'}), DDoS: ${secLevel || 'unknown'}`, 'Health checks sanos + protecci\u00f3n DDoS', 'Disponibilidad parcialmente configurada.', ['health_checks', 'zone_settings.security_level']);
      }
      const hcCheck = enrichedOrPerm(ctx, hc, 'Health Checks:Read', ['health_checks']);
      if (hcCheck) return hcCheck;
      return ev('fail', 0, 'Sin health checks ni protecci\u00f3n DDoS', 'Health checks sanos + protecci\u00f3n DDoS', 'No se detectaron controles de disponibilidad y resiliencia.', ['health_checks', 'zone_settings.security_level']);
    },
  },

  // 12. LFPDPPP-36.VII \u2014 Data integrity protection
  {
    control_id: 'LFPDPPP-36.VII',
    control_ref: 'Art\u00edculo 36, fracci\u00f3n VII del Reglamento',
    framework: 'lfpdppp',
    section_id: 'medidas_seguridad',
    title: { es: 'Protecci\u00f3n de la integridad de los datos', en: 'Data integrity protection' },
    description: { es: 'Mecanismos que garantizan que los datos personales no sean alterados durante su transmisi\u00f3n', en: 'Mechanisms that ensure personal data is not altered during transmission' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Art. 36 Reglamento LFPDPPP: Medidas de Seguridad Espec\u00edficas', en: 'Art. 36 LFPDPPP Regulation: Specific Security Measures' },
      clause: '36.VII',
      official_text: { es: 'El responsable deber\u00e1 garantizar la integridad de los datos personales, implementando mecanismos que prevengan su alteraci\u00f3n, p\u00e9rdida o destrucci\u00f3n no autorizada', en: 'The data controller shall guarantee the integrity of personal data, implementing mechanisms that prevent unauthorized alteration, loss or destruction' },
      applicability_note: { es: 'En Cloudflare: Always Use HTTPS, HSTS y SSL modo estricto protegen la integridad de los datos en tr\u00e1nsito contra ataques de intermediario', en: 'In Cloudflare: Always Use HTTPS, HSTS and SSL strict mode protect data integrity in transit against man-in-the-middle attacks' },
    },
    required_data_sources: ['zone_settings.always_use_https', 'zone_settings.security_header', 'zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'gdpr', control_id: 'GDPR-5.1.f', clause: 'Art. 5(1)(f)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Always Use HTTPS, HSTS y SSL Full (Strict)', en: 'Enable Always Use HTTPS, HSTS and SSL Full (Strict)' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n de integridad, los datos personales pueden ser alterados en tr\u00e1nsito por un atacante (ataque de intermediario), violando el principio de calidad del art\u00edculo 11 de la LFPDPPP', en: 'Without integrity protection, personal data can be altered in transit by an attacker (man-in-the-middle attack), violating the quality principle of article 11 of LFPDPPP' },
      steps: [
        { order: 1, action: { es: 'Habilitar Always Use HTTPS', en: 'Enable Always Use HTTPS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar "Usar siempre HTTPS" para redirigir todo el tr\u00e1fico HTTP a HTTPS', en: 'Enable "Always Use HTTPS" to redirect all HTTP traffic to HTTPS' } },
        { order: 2, action: { es: 'Configurar HSTS', en: 'Configure HSTS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Habilitar HSTS con max-age \u2265 31536000 e incluir subdominios', en: 'Enable HSTS with max-age \u2265 31536000 and include subdomains' } },
        { order: 3, action: { es: 'Configurar SSL en modo Full (Strict)', en: 'Set SSL to Full (Strict) mode' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar modo "Completo (estricto)" para validaci\u00f3n completa del certificado de origen', en: 'Select "Full (strict)" mode for complete origin certificate validation' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const alwaysHttps = s(ctx, 'always_use_https') === 'on';
      const hsts = getHsts(ctx);
      const hstsOk = hsts.enabled && hsts.max_age >= 31536000;
      const ssl = s(ctx, 'ssl');
      const sslOk = ssl === 'strict' || ssl === 'full_strict';
      const checks = [alwaysHttps, hstsOk, sslOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `HTTPS forzado: on, HSTS: max-age=${hsts.max_age}, SSL: ${ssl}`, 'Always HTTPS + HSTS (31536000+) + SSL Full (Strict)', 'Protecci\u00f3n completa de integridad de datos en tr\u00e1nsito.', ['zone_settings.always_use_https', 'zone_settings.security_header', 'zone_settings.ssl']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `HTTPS forzado: ${alwaysHttps ? 'on' : 'off'}, HSTS: ${hsts.enabled ? `max-age=${hsts.max_age}` : 'off'}, SSL: ${ssl || 'unknown'}`, 'Always HTTPS + HSTS (31536000+) + SSL Full (Strict)', `${passed}/3 controles de integridad de datos activos.`, ['zone_settings.always_use_https', 'zone_settings.security_header', 'zone_settings.ssl']);
      return ev('fail', 0, `HTTPS forzado: off, HSTS: off, SSL: ${ssl || 'unknown'}`, 'Always HTTPS + HSTS (31536000+) + SSL Full (Strict)', 'No se detectaron mecanismos de protecci\u00f3n de integridad de datos en tr\u00e1nsito.', ['zone_settings.always_use_https', 'zone_settings.security_header', 'zone_settings.ssl']);
    },
  },
];
