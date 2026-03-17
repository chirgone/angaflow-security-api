/**
 * Anga Security \u2014 ISO 27001:2022 Framework Controls
 *
 * 15 controls in Annex A.8 (Technological Controls) mapped to Cloudflare.
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules, getHsts } from './helpers';

export const ISO_27001_CONTROLS: FrameworkControl[] = [
  // A.8.5 - Secure Authentication
  {
    control_id: 'ISO-A.8.5',
    control_ref: 'Annex A.8.5',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Autenticaci\u00f3n segura', en: 'Secure authentication' },
    description: { es: 'Tecnolog\u00edas y procedimientos de autenticaci\u00f3n segura implementados', en: 'Secure authentication technologies and procedures implemented' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.5',
      official_text: { es: 'Se deben implementar tecnolog\u00edas y procedimientos de autenticaci\u00f3n segura basados en restricciones de acceso a la informaci\u00f3n', en: 'Secure authentication technologies and procedures shall be established based on information access restrictions' },
      applicability_note: { es: 'En Cloudflare: Authenticated Origin Pulls (mTLS) proporciona autenticaci\u00f3n mutua entre Cloudflare y el servidor de origen', en: 'In Cloudflare: Authenticated Origin Pulls (mTLS) provides mutual authentication between Cloudflare and origin server' },
    },
    required_data_sources: ['authenticated_origin_pulls'],
    required_permissions: ['SSL and Certificates:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-8.3.1', clause: '8.3.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.1', clause: 'CC6.1' },
      { framework: 'gdpr', control_id: 'GDPR-25.1', clause: 'Art. 25(1)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Authenticated Origin Pulls (mTLS)', en: 'Enable Authenticated Origin Pulls (mTLS)' },
      risk_if_ignored: { es: 'Sin autenticaci\u00f3n mutua, el origen acepta solicitudes no verificadas', en: 'Without mutual authentication, origin accepts unverified requests' },
      steps: [
        { order: 1, action: { es: 'Activar mTLS', en: 'Enable mTLS' }, where: { es: 'Dashboard > SSL/TLS > Servidor de origen', en: 'Dashboard > SSL/TLS > Origin Server' }, detail: { es: 'Habilitar Authenticated Origin Pulls', en: 'Enable Authenticated Origin Pulls' } },
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
      if (aop.enabled) return ev('pass', 100, 'mTLS enabled', 'mTLS active', 'Mutual TLS authentication is active between Cloudflare and origin.', ['authenticated_origin_pulls']);
      return ev('fail', 0, 'mTLS disabled', 'mTLS active', 'Authenticated Origin Pulls (mTLS) is not enabled.', ['authenticated_origin_pulls']);
    },
  },
  // A.8.6 - Capacity Management
  {
    control_id: 'ISO-A.8.6',
    control_ref: 'Annex A.8.6',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Gesti\u00f3n de capacidad', en: 'Capacity management' },
    description: { es: 'Uso de recursos monitoreado con reglas de limitaci\u00f3n de tasa', en: 'Resource usage monitored with rate limiting rules' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.6',
      official_text: { es: 'El uso de recursos debe ser monitoreado y ajustado, y se deben hacer proyecciones de requisitos futuros de capacidad', en: 'The use of resources shall be monitored, adjusted, and projections made of future capacity requirements' },
      applicability_note: { es: 'En Cloudflare: Las reglas de rate limiting protegen contra el agotamiento de recursos por abuso', en: 'In Cloudflare: Rate limiting rules protect against resource exhaustion from abuse' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'soc2_type2', control_id: 'SOC2-A1.2', clause: 'A1.2' },
    ],
    remediation_template: {
      summary: { es: 'Configurar reglas de rate limiting', en: 'Configure rate limiting rules' },
      risk_if_ignored: { es: 'Sin rate limiting, ataques de volumen pueden agotar recursos del servidor', en: 'Without rate limiting, volumetric attacks can exhaust server resources' },
      steps: [
        { order: 1, action: { es: 'Crear reglas de rate limiting', en: 'Create rate limiting rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas de limitaci\u00f3n', en: 'Dashboard > Security > WAF > Rate limiting rules' }, detail: { es: 'Definir l\u00edmites por IP y endpoint', en: 'Define limits per IP and endpoint' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const rl = getRateLimitRules(ctx);
      if (rl.length >= 2) return ev('pass', 100, `${rl.length} rate limiting rules`, '\u22652 rate limit rules', 'Rate limiting rules protect against resource exhaustion.', ['rulesets']);
      if (rl.length === 1) return ev('partial', 50, '1 rate limiting rule', '\u22652 rate limit rules', 'One rate limit rule exists. Consider adding more for critical endpoints.', ['rulesets']);
      return ev('fail', 0, 'No rate limiting rules', '\u22652 rate limit rules', 'No rate limiting rules configured.', ['rulesets']);
    },
  },
  // A.8.7 - Protection Against Malware
  {
    control_id: 'ISO-A.8.7',
    control_ref: 'Annex A.8.7',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Protecci\u00f3n contra malware', en: 'Protection against malware' },
    description: { es: 'Detecci\u00f3n y prevenci\u00f3n de tr\u00e1fico automatizado malicioso', en: 'Detection and prevention of malicious automated traffic' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.7',
      official_text: { es: 'Se debe implementar protecci\u00f3n contra malware, combinada con concienciaci\u00f3n adecuada de los usuarios', en: 'Protection against malware shall be implemented and combined with appropriate user awareness' },
      applicability_note: { es: 'En Cloudflare: Bot Management y WAF protegen contra tr\u00e1fico automatizado malicioso y ataques de malware web', en: 'In Cloudflare: Bot Management and WAF protect against malicious automated traffic and web malware attacks' },
    },
    required_data_sources: ['zone_settings.bot_management', 'rulesets'],
    required_permissions: ['Zone:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-8.6.1', clause: '8.6.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.III', clause: 'Art. 36.III' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Bot Management y reglas WAF contra malware', en: 'Enable Bot Management and anti-malware WAF rules' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n, bots maliciosos pueden realizar credential stuffing, scraping y distribuir malware', en: 'Without protection, malicious bots can perform credential stuffing, scraping and distribute malware' },
      steps: [
        { order: 1, action: { es: 'Activar Bot Management', en: 'Enable Bot Management' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Habilitar Bot Fight Mode o Bot Management completo', en: 'Enable Bot Fight Mode or full Bot Management' } },
        { order: 2, action: { es: 'Verificar WAF administrado activo', en: 'Verify managed WAF active' }, where: { es: 'Dashboard > Seguridad > WAF', en: 'Dashboard > Security > WAF' }, detail: { es: 'Asegurar que las reglas administradas est\u00e9n desplegadas', en: 'Ensure managed rules are deployed' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/bots/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const bm = s(ctx, 'bot_management');
      const waf = hasManagedWaf(ctx);
      const bmActive = bm?.enabled === true || bm?.enable_js === true;
      if (bmActive && waf) return ev('pass', 100, 'Bot Management + WAF active', 'Bot Management + WAF', 'Both bot management and WAF are protecting against malware.', ['zone_settings.bot_management', 'rulesets']);
      if (bmActive || waf) return ev('partial', 60, `Bot Mgmt: ${bmActive ? 'on' : 'off'}, WAF: ${waf ? 'on' : 'off'}`, 'Both Bot Mgmt + WAF', 'Partial malware protection. Enable both for full coverage.', ['zone_settings.bot_management', 'rulesets']);
      return ev('fail', 0, 'Neither Bot Management nor WAF active', 'Bot Management + WAF', 'No malware protection mechanisms detected.', ['zone_settings.bot_management', 'rulesets']);
    },
  },
  // A.8.9 - Configuration Management
  {
    control_id: 'ISO-A.8.9',
    control_ref: 'Annex A.8.9',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Gesti\u00f3n de configuraci\u00f3n', en: 'Configuration management' },
    description: { es: 'Las configuraciones de seguridad se establecen y mantienen', en: 'Security configurations are established and maintained' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.9',
      official_text: { es: 'Las configuraciones, incluidas las de seguridad, de hardware, software, servicios y redes se deben establecer, documentar, implementar, monitorear y revisar', en: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed' },
      applicability_note: { es: 'En Cloudflare: Verificar que configuraciones cr\u00edticas como SSL, HSTS, Always HTTPS est\u00e9n correctamente configuradas', en: 'In Cloudflare: Verify critical settings like SSL, HSTS, Always HTTPS are properly configured' },
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.always_use_https', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'soc2_type2', control_id: 'SOC2-CC8.1', clause: 'CC8.1' },
    ],
    remediation_template: {
      summary: { es: 'Revisar y endurecer configuraciones de seguridad de la zona', en: 'Review and harden zone security configurations' },
      risk_if_ignored: { es: 'Configuraciones inseguras exponen la aplicaci\u00f3n a ataques evitables', en: 'Insecure configurations expose the application to preventable attacks' },
      steps: [
        { order: 1, action: { es: 'Auditar configuraciones', en: 'Audit configurations' }, where: { es: 'Dashboard > SSL/TLS y Seguridad', en: 'Dashboard > SSL/TLS and Security' }, detail: { es: 'Verificar SSL=Strict, Always HTTPS=on, HSTS=on, TLS min=1.2', en: 'Verify SSL=Strict, Always HTTPS=on, HSTS=on, TLS min=1.2' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const https = s(ctx, 'always_use_https');
      const hsts = getHsts(ctx);
      const tls = s(ctx, 'min_tls_version');
      const checks = [
        ssl === 'strict' || ssl === 'full_strict',
        https === 'on',
        hsts.enabled,
        tls === '1.2' || tls === '1.3',
      ];
      const passed = checks.filter(Boolean).length;
      if (passed === 4) return ev('pass', 100, 'All critical settings properly configured', 'SSL Strict + HTTPS + HSTS + TLS 1.2+', 'All key security configurations are hardened.', ['zone_settings']);
      if (passed >= 2) return ev('partial', Math.round((passed / 4) * 100), `${passed}/4 settings correct: SSL=${ssl}, HTTPS=${https}, HSTS=${hsts.enabled}, TLS=${tls}`, 'All 4 settings correct', `${4 - passed} configuration(s) need attention.`, ['zone_settings']);
      return ev('fail', 0, `Only ${passed}/4 settings correct`, 'All 4 settings correct', 'Critical security configurations are not properly hardened.', ['zone_settings']);
    },
  },
  // A.8.12 - Data Leakage Prevention
  {
    control_id: 'ISO-A.8.12',
    control_ref: 'Annex A.8.12',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Prevenci\u00f3n de fuga de datos', en: 'Data leakage prevention' },
    description: { es: 'Medidas para prevenir la fuga de datos aplicadas al tr\u00e1fico web', en: 'Measures to prevent data leakage applied to web traffic' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.12',
      official_text: { es: 'Se deben aplicar medidas de prevenci\u00f3n de fuga de datos a sistemas, redes y cualquier otro dispositivo que procese, almacene o transmita informaci\u00f3n sensible', en: 'Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information' },
      applicability_note: { es: 'En Cloudflare: Always HTTPS y HSTS previenen la transmisi\u00f3n de datos por canales inseguros', en: 'In Cloudflare: Always HTTPS and HSTS prevent data transmission over insecure channels' },
    },
    required_data_sources: ['zone_settings.always_use_https', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'gdpr', control_id: 'GDPR-5.1.f', clause: 'Art. 5(1)(f)' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.VII', clause: 'Art. 36.VII' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Always HTTPS y HSTS', en: 'Enable Always HTTPS and HSTS' },
      risk_if_ignored: { es: 'Sin HTTPS forzado, datos sensibles pueden transmitirse sin cifrar', en: 'Without forced HTTPS, sensitive data may be transmitted unencrypted' },
      steps: [
        { order: 1, action: { es: 'Habilitar Always HTTPS', en: 'Enable Always HTTPS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar "Usar siempre HTTPS"', en: 'Enable "Always Use HTTPS"' } },
        { order: 2, action: { es: 'Habilitar HSTS', en: 'Enable HSTS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar HSTS con max-age de al menos 6 meses', en: 'Enable HSTS with max-age of at least 6 months' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const https = s(ctx, 'always_use_https');
      const hsts = getHsts(ctx);
      if (https === 'on' && hsts.enabled && hsts.max_age >= 15768000) return ev('pass', 100, `Always HTTPS: on, HSTS: on (max_age=${hsts.max_age})`, 'Always HTTPS + HSTS (6mo+)', 'Data leakage prevention via forced HTTPS and HSTS is fully active.', ['zone_settings']);
      if (https === 'on' || hsts.enabled) return ev('partial', 50, `Always HTTPS: ${https}, HSTS: ${hsts.enabled ? 'on' : 'off'}`, 'Both Always HTTPS + HSTS', 'Partial protection. Enable both Always HTTPS and HSTS.', ['zone_settings']);
      return ev('fail', 0, 'Neither Always HTTPS nor HSTS enabled', 'Always HTTPS + HSTS', 'No data leakage prevention via HTTPS enforcement.', ['zone_settings']);
    },
  },
  // A.8.15 - Logging
  {
    control_id: 'ISO-A.8.15',
    control_ref: 'Annex A.8.15',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Registro de actividades', en: 'Activity logging' },
    description: { es: 'Logs de actividades, excepciones y eventos de seguridad', en: 'Logs of activities, exceptions and security events' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.15',
      official_text: { es: 'Se deben producir, almacenar, proteger y analizar logs que registren actividades, excepciones, fallas y otros eventos relevantes', en: 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed' },
      applicability_note: { es: 'En Cloudflare: Audit Logs + Logpush proporcionan registro completo de actividades y eventos de seguridad', en: 'In Cloudflare: Audit Logs + Logpush provide comprehensive logging of activities and security events' },
    },
    required_data_sources: ['audit_logs', 'logpush_jobs'],
    required_permissions: ['Account Access: Audit Logs', 'Logs:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.3', clause: 'CC7.3' },
      { framework: 'gdpr', control_id: 'GDPR-5.2', clause: 'Art. 5(2)' },
    ],
    remediation_template: {
      summary: { es: 'Asegurar que Audit Logs sean accesibles y configurar Logpush', en: 'Ensure Audit Logs are accessible and configure Logpush' },
      risk_if_ignored: { es: 'Sin logs, es imposible investigar incidentes o demostrar cumplimiento', en: 'Without logs, it is impossible to investigate incidents or demonstrate compliance' },
      steps: [
        { order: 1, action: { es: 'Verificar Audit Logs', en: 'Verify Audit Logs' }, where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Confirmar acceso a los registros de auditor\u00eda', en: 'Confirm access to audit records' } },
        { order: 2, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Anal\u00edtica y Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Exportar logs a almacenamiento externo', en: 'Export logs to external storage' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const auditOk = ctx.enriched_data.audit_logs?.available && ctx.enriched_data.audit_logs.recent_count > 0;
      const logpushOk = ctx.enriched_data.logpush_jobs?.total ? ctx.enriched_data.logpush_jobs.total > 0 : false;
      if (auditOk && logpushOk) return ev('pass', 100, `Audit logs active, ${ctx.enriched_data.logpush_jobs!.total} Logpush jobs`, 'Audit logs + Logpush', 'Comprehensive logging in place.', ['audit_logs', 'logpush_jobs']);
      if (auditOk || logpushOk) return ev('partial', 50, `Audit logs: ${auditOk ? 'active' : 'inactive'}, Logpush: ${logpushOk ? 'active' : 'inactive'}`, 'Both audit logs + Logpush', 'Partial logging coverage. Enable both for full compliance.', ['audit_logs', 'logpush_jobs']);
      const hasPerm1 = ctx.available_permissions.includes('Account Access: Audit Logs');
      const hasPerm2 = ctx.available_permissions.includes('Logs:Read');
      if (!hasPerm1 && !hasPerm2) return ev('insufficient_permissions', 0, 'N/A', 'Audit Logs + Logpush', 'Token lacks Account Access: Audit Logs and Logs:Read permissions.', ['audit_logs', 'logpush_jobs']);
      return ev('fail', 0, 'No active logging detected', 'Audit logs + Logpush', 'Neither audit logs nor Logpush are available.', ['audit_logs', 'logpush_jobs']);
    },
  },
  // A.8.16 - Monitoring Activities
  {
    control_id: 'ISO-A.8.16',
    control_ref: 'Annex A.8.16',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Actividades de monitoreo', en: 'Monitoring activities' },
    description: { es: 'Redes, sistemas y aplicaciones monitoreados para comportamiento an\u00f3malo', en: 'Networks, systems and applications monitored for anomalous behavior' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.16',
      official_text: { es: 'Las redes, sistemas y aplicaciones deben ser monitoreadas para comportamiento an\u00f3malo y se deben tomar acciones apropiadas', en: 'Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken' },
      applicability_note: { es: 'En Cloudflare: Notification policies + Health Checks proporcionan monitoreo continuo y alertas', en: 'In Cloudflare: Notification policies + Health Checks provide continuous monitoring and alerts' },
    },
    required_data_sources: ['notification_policies', 'health_checks'],
    required_permissions: ['Notifications:Read', 'Health Checks:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.4.1', clause: '10.4.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.1', clause: 'CC7.1' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.V', clause: 'Art. 36.V' },
    ],
    remediation_template: {
      summary: { es: 'Configurar alertas de seguridad y Health Checks', en: 'Configure security alerts and Health Checks' },
      risk_if_ignored: { es: 'Sin monitoreo, incidentes cr\u00edticos pasan desapercibidos', en: 'Without monitoring, critical incidents go undetected' },
      steps: [
        { order: 1, action: { es: 'Configurar notificaciones', en: 'Configure notifications' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Crear alertas para eventos DDoS, WAF, SSL', en: 'Create alerts for DDoS, WAF, SSL events' } },
        { order: 2, action: { es: 'Crear Health Checks', en: 'Create Health Checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Monitorear endpoints cr\u00edticos', en: 'Monitor critical endpoints' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/notifications/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const np = ctx.enriched_data.notification_policies;
      const hc = ctx.enriched_data.health_checks;
      const hasAlerts = np ? np.total > 0 : false;
      const hasHC = hc ? hc.total > 0 : false;
      if (hasAlerts && hasHC) return ev('pass', 100, `${np!.total} alerts, ${hc!.total} health checks`, 'Alerts + Health Checks', 'Comprehensive monitoring with alerts and health checks.', ['notification_policies', 'health_checks']);
      if (hasAlerts || hasHC) return ev('partial', 50, `Alerts: ${hasAlerts ? np!.total : 0}, Health Checks: ${hasHC ? hc!.total : 0}`, 'Both alerts + health checks', 'Partial monitoring. Enable both for full coverage.', ['notification_policies', 'health_checks']);
      return ev('fail', 0, 'No monitoring configured', 'Alerts + Health Checks', 'No notification policies or health checks detected.', ['notification_policies', 'health_checks']);
    },
  },
  // A.8.20 - Network Security
  {
    control_id: 'ISO-A.8.20',
    control_ref: 'Annex A.8.20',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Seguridad de redes', en: 'Network security' },
    description: { es: 'Redes protegidas, gestionadas y controladas', en: 'Networks secured, managed and controlled' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.20',
      official_text: { es: 'Las redes y los dispositivos de red deben ser asegurados, gestionados y controlados para proteger la informaci\u00f3n en sistemas y aplicaciones', en: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications' },
      applicability_note: { es: 'En Cloudflare: WAF + DNSSEC + DDoS protection proporcionan seguridad de red integral', en: 'In Cloudflare: WAF + DNSSEC + DDoS protection provide comprehensive network security' },
    },
    required_data_sources: ['rulesets', 'dns_summary', 'zone_settings.security_level'],
    required_permissions: ['Firewall Services:Read', 'DNS:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.IV', clause: 'Art. 36.IV' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar WAF, DNSSEC y configurar nivel de seguridad adecuado', en: 'Enable WAF, DNSSEC and configure appropriate security level' },
      risk_if_ignored: { es: 'Redes desprotegidas permiten acceso no autorizado e interceptaci\u00f3n de datos', en: 'Unprotected networks allow unauthorized access and data interception' },
      steps: [
        { order: 1, action: { es: 'Activar WAF y DNSSEC', en: 'Enable WAF and DNSSEC' }, where: { es: 'Dashboard > Seguridad > WAF y Dashboard > DNS', en: 'Dashboard > Security > WAF and Dashboard > DNS' }, detail: { es: 'Desplegar reglas administradas y habilitar DNSSEC', en: 'Deploy managed rules and enable DNSSEC' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const secLevel = s(ctx, 'security_level');
      const goodLevel = secLevel === 'high' || secLevel === 'under_attack' || secLevel === 'medium';
      const checks = [waf, dnssec, goodLevel];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `WAF: active, DNSSEC: on, Security: ${secLevel}`, 'WAF + DNSSEC + adequate security level', 'Network security controls are comprehensive.', ['rulesets', 'dns_summary', 'zone_settings']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `WAF: ${waf}, DNSSEC: ${dnssec}, Security: ${secLevel}`, 'All 3 controls', `${passed}/3 network security controls active.`, ['rulesets', 'dns_summary', 'zone_settings']);
      return ev('fail', 0, 'No network security controls active', 'WAF + DNSSEC + security level', 'No network security controls detected.', ['rulesets', 'dns_summary', 'zone_settings']);
    },
  },
  // A.8.21 - Security of Network Services
  {
    control_id: 'ISO-A.8.21',
    control_ref: 'Annex A.8.21',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Seguridad de servicios de red', en: 'Security of network services' },
    description: { es: 'Mecanismos de seguridad y niveles de servicio para servicios de red', en: 'Security mechanisms and service levels for network services' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.21',
      official_text: { es: 'Se deben identificar, implementar y monitorear los mecanismos de seguridad, niveles de servicio y requisitos de gesti\u00f3n de todos los servicios de red', en: 'Security mechanisms, service levels and management requirements of all network services shall be identified, implemented and monitored' },
      applicability_note: { es: 'En Cloudflare: TLS 1.2+ y HSTS aseguran que los servicios de red utilicen protocolos seguros', en: 'In Cloudflare: TLS 1.2+ and HSTS ensure network services use secure protocols' },
    },
    required_data_sources: ['zone_settings.min_tls_version', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.2', clause: '4.2.2' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar TLS 1.2+ y HSTS con max-age adecuado', en: 'Configure TLS 1.2+ and HSTS with adequate max-age' },
      risk_if_ignored: { es: 'Protocolos obsoletos permiten ataques de downgrade y man-in-the-middle', en: 'Obsolete protocols allow downgrade and man-in-the-middle attacks' },
      steps: [
        { order: 1, action: { es: 'Configurar TLS m\u00ednimo 1.2', en: 'Set minimum TLS 1.2' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Seleccionar TLS 1.2 como versi\u00f3n m\u00ednima', en: 'Select TLS 1.2 as minimum version' } },
        { order: 2, action: { es: 'Habilitar HSTS', en: 'Enable HSTS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar con max-age de al menos 6 meses', en: 'Enable with max-age of at least 6 months' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls = s(ctx, 'min_tls_version');
      const hsts = getHsts(ctx);
      const tlsOk = tls === '1.2' || tls === '1.3';
      const hstsOk = hsts.enabled && hsts.max_age >= 15768000;
      if (tlsOk && hstsOk) return ev('pass', 100, `TLS min: ${tls}, HSTS: on (max_age=${hsts.max_age})`, 'TLS 1.2+ and HSTS', 'Network services are secured with modern TLS and HSTS.', ['zone_settings']);
      if (tlsOk || hstsOk) return ev('partial', 50, `TLS: ${tls}, HSTS: ${hsts.enabled}`, 'Both TLS 1.2+ and HSTS', 'Partial network service security. Enable both.', ['zone_settings']);
      return ev('fail', 0, `TLS: ${tls}, HSTS: disabled`, 'TLS 1.2+ and HSTS', 'Network services not adequately secured.', ['zone_settings']);
    },
  },
  // A.8.22 - Segregation of Networks
  {
    control_id: 'ISO-A.8.22',
    control_ref: 'Annex A.8.22',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Segregaci\u00f3n de redes', en: 'Segregation of networks' },
    description: { es: 'Grupos de servicios de informaci\u00f3n, usuarios y sistemas segregados en redes', en: 'Groups of information services, users and systems segregated in networks' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.22',
      official_text: { es: 'Los grupos de servicios de informaci\u00f3n, usuarios y sistemas de informaci\u00f3n deben ser segregados en las redes de la organizaci\u00f3n', en: 'Groups of information services, users and information systems shall be segregated in the organization\'s networks' },
      applicability_note: { es: 'En Cloudflare: Las reglas de acceso IP y geo-blocking proporcionan segregaci\u00f3n l\u00f3gica de red', en: 'In Cloudflare: IP access rules and geo-blocking provide logical network segregation' },
    },
    required_data_sources: ['ip_access_rules'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.6', clause: 'CC6.6' },
    ],
    remediation_template: {
      summary: { es: 'Implementar reglas de acceso IP y geo-blocking', en: 'Implement IP access rules and geo-blocking' },
      risk_if_ignored: { es: 'Sin segregaci\u00f3n, todo el tr\u00e1fico se trata igual sin importar el origen', en: 'Without segregation, all traffic is treated equally regardless of origin' },
      steps: [
        { order: 1, action: { es: 'Configurar reglas de acceso IP', en: 'Configure IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'Crear reglas para segmentar tr\u00e1fico por IP, pa\u00eds o ASN', en: 'Create rules to segment traffic by IP, country or ASN' } },
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
      if (rules.has_geo_blocks && rules.has_ip_allowlist) return ev('pass', 100, `${rules.total} rules (geo-blocks + allowlist)`, 'Geo-blocking + IP allowlist', 'Network segregation via geo-blocking and IP allowlisting.', ['ip_access_rules'], rules);
      if (rules.total >= 2) return ev('partial', 60, `${rules.total} IP access rules`, 'Geo-blocks + IP allowlist', 'Some IP restrictions present but full segregation not configured.', ['ip_access_rules'], rules);
      if (rules.total >= 1) return ev('partial', 30, `${rules.total} IP access rule(s)`, 'Multiple access rules', 'Minimal IP-based network segregation.', ['ip_access_rules'], rules);
      return ev('fail', 0, 'No IP access rules', 'IP access rules for segregation', 'No network segregation controls detected.', ['ip_access_rules']);
    },
  },
  // A.8.24 - Use of Cryptography
  {
    control_id: 'ISO-A.8.24',
    control_ref: 'Annex A.8.24',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Uso de criptograf\u00eda', en: 'Use of cryptography' },
    description: { es: 'Reglas para el uso efectivo de criptograf\u00eda definidas e implementadas', en: 'Rules for effective use of cryptography defined and implemented' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.24',
      official_text: { es: 'Se deben definir e implementar reglas para el uso efectivo de la criptograf\u00eda, incluida la gesti\u00f3n de claves criptogr\u00e1ficas', en: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented' },
      applicability_note: { es: 'En Cloudflare: SSL modo Strict + cifrados fuertes + certificados v\u00e1lidos constituyen la implementaci\u00f3n criptogr\u00e1fica', en: 'In Cloudflare: SSL Strict mode + strong ciphers + valid certificates constitute the cryptographic implementation' },
    },
    required_data_sources: ['zone_settings.ssl', 'cipher_suites', 'edge_certificates'],
    required_permissions: ['Zone:Read', 'SSL and Certificates:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19.III' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar SSL Strict, cifrados fuertes y verificar certificados', en: 'Configure SSL Strict, strong ciphers and verify certificates' },
      risk_if_ignored: { es: 'Criptograf\u00eda d\u00e9bil o ausente permite interceptaci\u00f3n y descifrado de datos', en: 'Weak or absent cryptography allows data interception and decryption' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL Strict', en: 'Configure SSL Strict' }, where: { es: 'Dashboard > SSL/TLS', en: 'Dashboard > SSL/TLS' }, detail: { es: 'Establecer modo Full (Strict)', en: 'Set Full (Strict) mode' } },
        { order: 2, action: { es: 'Verificar cifrados', en: 'Verify ciphers' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Verificar que no haya cifrados d\u00e9biles', en: 'Verify no weak ciphers present' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const ciphers = ctx.enriched_data.cipher_suites;
      const certs = ctx.enriched_data.edge_certificates;
      const sslOk = ssl === 'strict' || ssl === 'full_strict';
      const cipherOk = ciphers?.pci_dss_compliant === true && (ciphers?.weak_ciphers?.length || 0) === 0;
      const certOk = certs ? !certs.any_expired : true;
      const checks = [sslOk, cipherOk, certOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `SSL: ${ssl}, Ciphers: compliant, Certs: valid`, 'Strict SSL + strong ciphers + valid certs', 'Cryptographic controls are fully implemented.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `SSL: ${ssl}, Ciphers: ${cipherOk ? 'ok' : 'issues'}, Certs: ${certOk ? 'ok' : 'issues'}`, 'All 3 crypto controls', `${passed}/3 cryptographic controls pass.`, ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
      return ev('fail', 0, `SSL: ${ssl}, weak ciphers or expired certs`, 'All crypto controls passing', 'Cryptographic controls are inadequate.', ['zone_settings.ssl', 'cipher_suites', 'edge_certificates']);
    },
  },
  // A.8.25 - Secure Development Lifecycle
  {
    control_id: 'ISO-A.8.25',
    control_ref: 'Annex A.8.25',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Ciclo de desarrollo seguro', en: 'Secure development lifecycle' },
    description: { es: 'Reglas para el desarrollo seguro de software y sistemas establecidas', en: 'Rules for secure development of software and systems established' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.25',
      official_text: { es: 'Se deben establecer y aplicar reglas para el desarrollo seguro de software y sistemas', en: 'Rules for the secure development of software and systems shall be established and applied' },
      applicability_note: { es: 'En Cloudflare: WAF managed rules con OWASP protegen la capa de aplicaci\u00f3n como parte del SDLC', en: 'In Cloudflare: WAF managed rules with OWASP protect the application layer as part of the SDLC' },
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC8.1', clause: 'CC8.1' },
    ],
    remediation_template: {
      summary: { es: 'Desplegar WAF con reglas OWASP como capa de protecci\u00f3n del SDLC', en: 'Deploy WAF with OWASP rules as SDLC protection layer' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n a nivel de aplicaci\u00f3n, vulnerabilidades del c\u00f3digo quedan expuestas', en: 'Without application-level protection, code vulnerabilities are exposed' },
      steps: [
        { order: 1, action: { es: 'Activar WAF managed + OWASP', en: 'Enable WAF managed + OWASP' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar reglas administradas incluyendo OWASP Core Ruleset', en: 'Deploy managed rules including OWASP Core Ruleset' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);
      if (waf && owasp) return ev('pass', 100, 'WAF managed + OWASP active', 'WAF + OWASP', 'Application-layer protection via WAF and OWASP is in place.', ['rulesets']);
      if (waf) return ev('partial', 60, 'WAF managed active, OWASP not detected', 'WAF + OWASP', 'Managed WAF active but OWASP ruleset not detected.', ['rulesets']);
      return ev('fail', 0, 'No WAF or OWASP rules', 'WAF + OWASP', 'No application-layer security controls.', ['rulesets']);
    },
  },
  // A.8.26 - Application Security Requirements
  {
    control_id: 'ISO-A.8.26',
    control_ref: 'Annex A.8.26',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Requisitos de seguridad de aplicaciones', en: 'Application security requirements' },
    description: { es: 'Requisitos de seguridad identificados al desarrollar o adquirir aplicaciones', en: 'Security requirements identified when developing or acquiring applications' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.26',
      official_text: { es: 'Los requisitos de seguridad de la informaci\u00f3n deben ser identificados, especificados y aprobados al desarrollar o adquirir aplicaciones', en: 'Information security requirements shall be identified, specified and approved when developing or acquiring applications' },
      applicability_note: { es: 'En Cloudflare: Reglas WAF personalizadas y headers de seguridad demuestran requisitos de seguridad implementados', en: 'In Cloudflare: Custom WAF rules and security headers demonstrate implemented security requirements' },
    },
    required_data_sources: ['rulesets', 'zone_settings.security_header'],
    required_permissions: ['Firewall Services:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.3', clause: '6.4.3' },
    ],
    remediation_template: {
      summary: { es: 'Implementar reglas WAF personalizadas y headers de seguridad', en: 'Implement custom WAF rules and security headers' },
      risk_if_ignored: { es: 'Sin requisitos de seguridad espec\u00edficos, la aplicaci\u00f3n queda sin protecci\u00f3n personalizada', en: 'Without specific security requirements, the application lacks customized protection' },
      steps: [
        { order: 1, action: { es: 'Crear reglas WAF personalizadas', en: 'Create custom WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' }, detail: { es: 'Definir reglas espec\u00edficas para la aplicaci\u00f3n', en: 'Define application-specific rules' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const custom = getCustomWafRules(ctx);
      const hsts = getHsts(ctx);
      if (custom.length >= 2 && hsts.enabled) return ev('pass', 100, `${custom.length} custom rules + HSTS`, 'Custom rules + security headers', 'Application security requirements are implemented.', ['rulesets', 'zone_settings']);
      if (custom.length >= 1 || hsts.enabled) return ev('partial', 50, `Custom rules: ${custom.length}, HSTS: ${hsts.enabled}`, 'Custom rules + security headers', 'Partial application security. Add more custom rules and enable HSTS.', ['rulesets', 'zone_settings']);
      return ev('fail', 0, 'No custom rules or security headers', 'Custom rules + HSTS', 'No application-specific security requirements implemented.', ['rulesets', 'zone_settings']);
    },
  },
  // A.8.28 - Secure Coding
  {
    control_id: 'ISO-A.8.28',
    control_ref: 'Annex A.8.28',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Codificaci\u00f3n segura', en: 'Secure coding' },
    description: { es: 'Principios de codificaci\u00f3n segura aplicados al desarrollo de software', en: 'Secure coding principles applied to software development' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.28',
      official_text: { es: 'Se deben aplicar principios de codificaci\u00f3n segura al desarrollo de software', en: 'Secure coding principles shall be applied to software development' },
      applicability_note: { es: 'En Cloudflare: Page Shield monitorea scripts de terceros para detectar modificaciones o inyecciones maliciosas', en: 'In Cloudflare: Page Shield monitors third-party scripts to detect malicious modifications or injections' },
    },
    required_data_sources: ['page_shield', 'rulesets'],
    required_permissions: ['Page Shield:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.5.5', clause: '6.5.5' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Page Shield y reglas OWASP para protecci\u00f3n del c\u00f3digo', en: 'Enable Page Shield and OWASP rules for code protection' },
      risk_if_ignored: { es: 'Scripts maliciosos pueden robar datos de usuarios sin ser detectados', en: 'Malicious scripts can steal user data without detection' },
      steps: [
        { order: 1, action: { es: 'Activar Page Shield', en: 'Enable Page Shield' }, where: { es: 'Dashboard > Seguridad > Page Shield', en: 'Dashboard > Security > Page Shield' }, detail: { es: 'Habilitar monitoreo de scripts de terceros', en: 'Enable third-party script monitoring' } },
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
      if (psActive && owasp) return ev('pass', 100, `Page Shield active (${ps!.total_scripts} scripts), OWASP active`, 'Page Shield + OWASP', 'Client-side and server-side code protection active.', ['page_shield', 'rulesets']);
      if (psActive || owasp) return ev('partial', 50, `Page Shield: ${psActive ? 'on' : 'off'}, OWASP: ${owasp ? 'on' : 'off'}`, 'Both Page Shield + OWASP', 'Partial code protection. Enable both for full coverage.', ['page_shield', 'rulesets']);
      if (!ctx.available_permissions.includes('Page Shield:Read')) return ev('insufficient_permissions', 0, 'N/A', 'Page Shield + OWASP', 'Token lacks Page Shield:Read permission.', ['page_shield', 'rulesets']);
      return ev('fail', 0, 'No code protection active', 'Page Shield + OWASP', 'No client-side or server-side code protection.', ['page_shield', 'rulesets']);
    },
  },
  // A.8.8 - Management of Technical Vulnerabilities
  {
    control_id: 'ISO-A.8.8',
    control_ref: 'Annex A.8.8',
    framework: 'iso_27001',
    section_id: 'annex_a8',
    title: { es: 'Gesti\u00f3n de vulnerabilidades t\u00e9cnicas', en: 'Management of technical vulnerabilities' },
    description: { es: 'Informaci\u00f3n sobre vulnerabilidades obtenida y medidas tomadas', en: 'Information about vulnerabilities obtained and measures taken' },
    severity: 'high',
    evaluation_method: 'partial',
    regulatory_reference: {
      section: { es: 'Anexo A.8: Controles Tecnol\u00f3gicos', en: 'Annex A.8: Technological Controls' },
      clause: 'A.8.8',
      official_text: { es: 'Se debe obtener informaci\u00f3n sobre vulnerabilidades t\u00e9cnicas de los sistemas de informaci\u00f3n en uso de manera oportuna, y se deben tomar medidas apropiadas', en: 'Information about technical vulnerabilities of information systems in use shall be obtained in a timely fashion and appropriate measures taken' },
      applicability_note: { es: 'En Cloudflare: Las reglas WAF administradas se actualizan autom\u00e1ticamente contra nuevas vulnerabilidades. El monitoreo activo detecta incidentes', en: 'In Cloudflare: Managed WAF rules are automatically updated against new vulnerabilities. Active monitoring detects incidents' },
    },
    required_data_sources: ['rulesets', 'notification_policies'],
    required_permissions: ['Firewall Services:Read', 'Notifications:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.III', clause: 'Art. 36.III' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.d', clause: 'Art. 32(1)(d)' },
    ],
    remediation_template: {
      summary: { es: 'Mantener WAF administrado activo y configurar alertas de seguridad', en: 'Keep managed WAF active and configure security alerts' },
      risk_if_ignored: { es: 'Nuevas vulnerabilidades no se mitigan autom\u00e1ticamente sin WAF actualizado', en: 'New vulnerabilities are not automatically mitigated without updated WAF' },
      steps: [
        { order: 1, action: { es: 'Verificar WAF administrado activo', en: 'Verify managed WAF active' }, where: { es: 'Dashboard > Seguridad > WAF', en: 'Dashboard > Security > WAF' }, detail: { es: 'Confirmar que las reglas se actualizan autom\u00e1ticamente', en: 'Confirm rules are automatically updated' } },
        { order: 2, action: { es: 'Configurar alertas', en: 'Configure alerts' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Alertas para nuevas amenazas detectadas', en: 'Alerts for new detected threats' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const alerts = ctx.enriched_data.notification_policies?.has_security_alerts === true;
      if (waf && alerts) return ev('pass', 100, 'Managed WAF + security alerts active', 'WAF + security alerts', 'Vulnerability management via auto-updating WAF rules and alerting.', ['rulesets', 'notification_policies']);
      if (waf) return ev('partial', 60, 'Managed WAF active, no security alerts', 'WAF + security alerts', 'WAF provides auto-patching but no security alerts configured.', ['rulesets', 'notification_policies']);
      return ev('fail', 0, 'No WAF or security alerts', 'WAF + security alerts', 'No vulnerability management controls detected.', ['rulesets', 'notification_policies']);
    },
  },
];
