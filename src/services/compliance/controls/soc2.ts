/**
 * Anga Security \u2014 SOC 2 Type II Framework Controls
 *
 * 12 controls across 4 Trust Services Criteria sections:
 * CC6 (Logical & Physical Access), CC7 (System Operations),
 * CC8 (Change Management), A1 (Availability)
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, hasManagedWaf, hasOwaspRules, getCustomWafRules, getRateLimitRules, getHsts } from './helpers';

export const SOC2_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // CC6: Logical and Physical Access Controls
  // ================================================================
  {
    control_id: 'SOC2-CC6.1',
    control_ref: 'CC6.1',
    framework: 'soc2_type2',
    section_id: 'cc6',
    title: { es: 'Seguridad de acceso l\u00f3gico', en: 'Logical access security' },
    description: { es: 'Controles de acceso l\u00f3gico implementados para proteger activos de informaci\u00f3n', en: 'Logical access controls implemented to protect information assets' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical and Physical Access Controls' },
      clause: 'CC6.1',
      official_text: { es: 'La entidad implementa software de seguridad de acceso l\u00f3gico, infraestructura y arquitecturas sobre los activos de informaci\u00f3n protegidos para restringir el acceso', en: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to restrict access' },
      applicability_note: { es: 'En Cloudflare: Las reglas de acceso IP, el nivel de seguridad de la zona y los controles de acceso act\u00faan como controles de acceso l\u00f3gico', en: 'In Cloudflare: IP access rules, zone security level, and access controls act as logical access controls' },
    },
    required_data_sources: ['ip_access_rules', 'zone_settings.security_level'],
    required_permissions: ['Firewall Services:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-8.3.1', clause: '8.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar reglas de acceso IP y nivel de seguridad apropiado', en: 'Configure IP access rules and appropriate security level' },
      risk_if_ignored: { es: 'Sin controles de acceso l\u00f3gico, cualquier origen puede acceder a los recursos sin restricci\u00f3n', en: 'Without logical access controls, any origin can access resources without restriction' },
      steps: [
        { order: 1, action: { es: 'Configurar reglas de acceso IP', en: 'Configure IP access rules' }, where: { es: 'Dashboard > Seguridad > WAF > Herramientas', en: 'Dashboard > Security > WAF > Tools' }, detail: { es: 'A\u00f1adir reglas para restringir acceso por IP, pa\u00eds o ASN', en: 'Add rules to restrict access by IP, country or ASN' } },
        { order: 2, action: { es: 'Ajustar nivel de seguridad', en: 'Adjust security level' }, where: { es: 'Dashboard > Seguridad > Configuraci\u00f3n', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer nivel de seguridad en "Alto" o "Bajo ataque"', en: 'Set security level to "High" or "Under Attack"' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/ip-access-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const secLevel = s(ctx, 'security_level');
      const ipRules = ctx.enriched_data.ip_access_rules;
      const hasIpRules = ipRules ? ipRules.total > 0 : false;
      const secOk = secLevel === 'high' || secLevel === 'under_attack' || secLevel === 'medium';
      if (secOk && hasIpRules) return ev('pass', 100, `Security level: ${secLevel}, IP rules: ${ipRules?.total || 0}`, 'Security level \u2265 medium + IP access rules', 'Logical access controls are properly configured.', ['zone_settings.security_level', 'ip_access_rules']);
      if (secOk || hasIpRules) return ev('partial', 50, `Security level: ${secLevel || 'unknown'}, IP rules: ${hasIpRules ? 'configured' : 'none'}`, 'Security level \u2265 medium + IP access rules', 'Partial logical access controls. Configure both security level and IP rules.', ['zone_settings.security_level', 'ip_access_rules']);
      return ev('fail', 0, `Security level: ${secLevel || 'unknown'}, no IP rules`, 'Security level \u2265 medium + IP access rules', 'No logical access controls detected.', ['zone_settings.security_level', 'ip_access_rules']);
    },
  },
  {
    control_id: 'SOC2-CC6.3',
    control_ref: 'CC6.3',
    framework: 'soc2_type2',
    section_id: 'cc6',
    title: { es: 'Acceso basado en roles', en: 'Role-based access' },
    description: { es: 'Acceso a activos configurado seg\u00fan roles y nivel de seguridad', en: 'Access to assets configured based on roles and security level' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical and Physical Access Controls' },
      clause: 'CC6.3',
      official_text: { es: 'La entidad autoriza, modifica o elimina el acceso a datos, software, funciones y otros recursos de TI protegidos basado en roles y responsabilidades', en: 'The entity authorizes, modifies, or removes access to data, software, functions, and other protected IT resources based on roles and responsibilities' },
      applicability_note: { es: 'En Cloudflare: La configuraci\u00f3n del nivel de seguridad de la zona controla c\u00f3mo se eval\u00faan las solicitudes entrantes', en: 'In Cloudflare: Zone security level configuration controls how incoming requests are evaluated' },
    },
    required_data_sources: ['zone_settings.security_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-8.6.1', clause: '8.6.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.5', clause: 'A.8.5' },
    ],
    remediation_template: {
      summary: { es: 'Configurar nivel de seguridad de zona apropiado', en: 'Configure appropriate zone security level' },
      risk_if_ignored: { es: 'Sin nivel de seguridad adecuado, solicitudes maliciosas pasan sin desaf\u00edo', en: 'Without proper security level, malicious requests pass unchallenged' },
      steps: [
        { order: 1, action: { es: 'Ajustar nivel de seguridad', en: 'Adjust security level' }, where: { es: 'Dashboard > Seguridad > Configuraci\u00f3n', en: 'Dashboard > Security > Settings' }, detail: { es: 'Configurar nivel de seguridad en "Medio" o "Alto"', en: 'Set security level to "Medium" or "High"' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/security-level/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const secLevel = s(ctx, 'security_level');
      if (secLevel === 'high' || secLevel === 'under_attack') return ev('pass', 100, `Security level: ${secLevel}`, 'High or Under Attack', 'Zone security level provides strong access control.', ['zone_settings.security_level']);
      if (secLevel === 'medium') return ev('partial', 60, `Security level: ${secLevel}`, 'High or Under Attack', 'Security level is medium. Consider raising to high for stricter access control.', ['zone_settings.security_level']);
      return ev('fail', 0, `Security level: ${secLevel || 'unknown'}`, 'High or Under Attack', 'Security level is too low for effective role-based access control.', ['zone_settings.security_level']);
    },
  },
  {
    control_id: 'SOC2-CC6.6',
    control_ref: 'CC6.6',
    framework: 'soc2_type2',
    section_id: 'cc6',
    title: { es: 'Protecci\u00f3n de l\u00edmites del sistema', en: 'System boundary protection' },
    description: { es: 'Controles de seguridad implementados en los l\u00edmites del sistema', en: 'Security controls implemented at system boundaries' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical and Physical Access Controls' },
      clause: 'CC6.6',
      official_text: { es: 'La entidad implementa controles de acceso l\u00f3gico para proteger contra amenazas desde fuentes externas a los l\u00edmites del sistema', en: 'The entity implements logical access controls to protect against threats from sources outside its system boundaries' },
      applicability_note: { es: 'En Cloudflare: WAF, protecci\u00f3n DDoS y DNSSEC protegen los l\u00edmites del sistema', en: 'In Cloudflare: WAF, DDoS protection, and DNSSEC protect system boundaries' },
    },
    required_data_sources: ['rulesets', 'dns_summary', 'zone_settings.ddos_protection'],
    required_permissions: ['Firewall Services:Read', 'DNS:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Activar WAF administrado, DNSSEC y protecci\u00f3n DDoS', en: 'Enable managed WAF, DNSSEC, and DDoS protection' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n de l\u00edmites, el sistema est\u00e1 expuesto a ataques externos directos', en: 'Without boundary protection, the system is exposed to direct external attacks' },
      steps: [
        { order: 1, action: { es: 'Activar WAF administrado', en: 'Enable managed WAF' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Desplegar reglas administradas de Cloudflare', en: 'Deploy Cloudflare managed rules' } },
        { order: 2, action: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' }, where: { es: 'Dashboard > DNS > Configuraci\u00f3n', en: 'Dashboard > DNS > Settings' }, detail: { es: 'Activar DNSSEC para proteger integridad DNS', en: 'Activate DNSSEC to protect DNS integrity' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const checks = [waf, dnssec];
      const passed = checks.filter(Boolean).length;
      if (passed === 2) return ev('pass', 100, `WAF: active, DNSSEC: on`, 'WAF + DNSSEC active', 'System boundary protection is fully configured.', ['rulesets', 'dns_summary']);
      if (passed === 1) return ev('partial', 50, `WAF: ${waf ? 'active' : 'inactive'}, DNSSEC: ${dnssec ? 'on' : 'off'}`, 'WAF + DNSSEC active', `${passed}/2 boundary controls active. Enable all for full protection.`, ['rulesets', 'dns_summary']);
      return ev('fail', 0, 'No boundary protection active', 'WAF + DNSSEC active', 'No system boundary protection controls detected.', ['rulesets', 'dns_summary']);
    },
  },
  {
    control_id: 'SOC2-CC6.7',
    control_ref: 'CC6.7',
    framework: 'soc2_type2',
    section_id: 'cc6',
    title: { es: 'Seguridad en transmisi\u00f3n de datos', en: 'Data transmission security' },
    description: { es: 'Datos protegidos durante la transmisi\u00f3n con cifrado fuerte', en: 'Data protected during transmission with strong encryption' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical and Physical Access Controls' },
      clause: 'CC6.7',
      official_text: { es: 'La entidad restringe la transmisi\u00f3n, movimiento y eliminaci\u00f3n de informaci\u00f3n a usuarios autorizados y protege la misma durante la transmisi\u00f3n', en: 'The entity restricts the transmission, movement, and removal of information to authorized users and protects it during transmission' },
      applicability_note: { es: 'En Cloudflare: SSL/TLS en modo Strict, versi\u00f3n m\u00ednima TLS 1.2+ y HSTS habilitado', en: 'In Cloudflare: SSL/TLS in Strict mode, minimum TLS version 1.2+, and HSTS enabled' },
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.III', clause: 'Art. 19.III' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar SSL Strict, TLS 1.2+ y habilitar HSTS', en: 'Configure SSL Strict, TLS 1.2+, and enable HSTS' },
      risk_if_ignored: { es: 'Datos en tr\u00e1nsito sin cifrado adecuado pueden ser interceptados', en: 'Data in transit without proper encryption can be intercepted' },
      steps: [
        { order: 1, action: { es: 'Configurar SSL Full (Strict)', en: 'Set SSL to Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar modo "Completo (estricto)"', en: 'Select "Full (strict)" mode' } },
        { order: 2, action: { es: 'Establecer TLS m\u00ednimo 1.2', en: 'Set minimum TLS to 1.2' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Establecer versi\u00f3n m\u00ednima de TLS en 1.2', en: 'Set minimum TLS version to 1.2' } },
        { order: 3, action: { es: 'Habilitar HSTS', en: 'Enable HSTS' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar HSTS con max-age \u2265 31536000 e incluir subdominios', en: 'Enable HSTS with max-age \u2265 31536000 and include subdomains' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const tls = s(ctx, 'min_tls_version');
      const hsts = getHsts(ctx);
      const sslOk = ssl === 'strict' || ssl === 'full_strict';
      const tlsOk = tls === '1.2' || tls === '1.3';
      const hstsOk = hsts.enabled && hsts.max_age >= 31536000;
      const checks = [sslOk, tlsOk, hstsOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `SSL: ${ssl}, TLS min: ${tls}, HSTS: max-age=${hsts.max_age}`, 'SSL Strict + TLS 1.2+ + HSTS', 'All data transmission security controls are active.', ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `SSL: ${ssl || 'unknown'}, TLS min: ${tls || 'unknown'}, HSTS: ${hstsOk ? 'on' : 'off'}`, 'SSL Strict + TLS 1.2+ + HSTS', `${passed}/3 transmission security controls active.`, ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header']);
      return ev('fail', 0, `SSL: ${ssl || 'unknown'}, TLS min: ${tls || 'unknown'}, HSTS: off`, 'SSL Strict + TLS 1.2+ + HSTS', 'Data transmission security is not properly configured.', ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header']);
    },
  },
  {
    control_id: 'SOC2-CC6.8',
    control_ref: 'CC6.8',
    framework: 'soc2_type2',
    section_id: 'cc6',
    title: { es: 'Prevenci\u00f3n de software no autorizado', en: 'Unauthorized software prevention' },
    description: { es: 'Controles para prevenir o detectar software no autorizado', en: 'Controls to prevent or detect unauthorized software' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC6: Controles de Acceso L\u00f3gico y F\u00edsico', en: 'CC6: Logical and Physical Access Controls' },
      clause: 'CC6.8',
      official_text: { es: 'La entidad implementa controles para prevenir o detectar e investigar la introducci\u00f3n de software no autorizado o malicioso', en: 'The entity implements controls to prevent or detect and address the introduction of unauthorized or malicious software' },
      applicability_note: { es: 'En Cloudflare: Page Shield detecta scripts maliciosos y Bot Management previene tr\u00e1fico automatizado no autorizado', en: 'In Cloudflare: Page Shield detects malicious scripts and Bot Management prevents unauthorized automated traffic' },
    },
    required_data_sources: ['page_shield', 'zone_settings.bot_management'],
    required_permissions: ['Page Shield:Read', 'Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.7', clause: 'A.8.7' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-36.V', clause: 'Art. 36.V' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar Page Shield y Bot Management', en: 'Enable Page Shield and Bot Management' },
      risk_if_ignored: { es: 'Scripts maliciosos de terceros pueden exfiltrar datos o inyectar c\u00f3digo da\u00f1ino', en: 'Malicious third-party scripts can exfiltrate data or inject harmful code' },
      steps: [
        { order: 1, action: { es: 'Activar Page Shield', en: 'Enable Page Shield' }, where: { es: 'Dashboard > Seguridad > Page Shield', en: 'Dashboard > Security > Page Shield' }, detail: { es: 'Habilitar monitoreo de scripts de terceros', en: 'Enable third-party script monitoring' } },
        { order: 2, action: { es: 'Activar Bot Management', en: 'Enable Bot Management' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Habilitar Bot Fight Mode o Bot Management Enterprise', en: 'Enable Bot Fight Mode or Bot Management Enterprise' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/page-shield/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ps = ctx.enriched_data.page_shield;
      const bm = s(ctx, 'bot_management');
      const bmActive = bm?.enabled === true || bm?.enable_js === true;
      const psCheck = enrichedOrPerm(ctx, ps, 'Page Shield:Read', ['page_shield']);
      if (psCheck && !bmActive) return psCheck;
      const psActive = ps?.enabled === true;
      const psMalicious = ps?.malicious_scripts || 0;
      if (psActive && bmActive && psMalicious === 0) return ev('pass', 100, `Page Shield: on (${ps?.total_scripts || 0} scripts, 0 malicious), Bot Mgmt: on`, 'Page Shield + Bot Management active', 'Unauthorized software prevention controls are active with no threats detected.', ['page_shield', 'zone_settings.bot_management']);
      if (psActive && bmActive && psMalicious > 0) return ev('partial', 60, `Page Shield: on (${psMalicious} malicious scripts detected), Bot Mgmt: on`, 'No malicious scripts + Bot Management', `Controls active but ${psMalicious} malicious script(s) detected. Review and mitigate.`, ['page_shield', 'zone_settings.bot_management']);
      if (psActive || bmActive) return ev('partial', 40, `Page Shield: ${psActive ? 'on' : 'off'}, Bot Mgmt: ${bmActive ? 'on' : 'off'}`, 'Page Shield + Bot Management active', 'Partial unauthorized software prevention. Enable both Page Shield and Bot Management.', ['page_shield', 'zone_settings.bot_management']);
      return ev('fail', 0, 'Neither Page Shield nor Bot Management active', 'Page Shield + Bot Management active', 'No unauthorized software prevention controls detected.', ['page_shield', 'zone_settings.bot_management']);
    },
  },

  // ================================================================
  // CC7: System Operations
  // ================================================================
  {
    control_id: 'SOC2-CC7.1',
    control_ref: 'CC7.1',
    framework: 'soc2_type2',
    section_id: 'cc7',
    title: { es: 'Mecanismos de detecci\u00f3n', en: 'Detection mechanisms' },
    description: { es: 'Mecanismos de detecci\u00f3n implementados para identificar anomal\u00edas y eventos de seguridad', en: 'Detection mechanisms implemented to identify anomalies and security events' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC7: Operaciones del Sistema', en: 'CC7: System Operations' },
      clause: 'CC7.1',
      official_text: { es: 'Para cumplir sus objetivos, la entidad utiliza procedimientos de detecci\u00f3n y monitoreo para identificar cambios en las configuraciones que resultan en la introducci\u00f3n de nuevas vulnerabilidades', en: 'To meet its objectives, the entity uses detection and monitoring procedures to identify configuration changes that result in the introduction of new vulnerabilities' },
      applicability_note: { es: 'En Cloudflare: Los eventos WAF y las pol\u00edticas de notificaci\u00f3n proporcionan detecci\u00f3n de amenazas en tiempo real', en: 'In Cloudflare: WAF events and notification policies provide real-time threat detection' },
    },
    required_data_sources: ['rulesets', 'notification_policies'],
    required_permissions: ['Firewall Services:Read', 'Notifications:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.4.1', clause: '10.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar WAF y pol\u00edticas de notificaci\u00f3n de seguridad', en: 'Configure WAF and security notification policies' },
      risk_if_ignored: { es: 'Sin mecanismos de detecci\u00f3n, los incidentes de seguridad pasan desapercibidos hasta que causan da\u00f1o', en: 'Without detection mechanisms, security incidents go unnoticed until they cause damage' },
      steps: [
        { order: 1, action: { es: 'Verificar WAF activo', en: 'Verify WAF active' }, where: { es: 'Dashboard > Seguridad > WAF', en: 'Dashboard > Security > WAF' }, detail: { es: 'Asegurar que reglas administradas est\u00e9n desplegadas', en: 'Ensure managed rules are deployed' } },
        { order: 2, action: { es: 'Configurar notificaciones', en: 'Configure notifications' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Crear pol\u00edticas de alerta para eventos de seguridad', en: 'Create alert policies for security events' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/notifications/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const notif = ctx.enriched_data.notification_policies;
      const notifCheck = enrichedOrPerm(ctx, notif, 'Notifications:Read', ['notification_policies']);
      if (notifCheck && !waf) return notifCheck;
      const hasSecAlerts = notif?.has_security_alerts === true;
      if (waf && hasSecAlerts) return ev('pass', 100, `WAF: active, Security alerts: configured (${notif?.total || 0} policies)`, 'WAF active + security notifications', 'Detection mechanisms are properly configured with WAF and alerting.', ['rulesets', 'notification_policies']);
      if (waf || hasSecAlerts) return ev('partial', 50, `WAF: ${waf ? 'active' : 'inactive'}, Security alerts: ${hasSecAlerts ? 'configured' : 'none'}`, 'WAF active + security notifications', 'Partial detection coverage. Configure both WAF and notification policies.', ['rulesets', 'notification_policies']);
      return ev('fail', 0, 'No WAF or security notification policies', 'WAF active + security notifications', 'No detection mechanisms configured.', ['rulesets', 'notification_policies']);
    },
  },
  {
    control_id: 'SOC2-CC7.2',
    control_ref: 'CC7.2',
    framework: 'soc2_type2',
    section_id: 'cc7',
    title: { es: 'Monitoreo de anomal\u00edas', en: 'Anomaly monitoring' },
    description: { es: 'Monitoreo continuo de anomal\u00edas y eventos de seguridad con alertas', en: 'Continuous monitoring of anomalies and security events with alerts' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC7: Operaciones del Sistema', en: 'CC7: System Operations' },
      clause: 'CC7.2',
      official_text: { es: 'La entidad monitorea los componentes del sistema y el funcionamiento de esos componentes en busca de anomal\u00edas indicativas de actos maliciosos', en: 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts' },
      applicability_note: { es: 'En Cloudflare: Las pol\u00edticas de notificaci\u00f3n para DDoS, SSL y eventos de seguridad proporcionan monitoreo continuo', en: 'In Cloudflare: Notification policies for DDoS, SSL, and security events provide continuous monitoring' },
    },
    required_data_sources: ['notification_policies'],
    required_permissions: ['Notifications:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.4.1', clause: '10.4.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.16', clause: 'A.8.16' },
      { framework: 'gdpr', control_id: 'GDPR-33.1', clause: 'Art. 33(1)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar pol\u00edticas de notificaci\u00f3n para DDoS, SSL y seguridad', en: 'Configure notification policies for DDoS, SSL, and security' },
      risk_if_ignored: { es: 'Sin monitoreo de anomal\u00edas, ataques en curso no se detectan a tiempo', en: 'Without anomaly monitoring, ongoing attacks are not detected in time' },
      steps: [
        { order: 1, action: { es: 'Crear alerta DDoS', en: 'Create DDoS alert' }, where: { es: 'Dashboard > Notificaciones > Crear', en: 'Dashboard > Notifications > Create' }, detail: { es: 'A\u00f1adir pol\u00edtica de notificaci\u00f3n para ataques DDoS', en: 'Add notification policy for DDoS attacks' } },
        { order: 2, action: { es: 'Crear alerta SSL', en: 'Create SSL alert' }, where: { es: 'Dashboard > Notificaciones > Crear', en: 'Dashboard > Notifications > Create' }, detail: { es: 'A\u00f1adir pol\u00edtica para certificados pr\u00f3ximos a expirar', en: 'Add policy for certificates nearing expiry' } },
        { order: 3, action: { es: 'Crear alerta de seguridad', en: 'Create security alert' }, where: { es: 'Dashboard > Notificaciones > Crear', en: 'Dashboard > Notifications > Create' }, detail: { es: 'A\u00f1adir pol\u00edtica para eventos de firewall y seguridad', en: 'Add policy for firewall and security events' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/notifications/',
      estimated_effort: 'hours',
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
      const alertTypes = [hasSec, hasSsl, hasDdos];
      const configured = alertTypes.filter(Boolean).length;
      if (configured >= 3) return ev('pass', 100, `${notif!.total} policies: security=${hasSec}, SSL=${hasSsl}, DDoS=${hasDdos}`, 'Security + SSL + DDoS alerts', 'Comprehensive anomaly monitoring with alerts for all critical event types.', ['notification_policies'], notif);
      if (configured >= 1) return ev('partial', Math.round((configured / 3) * 100), `${notif!.total} policies: security=${hasSec}, SSL=${hasSsl}, DDoS=${hasDdos}`, 'Security + SSL + DDoS alerts', `${configured}/3 alert categories configured. Add monitoring for all types.`, ['notification_policies'], notif);
      return ev('fail', 0, `${notif!.total} policies but no security/SSL/DDoS alerts`, 'Security + SSL + DDoS alerts', 'No anomaly monitoring alerts configured for critical event types.', ['notification_policies'], notif);
    },
  },
  {
    control_id: 'SOC2-CC7.3',
    control_ref: 'CC7.3',
    framework: 'soc2_type2',
    section_id: 'cc7',
    title: { es: 'Evaluaci\u00f3n de eventos de seguridad', en: 'Security event evaluation' },
    description: { es: 'Registros de auditor\u00eda disponibles para evaluar eventos de seguridad', en: 'Audit logs available to evaluate security events' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC7: Operaciones del Sistema', en: 'CC7: System Operations' },
      clause: 'CC7.3',
      official_text: { es: 'La entidad eval\u00faa los eventos de seguridad identificados para determinar si constituyen incidentes de seguridad', en: 'The entity evaluates identified security events to determine whether they constitute security incidents' },
      applicability_note: { es: 'En Cloudflare: Los registros de auditor\u00eda permiten evaluar eventos de seguridad y determinar su impacto', en: 'In Cloudflare: Audit logs allow evaluation of security events and determination of their impact' },
    },
    required_data_sources: ['audit_logs'],
    required_permissions: ['Account Access: Audit Logs'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'gdpr', control_id: 'GDPR-33.1', clause: 'Art. 33(1)' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.IV', clause: 'Art. 19.IV' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar y revisar registros de auditor\u00eda regularmente', en: 'Enable and review audit logs regularly' },
      risk_if_ignored: { es: 'Sin registros de auditor\u00eda, no se puede determinar el alcance e impacto de los incidentes', en: 'Without audit logs, the scope and impact of incidents cannot be determined' },
      steps: [
        { order: 1, action: { es: 'Verificar registros de auditor\u00eda', en: 'Verify audit logs' }, where: { es: 'Dashboard > Cuenta > Registro de auditor\u00eda', en: 'Dashboard > Account > Audit Log' }, detail: { es: 'Confirmar que los registros de auditor\u00eda est\u00e1n disponibles y activos', en: 'Confirm audit logs are available and active' } },
        { order: 2, action: { es: 'Establecer proceso de revisi\u00f3n', en: 'Establish review process' }, where: { es: 'Proceso interno', en: 'Internal process' }, detail: { es: 'Definir procedimiento para revisar logs de auditor\u00eda peri\u00f3dicamente', en: 'Define procedure to review audit logs periodically' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const logs = ctx.enriched_data.audit_logs;
      const check = enrichedOrPerm(ctx, logs, 'Account Access: Audit Logs', ['audit_logs']);
      if (check) return check;
      if (logs!.available && logs!.recent_count > 0) return ev('pass', 100, `Audit logs available: ${logs!.recent_count} recent entries, actions: ${logs!.sample_actions.slice(0, 3).join(', ')}`, 'Audit logs available with recent entries', 'Audit logs are available for security event evaluation.', ['audit_logs'], logs);
      if (logs!.available) return ev('partial', 50, 'Audit logs available but no recent entries', 'Audit logs with recent activity', 'Audit log system is available but no recent entries found.', ['audit_logs'], logs);
      return ev('fail', 0, 'Audit logs not available', 'Audit logs available', 'Audit logs are not available for security event evaluation.', ['audit_logs']);
    },
  },

  // ================================================================
  // CC8: Change Management
  // ================================================================
  {
    control_id: 'SOC2-CC8.1',
    control_ref: 'CC8.1',
    framework: 'soc2_type2',
    section_id: 'cc8',
    title: { es: 'Gesti\u00f3n de cambios', en: 'Change management' },
    description: { es: 'Cambios en la infraestructura y configuraci\u00f3n son registrados y rastreados', en: 'Changes to infrastructure and configuration are logged and tracked' },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CC8: Gesti\u00f3n de Cambios', en: 'CC8: Change Management' },
      clause: 'CC8.1',
      official_text: { es: 'La entidad autoriza, dise\u00f1a, desarrolla, configura, documenta, prueba, aprueba e implementa cambios a la infraestructura, datos, software y procedimientos', en: 'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures' },
      applicability_note: { es: 'En Cloudflare: Los registros de auditor\u00eda rastrean todos los cambios de configuraci\u00f3n realizados en la zona', en: 'In Cloudflare: Audit logs track all configuration changes made to the zone' },
    },
    required_data_sources: ['audit_logs'],
    required_permissions: ['Account Access: Audit Logs'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.5.5', clause: '6.5.5' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.9', clause: 'A.8.9' },
      { framework: 'gdpr', control_id: 'GDPR-5.2', clause: 'Art. 5(2)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar y monitorear registros de auditor\u00eda para cambios de configuraci\u00f3n', en: 'Enable and monitor audit logs for configuration changes' },
      risk_if_ignored: { es: 'Sin registro de cambios, modificaciones no autorizadas pasan desapercibidas', en: 'Without change logging, unauthorized modifications go unnoticed' },
      steps: [
        { order: 1, action: { es: 'Revisar registros de auditor\u00eda', en: 'Review audit logs' }, where: { es: 'Dashboard > Cuenta > Registro de auditor\u00eda', en: 'Dashboard > Account > Audit Log' }, detail: { es: 'Verificar que los cambios de configuraci\u00f3n se registran autom\u00e1ticamente', en: 'Verify that configuration changes are automatically logged' } },
        { order: 2, action: { es: 'Configurar exportaci\u00f3n de logs', en: 'Configure log export' }, where: { es: 'Dashboard > Anal\u00edtica > Logpush', en: 'Dashboard > Analytics > Logpush' }, detail: { es: 'Exportar registros de auditor\u00eda a un sistema SIEM para retenci\u00f3n a largo plazo', en: 'Export audit logs to a SIEM system for long-term retention' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/setup/account/account-security/review-audit-logs/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const logs = ctx.enriched_data.audit_logs;
      const check = enrichedOrPerm(ctx, logs, 'Account Access: Audit Logs', ['audit_logs']);
      if (check) return check;
      if (logs!.available && logs!.has_config_changes) return ev('pass', 100, `Audit logs tracking changes: ${logs!.recent_count} entries, config changes detected`, 'Audit logs with config change tracking', 'Configuration changes are being tracked via audit logs.', ['audit_logs'], logs);
      if (logs!.available) return ev('partial', 50, `Audit logs available but no config changes detected (${logs!.recent_count} entries)`, 'Audit logs with config change tracking', 'Audit logs available but no configuration changes recorded recently.', ['audit_logs'], logs);
      return ev('fail', 0, 'Audit logs not available', 'Audit logs with config change tracking', 'No audit log capability for change management tracking.', ['audit_logs']);
    },
  },

  // ================================================================
  // A1: Availability
  // ================================================================
  {
    control_id: 'SOC2-A1.1',
    control_ref: 'A1.1',
    framework: 'soc2_type2',
    section_id: 'a1',
    title: { es: 'Planificaci\u00f3n de disponibilidad', en: 'Availability planning' },
    description: { es: 'Monitoreo de salud y disponibilidad del sistema implementado', en: 'System health and availability monitoring implemented' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'A1: Disponibilidad', en: 'A1: Availability' },
      clause: 'A1.1',
      official_text: { es: 'La entidad mantiene, monitorea y eval\u00faa el entorno de procesamiento actual e identifica vulnerabilidades y capacidades para alcanzar sus objetivos de disponibilidad', en: 'The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its availability objectives' },
      applicability_note: { es: 'En Cloudflare: Los health checks monitorean la disponibilidad del origen y detectan problemas proactivamente', en: 'In Cloudflare: Health checks monitor origin availability and detect issues proactively' },
    },
    required_data_sources: ['health_checks'],
    required_permissions: ['Health Checks:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.14', clause: 'A.8.14' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.b', clause: 'Art. 32(1)(b)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar health checks para monitorear disponibilidad del origen', en: 'Configure health checks to monitor origin availability' },
      risk_if_ignored: { es: 'Sin monitoreo de salud, las ca\u00eddas del servidor se detectan solo cuando los usuarios reportan problemas', en: 'Without health monitoring, server outages are detected only when users report problems' },
      steps: [
        { order: 1, action: { es: 'Crear health checks', en: 'Create health checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Configurar health checks HTTP/HTTPS para monitorear el servidor de origen', en: 'Set up HTTP/HTTPS health checks to monitor the origin server' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hc = ctx.enriched_data.health_checks;
      const check = enrichedOrPerm(ctx, hc, 'Health Checks:Read', ['health_checks']);
      if (check) return check;
      if (hc!.total > 0 && hc!.all_healthy) return ev('pass', 100, `${hc!.total} health check(s), all healthy`, 'Active health checks, all healthy', 'Health checks are configured and all endpoints are healthy.', ['health_checks'], hc);
      if (hc!.total > 0) return ev('partial', 60, `${hc!.total} health check(s), some unhealthy`, 'Active health checks, all healthy', 'Health checks configured but some endpoints are unhealthy. Investigate failing checks.', ['health_checks'], hc);
      return ev('fail', 0, 'No health checks configured', 'Active health checks', 'No health checks configured. Origin availability is not being monitored.', ['health_checks']);
    },
  },
  {
    control_id: 'SOC2-A1.2',
    control_ref: 'A1.2',
    framework: 'soc2_type2',
    section_id: 'a1',
    title: { es: 'Protecci\u00f3n ambiental', en: 'Environmental protection' },
    description: { es: 'Controles de protecci\u00f3n contra amenazas ambientales y ataques volum\u00e9tricos', en: 'Protection controls against environmental threats and volumetric attacks' },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'A1: Disponibilidad', en: 'A1: Availability' },
      clause: 'A1.2',
      official_text: { es: 'La entidad autoriza, dise\u00f1a, desarrolla e implementa controles ambientales, mecanismos de software y tecnolog\u00eda para prevenir, detectar y mitigar amenazas', en: 'The entity authorizes, designs, develops, or otherwise obtains, implements, and operates environmental protections, software, processes, and recovery infrastructure to meet its objectives' },
      applicability_note: { es: 'En Cloudflare: La protecci\u00f3n DDoS y las reglas de rate limiting protegen contra ataques volum\u00e9tricos que amenazan la disponibilidad', en: 'In Cloudflare: DDoS protection and rate limiting rules protect against volumetric attacks that threaten availability' },
    },
    required_data_sources: ['zone_settings.security_level', 'rulesets'],
    required_permissions: ['Zone:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.20', clause: 'A.8.20' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
    ],
    remediation_template: {
      summary: { es: 'Configurar protecci\u00f3n DDoS y reglas de rate limiting', en: 'Configure DDoS protection and rate limiting rules' },
      risk_if_ignored: { es: 'Sin protecci\u00f3n contra DDoS y rate limiting, los ataques volum\u00e9tricos pueden causar indisponibilidad total', en: 'Without DDoS protection and rate limiting, volumetric attacks can cause total unavailability' },
      steps: [
        { order: 1, action: { es: 'Verificar protecci\u00f3n DDoS', en: 'Verify DDoS protection' }, where: { es: 'Dashboard > Seguridad > DDoS', en: 'Dashboard > Security > DDoS' }, detail: { es: 'Confirmar que la protecci\u00f3n DDoS est\u00e1 activa (habilitada por defecto en Cloudflare)', en: 'Confirm DDoS protection is active (enabled by default in Cloudflare)' } },
        { order: 2, action: { es: 'Configurar rate limiting', en: 'Configure rate limiting' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas de limitaci\u00f3n', en: 'Dashboard > Security > WAF > Rate limiting rules' }, detail: { es: 'Crear reglas de rate limiting para proteger endpoints cr\u00edticos', en: 'Create rate limiting rules to protect critical endpoints' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ddos-protection/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const rl = getRateLimitRules(ctx);
      const waf = hasManagedWaf(ctx);
      const secLevel = s(ctx, 'security_level');
      const secOk = secLevel && secLevel !== 'off' && secLevel !== 'essentially_off';
      const checks = [rl.length > 0, waf, secOk];
      const passed = checks.filter(Boolean).length;
      if (passed >= 3) return ev('pass', 100, `Rate limits: ${rl.length}, WAF: active, Security level: ${secLevel}`, 'Rate limiting + WAF + DDoS protection', 'Environmental protection controls are fully configured.', ['rulesets', 'zone_settings.security_level']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `Rate limits: ${rl.length}, WAF: ${waf ? 'active' : 'inactive'}, Security level: ${secLevel || 'unknown'}`, 'Rate limiting + WAF + DDoS protection', `${passed}/3 environmental protection controls active.`, ['rulesets', 'zone_settings.security_level']);
      return ev('fail', 0, 'No environmental protection controls', 'Rate limiting + WAF + DDoS protection', 'No environmental protection controls configured against volumetric attacks.', ['rulesets', 'zone_settings.security_level']);
    },
  },
  {
    control_id: 'SOC2-A1.3',
    control_ref: 'A1.3',
    framework: 'soc2_type2',
    section_id: 'a1',
    title: { es: 'Recuperaci\u00f3n y resiliencia', en: 'Recovery and resilience' },
    description: { es: 'Capacidades de recuperaci\u00f3n y resiliencia para mantener la disponibilidad', en: 'Recovery and resilience capabilities to maintain availability' },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'A1: Disponibilidad', en: 'A1: Availability' },
      clause: 'A1.3',
      official_text: { es: 'La entidad prueba los procedimientos de plan de recuperaci\u00f3n que soportan la recuperaci\u00f3n del sistema para cumplir sus objetivos de disponibilidad', en: 'The entity tests recovery plan procedures supporting system recovery to meet its availability objectives' },
      applicability_note: { es: 'En Cloudflare: Certificados redundantes y health checks proporcionan resiliencia y capacidad de recuperaci\u00f3n autom\u00e1tica', en: 'In Cloudflare: Redundant certificates and health checks provide resilience and automatic recovery capability' },
    },
    required_data_sources: ['edge_certificates', 'health_checks'],
    required_permissions: ['SSL and Certificates:Read', 'Health Checks:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.14', clause: 'A.8.14' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.c', clause: 'Art. 32(1)(c)' },
      { framework: 'lfpdppp', control_id: 'LFPDPPP-19.IV', clause: 'Art. 19.IV' },
    ],
    remediation_template: {
      summary: { es: 'Asegurar certificados redundantes y health checks activos', en: 'Ensure redundant certificates and active health checks' },
      risk_if_ignored: { es: 'Sin redundancia, un fallo en un \u00fanico componente puede causar indisponibilidad total', en: 'Without redundancy, a single component failure can cause total unavailability' },
      steps: [
        { order: 1, action: { es: 'Verificar certificados', en: 'Verify certificates' }, where: { es: 'Dashboard > SSL/TLS > Certificados de borde', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Asegurar que hay certificados v\u00e1lidos y no pr\u00f3ximos a expirar', en: 'Ensure valid certificates exist and are not close to expiring' } },
        { order: 2, action: { es: 'Configurar health checks', en: 'Configure health checks' }, where: { es: 'Dashboard > Tr\u00e1fico > Health Checks', en: 'Dashboard > Traffic > Health Checks' }, detail: { es: 'Habilitar health checks para detecci\u00f3n autom\u00e1tica de fallos', en: 'Enable health checks for automatic failure detection' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/health-checks/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const certs = ctx.enriched_data.edge_certificates;
      const hc = ctx.enriched_data.health_checks;
      const certCheck = enrichedOrPerm(ctx, certs, 'SSL and Certificates:Read', ['edge_certificates']);
      const hcCheck = enrichedOrPerm(ctx, hc, 'Health Checks:Read', ['health_checks']);
      if (certCheck && hcCheck) return certCheck;
      const certsOk = certs ? certs.total > 0 && !certs.any_expired : false;
      const hcOk = hc ? hc.total > 0 : false;
      const checks = [certsOk, hcOk];
      const passed = checks.filter(Boolean).length;
      if (passed === 2) return ev('pass', 100, `Certificates: ${certs?.total || 0} valid (no expired), Health checks: ${hc?.total || 0} active`, 'Valid certificates + active health checks', 'Recovery and resilience controls are properly configured.', ['edge_certificates', 'health_checks']);
      if (passed === 1) return ev('partial', 50, `Certificates: ${certsOk ? 'valid' : (certs?.any_expired ? 'expired found' : 'none')}, Health checks: ${hcOk ? `${hc?.total} active` : 'none'}`, 'Valid certificates + active health checks', `${passed}/2 resilience controls active. Configure both for full coverage.`, ['edge_certificates', 'health_checks']);
      return ev('fail', 0, `Certificates: ${certs?.any_expired ? 'expired' : 'none'}, Health checks: none`, 'Valid certificates + active health checks', 'No resilience or recovery controls detected.', ['edge_certificates', 'health_checks']);
    },
  },
];
