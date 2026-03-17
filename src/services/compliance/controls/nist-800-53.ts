/**
 * Anga Security — NIST SP 800-53 Rev 5 Framework Controls (Infrastructure)
 *
 * 15 controls covering infrastructure-level security evaluable via Cloudflare API.
 *
 * Families: SC (System & Communications Protection), AU (Audit & Accountability),
 * CM (Configuration Management), SI (System & Information Integrity),
 * AC (Access Control), RA (Risk Assessment), CA (Assessment, Authorization & Monitoring)
 *
 * NIST SP 800-53 is a public domain publication by NIST.
 * This assessment covers ONLY infrastructure-level controls evaluable via Cloudflare API.
 * Full 800-53 compliance requires assessment of all 1000+ controls across your entire stack.
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, getHsts, hasManagedWaf, hasOwaspRules, getRateLimitRules } from './helpers';

export const NIST_800_53_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // SC — System and Communications Protection
  // ================================================================
  {
    control_id: 'NIST-800-53-SC-8',
    control_ref: 'SC-8',
    framework: 'nist_800_53',
    section_id: 'sc',
    title: {
      es: 'SC-8: Confidencialidad e Integridad de Transmisión',
      en: 'SC-8: Transmission Confidentiality and Integrity',
    },
    description: {
      es: 'Proteger la confidencialidad e integridad de la información transmitida mediante cifrado TLS fuerte, HSTS y versión mínima de TLS adecuada',
      en: 'Protect the confidentiality and integrity of transmitted information using strong TLS encryption, HSTS, and adequate minimum TLS version',
    },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'SC: Protección de Sistemas y Comunicaciones',
        en: 'SC: System and Communications Protection',
      },
      clause: 'SC-8',
      official_text: {
        es: 'El sistema de información protege la confidencialidad e integridad de la información transmitida. Mejora (1): Emplear mecanismos criptográficos para prevenir divulgación no autorizada y detectar cambios en la información durante la transmisión.',
        en: 'The information system protects the confidentiality and integrity of transmitted information. Enhancement (1): Employ cryptographic mechanisms to prevent unauthorized disclosure of, and detect changes to, information during transmission.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se evalúa TLS 1.3 habilitado, versión mínima TLS >= 1.2, y HSTS configurado con max-age adecuado. Estos tres controles en conjunto aseguran cifrado fuerte de extremo a extremo.',
        en: 'In Cloudflare: Evaluates TLS 1.3 enabled, minimum TLS version >= 1.2, and HSTS configured with adequate max-age. These three controls together ensure strong end-to-end encryption.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.tls_1_3', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.2', clause: '4.2.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
      { framework: 'infra_baseline', control_id: 'INFRA-TLS-002', clause: 'TLS-002' },
    ],
    remediation_template: {
      summary: {
        es: 'Habilitar TLS 1.3, establecer versión mínima TLS en 1.2+ y configurar HSTS con max-age de al menos 1 año',
        en: 'Enable TLS 1.3, set minimum TLS version to 1.2+, and configure HSTS with max-age of at least 1 year',
      },
      risk_if_ignored: {
        es: 'Sin cifrado fuerte en tránsito, los datos pueden ser interceptados, leídos o modificados por atacantes mediante ataques man-in-the-middle',
        en: 'Without strong encryption in transit, data can be intercepted, read, or modified by attackers through man-in-the-middle attacks',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar TLS 1.3', en: 'Enable TLS 1.3' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'Localiza la sección "TLS 1.3" y cambia el toggle a "On". Los cambios se aplican automáticamente sin necesidad de guardar.',
            en: 'Locate the "TLS 1.3" section and toggle it to "On". Changes apply automatically without needing to save.',
          },
        },
        {
          order: 2,
          action: { es: 'Establecer versión mínima de TLS', en: 'Set minimum TLS version' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'En "Versión mínima de TLS", selecciona "1.2" del menú desplegable. Esto rechaza conexiones TLS 1.0 y 1.1 que tienen vulnerabilidades conocidas.',
            en: 'Under "Minimum TLS Version", select "1.2" from the dropdown. This rejects TLS 1.0 and 1.1 connections which have known vulnerabilities.',
          },
        },
        {
          order: 3,
          action: { es: 'Configurar HSTS', en: 'Configure HSTS' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' },
          detail: {
            es: 'Haz clic en "Habilitar HSTS", acepta el diálogo de advertencia. Establece Max-Age a 12 meses (31536000 segundos). Activa "Incluir subdominios" y "No-Sniff". Esto fuerza a los navegadores a usar HTTPS exclusivamente.',
            en: 'Click "Enable HSTS", accept the warning dialog. Set Max-Age to 12 months (31536000 seconds). Enable "Include subdomains" and "No-Sniff". This forces browsers to use HTTPS exclusively.',
          },
        },
        {
          order: 4,
          action: { es: 'Verificar la configuración', en: 'Verify the configuration' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'Confirma que TLS 1.3 muestra "On", versión mínima muestra "1.2", y HSTS muestra "Enabled" con los valores correctos.',
            en: 'Confirm TLS 1.3 shows "On", minimum version shows "1.2", and HSTS shows "Enabled" with correct values.',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/tls-13/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls13 = s(ctx, 'tls_1_3');
      const minTls = s(ctx, 'min_tls_version');
      const hsts = getHsts(ctx);

      const isTls13On = tls13 === 'on' || tls13 === 'zrt';
      const isMinTlsOk = minTls === '1.2' || minTls === '1.3';
      const isHstsOk = hsts.enabled && hsts.max_age >= 15768000; // At least 6 months

      const checks = [isTls13On, isMinTlsOk, isHstsOk];
      const passed = checks.filter(Boolean).length;

      if (passed === 3) {
        return ev(
          'pass', 100,
          `TLS 1.3: ${tls13}, Min TLS: ${minTls}, HSTS: enabled (max-age: ${hsts.max_age})`,
          'TLS 1.3 on + Min TLS >= 1.2 + HSTS enabled',
          'All transmission confidentiality and integrity controls are properly configured.',
          ['zone_settings.tls_1_3', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
        );
      }
      if (passed >= 1) {
        const issues: string[] = [];
        if (!isTls13On) issues.push('TLS 1.3 not enabled');
        if (!isMinTlsOk) issues.push(`Min TLS ${minTls || 'unknown'} below 1.2`);
        if (!isHstsOk) issues.push(hsts.enabled ? `HSTS max-age ${hsts.max_age}s too low` : 'HSTS not enabled');
        return ev(
          'partial', Math.round((passed / 3) * 100),
          `TLS 1.3: ${tls13 || 'off'}, Min TLS: ${minTls || 'unknown'}, HSTS: ${hsts.enabled ? `on (${hsts.max_age}s)` : 'off'}`,
          'TLS 1.3 on + Min TLS >= 1.2 + HSTS enabled',
          `${passed}/3 transmission protection controls active. Issues: ${issues.join('; ')}.`,
          ['zone_settings.tls_1_3', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
        );
      }
      return ev(
        'fail', 0,
        `TLS 1.3: ${tls13 || 'off'}, Min TLS: ${minTls || 'unknown'}, HSTS: ${hsts.enabled ? 'on' : 'off'}`,
        'TLS 1.3 on + Min TLS >= 1.2 + HSTS enabled',
        'No transmission confidentiality controls are properly configured. Data in transit is at risk.',
        ['zone_settings.tls_1_3', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
      );
    },
  },

  // ================================================================
  // AU — Audit and Accountability
  // ================================================================
  {
    control_id: 'NIST-800-53-AU-2',
    control_ref: 'AU-2',
    framework: 'nist_800_53',
    section_id: 'au',
    title: {
      es: 'AU-2: Eventos Auditables',
      en: 'AU-2: Auditable Events',
    },
    description: {
      es: 'Identificar eventos auditables y asegurar que los registros de seguridad se exportan a almacenamiento externo para retención y análisis forense',
      en: 'Identify auditable events and ensure security logs are exported to external storage for retention and forensic analysis',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'AU: Auditoría y Responsabilidad',
        en: 'AU: Audit and Accountability',
      },
      clause: 'AU-2',
      official_text: {
        es: 'La organización: a. Identifica los tipos de eventos que el sistema de información es capaz de registrar; b. Coordina la función de registro de auditoría con otras entidades; c. Proporciona una justificación de por qué los eventos auditables se consideran adecuados; d. Determina los campos de eventos a registrar.',
        en: 'The organization: a. Identifies the types of events that the information system is capable of logging; b. Coordinates the audit logging function with other entities; c. Provides a rationale for why the auditable events are deemed adequate; d. Determines event fields to be logged.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se evalúa la existencia de Logpush jobs configurados que exportan logs de firewall, HTTP y auditoría a almacenamiento externo (S3, R2, GCS, etc.).',
        en: 'In Cloudflare: Evaluates the existence of configured Logpush jobs that export firewall, HTTP, and audit logs to external storage (S3, R2, GCS, etc.).',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['logpush_jobs', 'audit_logs'],
    required_permissions: ['Logs:Read', 'Account Access: Audit Logs'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.1', clause: '10.2.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-10.2.2', clause: '10.2.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.15', clause: 'A.8.15' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
      { framework: 'infra_baseline', control_id: 'INFRA-LOG-001', clause: 'LOG-001' },
    ],
    remediation_template: {
      summary: {
        es: 'Configurar Logpush para exportar logs de seguridad a un destino externo y verificar que los Audit Logs de cuenta estén activos',
        en: 'Configure Logpush to export security logs to an external destination and verify account Audit Logs are active',
      },
      risk_if_ignored: {
        es: 'Sin registros exportados, no hay capacidad forense después de un incidente. Los logs internos de Cloudflare tienen retención limitada y no cumplen requisitos de auditoría.',
        en: 'Without exported logs, there is no forensic capability after an incident. Cloudflare internal logs have limited retention and do not meet audit requirements.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Navegar a Logpush', en: 'Navigate to Logpush' },
          where: { es: 'Dashboard > Analytics y Logs > Logs', en: 'Dashboard > Analytics & Logs > Logs' },
          detail: {
            es: 'Accede a la sección de Logs en el panel lateral izquierdo. Si no aparece, tu plan puede no incluir Logpush (requiere Enterprise o complemento).',
            en: 'Access the Logs section in the left sidebar. If it does not appear, your plan may not include Logpush (requires Enterprise or add-on).',
          },
        },
        {
          order: 2,
          action: { es: 'Crear job de Logpush para HTTP Requests', en: 'Create Logpush job for HTTP Requests' },
          where: { es: 'Dashboard > Analytics y Logs > Logs > Crear job', en: 'Dashboard > Analytics & Logs > Logs > Create job' },
          detail: {
            es: 'Selecciona "HTTP requests" como dataset. Elige un destino (R2, S3, GCS, Azure Blob, Splunk, Datadog, etc.). Configura los campos: ClientIP, ClientRequestURI, EdgeResponseStatus, WAFAction, RayID, DateTime.',
            en: 'Select "HTTP requests" as dataset. Choose a destination (R2, S3, GCS, Azure Blob, Splunk, Datadog, etc.). Configure fields: ClientIP, ClientRequestURI, EdgeResponseStatus, WAFAction, RayID, DateTime.',
          },
        },
        {
          order: 3,
          action: { es: 'Crear job de Logpush para Firewall Events', en: 'Create Logpush job for Firewall Events' },
          where: { es: 'Dashboard > Analytics y Logs > Logs > Crear job', en: 'Dashboard > Analytics & Logs > Logs > Create job' },
          detail: {
            es: 'Crea un segundo job con dataset "Firewall events". Esto captura todas las acciones del WAF, rate limiting y reglas de seguridad.',
            en: 'Create a second job with dataset "Firewall events". This captures all WAF actions, rate limiting, and security rule events.',
          },
        },
        {
          order: 4,
          action: { es: 'Verificar Audit Logs de cuenta', en: 'Verify account Audit Logs' },
          where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' },
          detail: {
            es: 'Confirma que los eventos de auditoría de la cuenta (cambios de configuración, login, etc.) están registrándose. Estos están disponibles en todos los planes.',
            en: 'Confirm account audit events (configuration changes, login, etc.) are being recorded. These are available on all plans.',
          },
        },
        {
          order: 5,
          action: { es: 'Verificar que los jobs estén activos', en: 'Verify jobs are active' },
          where: { es: 'Dashboard > Analytics y Logs > Logs', en: 'Dashboard > Analytics & Logs > Logs' },
          detail: {
            es: 'Confirma que los jobs de Logpush muestran estado "Active" y que "Last successful push" tiene una fecha reciente.',
            en: 'Confirm Logpush jobs show "Active" status and "Last successful push" has a recent date.',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const logpush = ctx.enriched_data.logpush_jobs;
      const auditLogs = ctx.enriched_data.audit_logs;

      // Check Logpush availability
      const hasLogpush = logpush && logpush.total > 0;
      const hasFirewallLogs = logpush?.has_firewall_logs === true;
      const hasHttpLogs = logpush?.has_http_logs === true;
      const hasAuditLogs = auditLogs?.available === true && (auditLogs?.recent_count || 0) > 0;

      // If no logpush data, check permissions
      if (!logpush) {
        if (!ctx.available_permissions.includes('Logs:Read')) {
          return ev(
            'insufficient_permissions', 0,
            'N/A',
            'Requires permission: Logs:Read',
            'API token lacks Logs:Read permission. Cannot evaluate Logpush configuration.',
            ['logpush_jobs'],
          );
        }
      }

      const checks = [hasLogpush, hasFirewallLogs || hasHttpLogs, hasAuditLogs];
      const passed = checks.filter(Boolean).length;

      if (passed === 3) {
        return ev(
          'pass', 100,
          `Logpush: ${logpush!.total} jobs (FW: ${hasFirewallLogs}, HTTP: ${hasHttpLogs}), Audit Logs: active (${auditLogs!.recent_count} events)`,
          'Logpush + Firewall/HTTP logs + Audit Logs active',
          'Comprehensive event logging is configured with external export and account audit trail.',
          ['logpush_jobs', 'audit_logs'],
        );
      }
      if (passed >= 1) {
        const issues: string[] = [];
        if (!hasLogpush) issues.push('No Logpush jobs configured');
        if (!hasFirewallLogs && !hasHttpLogs) issues.push('No firewall or HTTP log export');
        if (!hasAuditLogs) issues.push('Account audit logs not available or empty');
        return ev(
          'partial', Math.round((passed / 3) * 100),
          `Logpush: ${logpush?.total || 0} jobs, Audit Logs: ${hasAuditLogs ? 'active' : 'inactive'}`,
          'Logpush + Firewall/HTTP logs + Audit Logs active',
          `${passed}/3 event logging checks passed. Issues: ${issues.join('; ')}.`,
          ['logpush_jobs', 'audit_logs'],
        );
      }
      return ev(
        'fail', 0,
        `Logpush: ${logpush?.total || 0} jobs, Audit Logs: ${hasAuditLogs ? 'active' : 'not available'}`,
        'Logpush + Firewall/HTTP logs + Audit Logs active',
        'No event logging infrastructure configured. Security events are not being captured or exported.',
        ['logpush_jobs', 'audit_logs'],
      );
    },
  },

  // ================================================================
  // CM — Configuration Management
  // ================================================================
  {
    control_id: 'NIST-800-53-CM-6',
    control_ref: 'CM-6',
    framework: 'nist_800_53',
    section_id: 'cm',
    title: {
      es: 'CM-6: Ajustes de Configuración de Seguridad',
      en: 'CM-6: Configuration Settings',
    },
    description: {
      es: 'Establecer y mantener ajustes de configuración seguros para la infraestructura, incluyendo HTTPS forzado, reescritura automática de HTTPS y modo SSL estricto',
      en: 'Establish and maintain secure configuration settings for infrastructure, including forced HTTPS, automatic HTTPS rewrite, and strict SSL mode',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'CM: Gestión de Configuración',
        en: 'CM: Configuration Management',
      },
      clause: 'CM-6',
      official_text: {
        es: 'La organización: a. Establece y documenta los ajustes de configuración para productos de tecnología de información empleados dentro del sistema; b. Implementa los ajustes de configuración; c. Identifica, documenta y aprueba cualquier desviación de los ajustes de configuración establecidos.',
        en: 'The organization: a. Establishes and documents configuration settings for information technology products employed within the system; b. Implements the configuration settings; c. Identifies, documents, and approves any deviations from established configuration settings.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se evalúan tres configuraciones fundamentales de seguridad: "Always Use HTTPS" (redirige todo el tráfico HTTP a HTTPS), "Automatic HTTPS Rewrites" (corrige URLs mixtas), y modo SSL Full (Strict) para validación completa de certificados.',
        en: 'In Cloudflare: Evaluates three fundamental security configurations: "Always Use HTTPS" (redirects all HTTP traffic to HTTPS), "Automatic HTTPS Rewrites" (fixes mixed content URLs), and SSL Full (Strict) mode for complete certificate validation.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.always_use_https', 'zone_settings.automatic_https_rewrites', 'zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.9', clause: 'A.8.9' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.7', clause: 'CC6.7' },
    ],
    remediation_template: {
      summary: {
        es: 'Habilitar "Always Use HTTPS", "Automatic HTTPS Rewrites" y configurar SSL en modo Full (Strict)',
        en: 'Enable "Always Use HTTPS", "Automatic HTTPS Rewrites", and set SSL to Full (Strict) mode',
      },
      risk_if_ignored: {
        es: 'Configuraciones inseguras permiten conexiones sin cifrar, contenido mixto que degrada la seguridad, y validación incompleta de certificados de origen',
        en: 'Insecure configurations allow unencrypted connections, mixed content that degrades security, and incomplete origin certificate validation',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar "Always Use HTTPS"', en: 'Enable "Always Use HTTPS"' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'Localiza "Always Use HTTPS" y activa el toggle. Esto crea una regla de redirección 301 de HTTP a HTTPS para todo el tráfico. Se aplica automáticamente.',
            en: 'Locate "Always Use HTTPS" and enable the toggle. This creates a 301 redirect rule from HTTP to HTTPS for all traffic. Applied automatically.',
          },
        },
        {
          order: 2,
          action: { es: 'Habilitar "Automatic HTTPS Rewrites"', en: 'Enable "Automatic HTTPS Rewrites"' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'Activa "Automatic HTTPS Rewrites". Esto corrige automáticamente URLs de contenido mixto (http://) a HTTPS en las respuestas HTML, evitando advertencias de "mixed content" en navegadores.',
            en: 'Enable "Automatic HTTPS Rewrites". This automatically fixes mixed content URLs (http://) to HTTPS in HTML responses, preventing "mixed content" warnings in browsers.',
          },
        },
        {
          order: 3,
          action: { es: 'Configurar SSL en Full (Strict)', en: 'Set SSL to Full (Strict)' },
          where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' },
          detail: {
            es: 'Selecciona "Completo (estricto)" como modo de encriptación. Esto asegura que Cloudflare valida el certificado SSL del servidor de origen, previniendo ataques de suplantación.',
            en: 'Select "Full (strict)" as encryption mode. This ensures Cloudflare validates the origin server SSL certificate, preventing spoofing attacks.',
          },
        },
        {
          order: 4,
          action: { es: 'Verificar configuración', en: 'Verify configuration' },
          where: { es: 'Dashboard > SSL/TLS', en: 'Dashboard > SSL/TLS' },
          detail: {
            es: 'Verifica que el modo SSL muestre "Full (Strict)", "Always Use HTTPS" muestre "On", y "Automatic HTTPS Rewrites" muestre "On".',
            en: 'Verify SSL mode shows "Full (Strict)", "Always Use HTTPS" shows "On", and "Automatic HTTPS Rewrites" shows "On".',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const alwaysHttps = s(ctx, 'always_use_https');
      const autoRewrites = s(ctx, 'automatic_https_rewrites');
      const ssl = s(ctx, 'ssl');

      const isAlwaysHttps = alwaysHttps === 'on';
      const isAutoRewrites = autoRewrites === 'on';
      const isSslStrict = ssl === 'strict' || ssl === 'full_strict';

      const checks = [isAlwaysHttps, isAutoRewrites, isSslStrict];
      const passed = checks.filter(Boolean).length;

      if (passed === 3) {
        return ev(
          'pass', 100,
          `Always HTTPS: on, Auto Rewrites: on, SSL: ${ssl}`,
          'Always HTTPS + Auto Rewrites + SSL Full (Strict)',
          'All security configuration settings are properly established.',
          ['zone_settings.always_use_https', 'zone_settings.automatic_https_rewrites', 'zone_settings.ssl'],
        );
      }
      if (passed >= 1) {
        const issues: string[] = [];
        if (!isAlwaysHttps) issues.push('"Always Use HTTPS" disabled');
        if (!isAutoRewrites) issues.push('"Automatic HTTPS Rewrites" disabled');
        if (!isSslStrict) issues.push(`SSL mode "${ssl || 'unknown'}" is not Full (Strict)`);
        return ev(
          'partial', Math.round((passed / 3) * 100),
          `Always HTTPS: ${alwaysHttps || 'off'}, Auto Rewrites: ${autoRewrites || 'off'}, SSL: ${ssl || 'unknown'}`,
          'Always HTTPS + Auto Rewrites + SSL Full (Strict)',
          `${passed}/3 configuration settings correct. Issues: ${issues.join('; ')}.`,
          ['zone_settings.always_use_https', 'zone_settings.automatic_https_rewrites', 'zone_settings.ssl'],
        );
      }
      return ev(
        'fail', 0,
        `Always HTTPS: ${alwaysHttps || 'off'}, Auto Rewrites: ${autoRewrites || 'off'}, SSL: ${ssl || 'unknown'}`,
        'Always HTTPS + Auto Rewrites + SSL Full (Strict)',
        'None of the expected security configuration settings are properly established.',
        ['zone_settings.always_use_https', 'zone_settings.automatic_https_rewrites', 'zone_settings.ssl'],
      );
    },
  },

  // ================================================================
  // SC-5 — Denial of Service Protection
  // ================================================================
  {
    control_id: 'NIST-800-53-SC-5',
    control_ref: 'SC-5',
    framework: 'nist_800_53',
    section_id: 'sc',
    title: { es: 'SC-5: Protección contra Denegación de Servicio', en: 'SC-5: Denial of Service Protection' },
    description: {
      es: 'El sistema debe protegerse contra ataques de denegación de servicio mediante rate limiting y controles de tráfico.',
      en: 'The system must protect against denial-of-service attacks through rate limiting and traffic controls.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SC: Protección de Sistemas y Comunicaciones', en: 'SC: System and Communications Protection' },
      clause: 'SC-5',
      official_text: {
        es: 'El sistema de información protege contra o limita los efectos de los tipos de ataques de denegación de servicio especificados.',
        en: 'The information system protects against or limits the effects of the specified types of denial-of-service attacks.',
      },
      applicability_note: {
        es: 'En Cloudflare: Rate limiting rules + security level + DDoS managed rules proveen protección SC-5.',
        en: 'In Cloudflare: Rate limiting rules + security level + DDoS managed rules provide SC-5 protection.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['rulesets', 'zone_settings.security_level'],
    required_permissions: ['Zone:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'infra_baseline', control_id: 'INFRA-RATE-001', clause: 'RATE-001' },
      { framework: 'infra_baseline', control_id: 'INFRA-DDOS-001', clause: 'DDOS-001' },
    ],
    remediation_template: {
      summary: { es: 'Configurar rate limiting y nivel de seguridad adecuado', en: 'Configure rate limiting and adequate security level' },
      risk_if_ignored: {
        es: 'Sin protección DoS, los atacantes pueden saturar el servicio haciéndolo inaccesible.',
        en: 'Without DoS protection, attackers can saturate the service making it inaccessible.',
      },
      steps: [
        { order: 1, action: { es: 'Configurar rate limiting', en: 'Configure rate limiting' }, where: { es: 'Dashboard > Seguridad > WAF > Rate limiting', en: 'Dashboard > Security > WAF > Rate limiting' }, detail: { es: 'Crear reglas de rate limiting para endpoints críticos.', en: 'Create rate limiting rules for critical endpoints.' } },
        { order: 2, action: { es: 'Establecer nivel de seguridad', en: 'Set security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer nivel de seguridad en Medium o superior.', en: 'Set security level to Medium or higher.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/rate-limiting-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const rlRules = getRateLimitRules(ctx);
      const secLevel = s(ctx, 'security_level');
      const hasRL = rlRules.filter((r: any) => r.enabled !== false).length > 0;
      const hasSecLevel = ['medium', 'high', 'under_attack'].includes(secLevel);
      if (hasRL && hasSecLevel) return ev('pass', 100, `rate limit rules: ${rlRules.length}, security level: ${secLevel}`, 'rate limiting + medium+ security level', 'DoS protections are active.', ['rulesets', 'zone_settings']);
      if (hasRL || hasSecLevel) return ev('partial', 50, `rate limit: ${hasRL}, security level: ${secLevel}`, 'rate limiting + medium+ security level', `Partial DoS protection: ${hasRL ? 'rate limiting active' : 'no rate limiting'}, ${hasSecLevel ? 'security level OK' : 'security level too low'}.`, ['rulesets', 'zone_settings']);
      return ev('fail', 0, `no rate limiting, security level: ${secLevel}`, 'rate limiting + medium+ security level', 'No DoS protections configured.', ['rulesets', 'zone_settings']);
    },
  },

  // ================================================================
  // SC-28 — Protection of Information at Rest (headers)
  // ================================================================
  {
    control_id: 'NIST-800-53-SC-28',
    control_ref: 'SC-28',
    framework: 'nist_800_53',
    section_id: 'sc',
    title: { es: 'SC-28: Protección de Información en Reposo', en: 'SC-28: Protection of Information at Rest' },
    description: {
      es: 'Los headers de seguridad deben prevenir el almacenamiento en caché de información sensible en el navegador del cliente.',
      en: 'Security headers must prevent caching of sensitive information in the client browser.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SC: Protección de Sistemas y Comunicaciones', en: 'SC: System and Communications Protection' },
      clause: 'SC-28',
      official_text: {
        es: 'El sistema de información protege la confidencialidad e integridad de la información en reposo.',
        en: 'The information system protects the confidentiality and integrity of information at rest.',
      },
      applicability_note: {
        es: 'En Cloudflare: X-Content-Type-Options nosniff y Cache-Control previenen exposición de datos en caché.',
        en: 'In Cloudflare: X-Content-Type-Options nosniff and Cache-Control prevent data exposure via cache.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'infra_baseline', control_id: 'INFRA-HDR-002', clause: 'HDR-002' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar nosniff para proteger información en reposo', en: 'Enable nosniff to protect information at rest' },
      risk_if_ignored: {
        es: 'Sin nosniff, el navegador puede interpretar incorrectamente tipos MIME exponiendo datos sensibles.',
        en: 'Without nosniff, the browser may misinterpret MIME types exposing sensitive data.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar nosniff en Security Headers', en: 'Enable nosniff in Security Headers' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar "No-sniff header" en la sección HSTS.', en: 'Enable "No-sniff header" in the HSTS section.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-header/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      if (hsts.nosniff) return ev('pass', 100, 'nosniff: enabled', 'nosniff enabled', 'X-Content-Type-Options nosniff is enabled — browser MIME sniffing prevented.', ['zone_settings']);
      return ev('fail', 0, 'nosniff: disabled', 'nosniff enabled', 'X-Content-Type-Options nosniff is not enabled.', ['zone_settings']);
    },
  },

  // ================================================================
  // SI-3 — Malicious Code Protection
  // ================================================================
  {
    control_id: 'NIST-800-53-SI-3',
    control_ref: 'SI-3',
    framework: 'nist_800_53',
    section_id: 'si',
    title: { es: 'SI-3: Protección contra Código Malicioso', en: 'SI-3: Malicious Code Protection' },
    description: {
      es: 'El sistema debe implementar mecanismos de protección contra código malicioso en puntos de entrada del sistema de información.',
      en: 'The system must implement malicious code protection mechanisms at information system entry points.',
    },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SI: Integridad del Sistema y la Información', en: 'SI: System and Information Integrity' },
      clause: 'SI-3',
      official_text: {
        es: 'El sistema de información implementa mecanismos de protección contra código malicioso en los puntos de entrada y salida del sistema.',
        en: 'The information system implements malicious code protection mechanisms at information system entry and exit points.',
      },
      applicability_note: {
        es: 'En Cloudflare: El WAF administrado con OWASP protege contra código malicioso (SQLi, XSS, RCE, etc.).',
        en: 'In Cloudflare: Managed WAF with OWASP protects against malicious code (SQLi, XSS, RCE, etc.).',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_csf', control_id: 'NIST-CSF-DE.CM-4', clause: 'DE.CM-4' },
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'infra_baseline', control_id: 'INFRA-WAF-001', clause: 'WAF-001' },
    ],
    remediation_template: {
      summary: { es: 'Activar WAF con OWASP para protección contra código malicioso', en: 'Enable WAF with OWASP for malicious code protection' },
      risk_if_ignored: {
        es: 'Sin WAF, el código malicioso (SQLi, XSS, RCE) puede ejecutarse en el sistema.',
        en: 'Without WAF, malicious code (SQLi, XSS, RCE) may execute on the system.',
      },
      steps: [
        { order: 1, action: { es: 'Activar WAF administrado + OWASP', en: 'Enable managed WAF + OWASP' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Activar Cloudflare Managed Ruleset y OWASP Core Ruleset.', en: 'Enable Cloudflare Managed Ruleset and OWASP Core Ruleset.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const managed = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);
      if (managed && owasp) return ev('pass', 100, 'managed WAF + OWASP active', 'WAF + OWASP', 'Malicious code protection is active via managed WAF and OWASP ruleset.', ['rulesets']);
      if (managed) return ev('partial', 60, 'managed WAF active, no OWASP', 'WAF + OWASP', 'WAF active but OWASP Core Ruleset not deployed — protection is incomplete.', ['rulesets']);
      return ev('fail', 0, 'no managed WAF', 'WAF + OWASP', 'No malicious code protection deployed.', ['rulesets']);
    },
  },

  // ================================================================
  // AC-17 — Remote Access
  // ================================================================
  {
    control_id: 'NIST-800-53-AC-17',
    control_ref: 'AC-17',
    framework: 'nist_800_53',
    section_id: 'ac',
    title: { es: 'AC-17: Acceso Remoto Seguro', en: 'AC-17: Remote Access Security' },
    description: {
      es: 'El acceso remoto al sistema debe estar protegido con cifrado fuerte y controles de autenticación.',
      en: 'Remote access to the system must be protected with strong encryption and authentication controls.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'AC: Control de Acceso', en: 'AC: Access Control' },
      clause: 'AC-17',
      official_text: {
        es: 'La organización establece y documenta las restricciones de uso, los requisitos de configuración y conexión, y la guía de implementación para cada tipo de acceso remoto permitido.',
        en: 'The organization establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of allowed remote access.',
      },
      applicability_note: {
        es: 'En Cloudflare: TLS 1.3, HSTS y SSL Full (Strict) garantizan que el acceso remoto sea cifrado y autenticado.',
        en: 'In Cloudflare: TLS 1.3, HSTS, and SSL Full (Strict) ensure remote access is encrypted and authenticated.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.tls_1_3', 'zone_settings.ssl', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
    ],
    remediation_template: {
      summary: { es: 'Asegurar TLS 1.3 + SSL Strict + HSTS para acceso remoto seguro', en: 'Ensure TLS 1.3 + SSL Strict + HSTS for secure remote access' },
      risk_if_ignored: {
        es: 'Sin cifrado fuerte, las sesiones de acceso remoto pueden ser interceptadas.',
        en: 'Without strong encryption, remote access sessions can be intercepted.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar TLS 1.3', en: 'Enable TLS 1.3' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar TLS 1.3.', en: 'Enable TLS 1.3.' } },
        { order: 2, action: { es: 'Establecer SSL a Full (Strict)', en: 'Set SSL to Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Overview', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar Full (Strict).', en: 'Select Full (Strict).' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls13 = s(ctx, 'tls_1_3') === 'on';
      const ssl = s(ctx, 'ssl') === 'strict';
      const hsts = getHsts(ctx);
      const checks = [tls13, ssl, hsts.enabled];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `TLS1.3: on, SSL: strict, HSTS: ${hsts.max_age}s`, 'TLS 1.3 + SSL Strict + HSTS', 'Remote access is secured with TLS 1.3, SSL Full Strict, and HSTS.', ['zone_settings']);
      if (passed >= 2) return ev('partial', Math.round((passed / 3) * 100), `TLS1.3: ${tls13}, SSL strict: ${ssl}, HSTS: ${hsts.enabled}`, 'TLS 1.3 + SSL Strict + HSTS', `${passed}/3 remote access security controls active.`, ['zone_settings']);
      return ev('fail', 0, `TLS1.3: ${tls13}, SSL strict: ${ssl}, HSTS: ${hsts.enabled}`, 'TLS 1.3 + SSL Strict + HSTS', 'Remote access security controls are insufficient.', ['zone_settings']);
    },
  },

  // ================================================================
  // RA-5 — Vulnerability Monitoring
  // ================================================================
  {
    control_id: 'NIST-800-53-RA-5',
    control_ref: 'RA-5',
    framework: 'nist_800_53',
    section_id: 'ra',
    title: { es: 'RA-5: Monitoreo de Vulnerabilidades', en: 'RA-5: Vulnerability Monitoring' },
    description: {
      es: 'Deben existir controles de monitoreo activo de vulnerabilidades mediante WAF y reglas actualizadas.',
      en: 'Active vulnerability monitoring controls must exist through WAF and updated rules.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'RA: Evaluación de Riesgo', en: 'RA: Risk Assessment' },
      clause: 'RA-5',
      official_text: {
        es: 'La organización monitorea y escanea las vulnerabilidades en el sistema de información y las aplicaciones alojadas periódicamente.',
        en: 'The organization monitors and scans for vulnerabilities in the information system and hosted applications periodically.',
      },
      applicability_note: {
        es: 'En Cloudflare: El WAF administrado con reglas actualizadas automáticamente provee monitoreo continuo de vulnerabilidades.',
        en: 'In Cloudflare: Managed WAF with automatically updated rules provides continuous vulnerability monitoring.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SI-3', clause: 'SI-3' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-DE.CM-4', clause: 'DE.CM-4' },
    ],
    remediation_template: {
      summary: { es: 'Asegurar WAF administrado activo para monitoreo de vulnerabilidades', en: 'Ensure active managed WAF for vulnerability monitoring' },
      risk_if_ignored: {
        es: 'Sin monitoreo de vulnerabilidades, las nuevas vulnerabilidades pueden ser explotadas sin detección.',
        en: 'Without vulnerability monitoring, new vulnerabilities may be exploited without detection.',
      },
      steps: [
        { order: 1, action: { es: 'Verificar WAF administrado activo', en: 'Verify managed WAF is active' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' }, detail: { es: 'Confirmar que las reglas administradas están en modo "Block" o "Challenge".', en: 'Confirm managed rules are in "Block" or "Challenge" mode.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const managed = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);
      if (managed && owasp) return ev('pass', 100, 'managed WAF + OWASP active', 'managed WAF active', 'Vulnerability monitoring via managed WAF and OWASP is active.', ['rulesets']);
      if (managed) return ev('partial', 65, 'managed WAF active, no OWASP', 'managed WAF + OWASP', 'WAF active but OWASP rules not enabled — add for comprehensive coverage.', ['rulesets']);
      return ev('fail', 0, 'no managed WAF', 'managed WAF active', 'No automated vulnerability monitoring deployed.', ['rulesets']);
    },
  },

  // ================================================================
  // CA-7 — Continuous Monitoring
  // ================================================================
  {
    control_id: 'NIST-800-53-CA-7',
    control_ref: 'CA-7',
    framework: 'nist_800_53',
    section_id: 'ca',
    title: { es: 'CA-7: Monitoreo Continuo', en: 'CA-7: Continuous Monitoring' },
    description: {
      es: 'El sistema debe contar con monitoreo continuo mediante logs exportados y configuración de alertas.',
      en: 'The system must have continuous monitoring through exported logs and alert configuration.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CA: Evaluación, Autorización y Monitoreo', en: 'CA: Assessment, Authorization and Monitoring' },
      clause: 'CA-7',
      official_text: {
        es: 'La organización desarrolla una estrategia de monitoreo continuo y un programa de monitoreo continuo que incluya métricas, frecuencias y reporte de estado de seguridad.',
        en: 'The organization develops a continuous monitoring strategy and a continuous monitoring program including metrics, frequencies, and security status reporting.',
      },
      applicability_note: {
        es: 'En Cloudflare: Logpush con firewall_events y http_requests provee la base de monitoreo continuo.',
        en: 'In Cloudflare: Logpush with firewall_events and http_requests provides the basis for continuous monitoring.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['logpush_jobs'],
    required_permissions: ['Logs:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-AU-2', clause: 'AU-2' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC7.2', clause: 'CC7.2' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush para monitoreo continuo', en: 'Configure Logpush for continuous monitoring' },
      risk_if_ignored: {
        es: 'Sin monitoreo continuo, los incidentes de seguridad pueden pasar desapercibidos durante días o semanas.',
        en: 'Without continuous monitoring, security incidents may go undetected for days or weeks.',
      },
      steps: [
        { order: 1, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Analytics & Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Crear jobs de Logpush para firewall_events y http_requests.', en: 'Create Logpush jobs for firewall_events and http_requests.' } },
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
          return ev('insufficient_permissions', 0, 'N/A', 'Requires: Logs:Read', 'Token lacks Logs:Read permission.', ['logpush_jobs']);
        }
        return ev('fail', 0, 'no logpush data', '1+ active logpush jobs', 'Logpush data unavailable — continuous monitoring may not be configured.', ['logpush_jobs']);
      }
      const jobs = Array.isArray(logpush) ? logpush : [];
      const activeJobs = jobs.filter((j: any) => j.enabled !== false);
      if (activeJobs.length > 0) return ev('pass', 100, `${activeJobs.length} active Logpush jobs`, '1+ active jobs', `${activeJobs.length} active Logpush job(s) configured for continuous monitoring.`, ['logpush_jobs']);
      return ev('fail', 0, 'no active logpush jobs', '1+ active jobs', 'No active Logpush jobs — continuous monitoring not configured.', ['logpush_jobs']);
    },
  },

  // ================================================================
  // SC-12 — Cryptographic Key Establishment and Management
  // ================================================================
  {
    control_id: 'NIST-800-53-SC-12',
    control_ref: 'SC-12',
    framework: 'nist_800_53',
    section_id: 'sc',
    title: { es: 'SC-12: Gestión de Claves Criptográficas', en: 'SC-12: Cryptographic Key Establishment and Management' },
    description: {
      es: 'Se establecen y gestionan claves criptográficas para los sistemas de información mediante certificados TLS válidos y activos gestionados por Cloudflare.',
      en: 'Cryptographic keys are established and managed for information systems through valid and active TLS certificates managed by Cloudflare.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SC: Protección de Sistemas y Comunicaciones', en: 'SC: System and Communications Protection' },
      clause: 'SC-12',
      official_text: {
        es: 'La organización establece y gestiona claves criptográficas cuando se emplea criptografía dentro del sistema de información.',
        en: 'The organization establishes and manages cryptographic keys when cryptography is employed within the information system.',
      },
      applicability_note: {
        es: 'En Cloudflare: SSL Full (Strict) implica certificados válidos y gestionados tanto en edge como en origen. La gestión de claves se evalúa a través del modo SSL y la versión TLS mínima.',
        en: 'In Cloudflare: SSL Full (Strict) implies valid and managed certificates at both edge and origin. Key management is evaluated through SSL mode and minimum TLS version.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.min_tls_version'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
      { framework: 'infra_baseline', control_id: 'INFRA-TLS-002', clause: 'TLS-002' },
    ],
    remediation_template: {
      summary: { es: 'Asegurar SSL Full (Strict) y TLS 1.2+ para gestión correcta de claves', en: 'Ensure SSL Full (Strict) and TLS 1.2+ for correct key management' },
      risk_if_ignored: {
        es: 'Sin gestión correcta de claves criptográficas, los certificados pueden expirar o ser inválidos, comprometiendo toda la cadena de cifrado.',
        en: 'Without correct cryptographic key management, certificates may expire or be invalid, compromising the entire encryption chain.',
      },
      steps: [
        { order: 1, action: { es: 'Verificar SSL Full (Strict)', en: 'Verify SSL Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Confirmar modo Full (Strict) para validar certificados de origen.', en: 'Confirm Full (Strict) mode to validate origin certificates.' } },
        { order: 2, action: { es: 'Verificar certificado de origen válido', en: 'Verify valid origin certificate' }, where: { es: 'Dashboard > SSL/TLS > Certificados de origen', en: 'Dashboard > SSL/TLS > Origin Certificates' }, detail: { es: 'Confirmar que el certificado de origen está vigente. Usar Cloudflare Origin CA si es necesario.', en: 'Confirm origin certificate is valid. Use Cloudflare Origin CA if needed.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const minTls = s(ctx, 'min_tls_version');
      const isSslStrict = ssl === 'strict' || ssl === 'full_strict';
      const isMinTlsOk = minTls === '1.2' || minTls === '1.3';
      if (isSslStrict && isMinTlsOk) return ev('pass', 100, `SSL: ${ssl}, Min TLS: ${minTls}`, 'SSL Full (Strict) + TLS 1.2+', 'Cryptographic key management is in place with SSL Full Strict and modern TLS.', ['zone_settings.ssl', 'zone_settings.min_tls_version']);
      if (isSslStrict || isMinTlsOk) return ev('partial', 50, `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}`, 'SSL Full (Strict) + TLS 1.2+', `Partial key management: ${isSslStrict ? 'SSL Strict OK' : 'SSL not Strict'}, ${isMinTlsOk ? 'TLS OK' : 'TLS below 1.2'}.`, ['zone_settings.ssl', 'zone_settings.min_tls_version']);
      return ev('fail', 0, `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}`, 'SSL Full (Strict) + TLS 1.2+', 'Cryptographic key management not properly configured.', ['zone_settings.ssl', 'zone_settings.min_tls_version']);
    },
  },

  // ================================================================
  // SI-4 — System Monitoring
  // ================================================================
  {
    control_id: 'NIST-800-53-SI-4',
    control_ref: 'SI-4',
    framework: 'nist_800_53',
    section_id: 'si',
    title: { es: 'SI-4: Monitoreo del Sistema', en: 'SI-4: System Monitoring' },
    description: {
      es: 'El sistema debe ser monitoreado para detectar ataques, indicadores de posibles ataques, y conexiones no autorizadas mediante Logpush y niveles de seguridad adecuados.',
      en: 'The system must be monitored to detect attacks, indicators of potential attacks, and unauthorized connections through Logpush and adequate security levels.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SI: Integridad del Sistema y la Información', en: 'SI: System and Information Integrity' },
      clause: 'SI-4',
      official_text: {
        es: 'La organización monitorea el sistema de información para detectar: ataques e indicadores de posibles ataques; y conexiones locales, de red e inalámbricas no autorizadas.',
        en: 'The organization monitors the information system to detect: attacks and indicators of potential attacks; and unauthorized local, network, and remote connections.',
      },
      applicability_note: {
        es: 'En Cloudflare: Logpush con firewall_events provee monitoreo continuo del sistema. El nivel de seguridad determina la sensibilidad de detección.',
        en: 'In Cloudflare: Logpush with firewall_events provides continuous system monitoring. Security level determines detection sensitivity.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['logpush_jobs', 'zone_settings.security_level'],
    required_permissions: ['Zone:Read', 'Logs:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CA-7', clause: 'CA-7' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-DE.AE-3', clause: 'DE.AE-3' },
      { framework: 'infra_baseline', control_id: 'INFRA-LOG-001', clause: 'LOG-001' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush y nivel de seguridad para monitoreo del sistema', en: 'Configure Logpush and security level for system monitoring' },
      risk_if_ignored: {
        es: 'Sin monitoreo del sistema, los ataques activos pueden pasar desapercibidos durante horas o días.',
        en: 'Without system monitoring, active attacks may go undetected for hours or days.',
      },
      steps: [
        { order: 1, action: { es: 'Configurar Logpush', en: 'Configure Logpush' }, where: { es: 'Dashboard > Analytics & Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Crear job para firewall_events y http_requests.', en: 'Create job for firewall_events and http_requests.' } },
        { order: 2, action: { es: 'Establecer nivel de seguridad', en: 'Set security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer Medium o superior para detección activa.', en: 'Set Medium or higher for active detection.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const logpush = ctx.enriched_data?.logpush_jobs;
      const secLevel = s(ctx, 'security_level');
      const hasLogs = logpush && (logpush.has_firewall_logs || logpush.has_http_logs);
      const hasSecLevel = ['medium', 'high', 'under_attack'].includes(secLevel);
      if (hasLogs && hasSecLevel) return ev('pass', 100, `Logpush: active, security level: ${secLevel}`, 'Logpush + medium+ security level', 'System monitoring is active via Logpush export and adequate security level.', ['logpush_jobs', 'zone_settings.security_level']);
      if (hasLogs || hasSecLevel) return ev('partial', 50, `Logpush: ${hasLogs ? 'active' : 'inactive'}, security level: ${secLevel || 'low'}`, 'Logpush + medium+ security level', `Partial monitoring: ${hasLogs ? 'logs active' : 'no logs'}, security level: ${secLevel || 'low'}.`, ['logpush_jobs', 'zone_settings.security_level']);
      return ev('fail', 0, `Logpush: inactive, security level: ${secLevel || 'off'}`, 'Logpush + medium+ security level', 'No system monitoring configured.', ['logpush_jobs', 'zone_settings.security_level']);
    },
  },

  // ================================================================
  // AC-4 — Information Flow Enforcement
  // ================================================================
  {
    control_id: 'NIST-800-53-AC-4',
    control_ref: 'AC-4',
    framework: 'nist_800_53',
    section_id: 'ac',
    title: { es: 'AC-4: Control de Flujo de Información', en: 'AC-4: Information Flow Enforcement' },
    description: {
      es: 'El sistema debe controlar el flujo de información dentro del sistema y entre sistemas basándose en políticas de seguridad mediante WAF y rate limiting.',
      en: 'The system must control the flow of information within the system and between interconnected systems based on security policies through WAF and rate limiting.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'AC: Control de Acceso', en: 'AC: Access Control' },
      clause: 'AC-4',
      official_text: {
        es: 'El sistema de información hace cumplir las políticas de control de flujo de información aprobadas dentro del sistema y entre sistemas interconectados.',
        en: 'The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems.',
      },
      applicability_note: {
        es: 'En Cloudflare: El WAF y las reglas de rate limiting son los mecanismos de control de flujo de información a nivel de red HTTP.',
        en: 'In Cloudflare: WAF and rate limiting rules are the mechanisms for controlling information flow at the HTTP network level.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-5', clause: 'SC-5' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SI-3', clause: 'SI-3' },
      { framework: 'infra_baseline', control_id: 'INFRA-WAF-001', clause: 'WAF-001' },
    ],
    remediation_template: {
      summary: { es: 'Implementar WAF + rate limiting para control de flujo de información', en: 'Implement WAF + rate limiting for information flow control' },
      risk_if_ignored: {
        es: 'Sin control de flujo, el tráfico malicioso puede fluir sin restricción hacia sistemas internos.',
        en: 'Without flow control, malicious traffic can flow unrestricted to internal systems.',
      },
      steps: [
        { order: 1, action: { es: 'Activar WAF con reglas administradas', en: 'Enable WAF with managed rules' }, where: { es: 'Dashboard > Seguridad > WAF', en: 'Dashboard > Security > WAF' }, detail: { es: 'Desplegar Cloudflare Managed Ruleset para control de tráfico HTTP.', en: 'Deploy Cloudflare Managed Ruleset for HTTP traffic control.' } },
        { order: 2, action: { es: 'Crear reglas de rate limiting', en: 'Create rate limiting rules' }, where: { es: 'Dashboard > Seguridad > WAF > Rate limiting', en: 'Dashboard > Security > WAF > Rate limiting' }, detail: { es: 'Establecer límites de velocidad para controlar el flujo de información.', en: 'Set rate limits to control information flow.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const rlRules = getRateLimitRules(ctx);
      const hasRL = rlRules.filter((r: any) => r.enabled !== false).length > 0;
      if (waf && hasRL) return ev('pass', 100, `managed WAF: active, rate limiting: ${rlRules.length} rules`, 'managed WAF + rate limiting', 'Information flow control is enforced via WAF and rate limiting.', ['rulesets']);
      if (waf || hasRL) return ev('partial', 55, `managed WAF: ${waf}, rate limiting: ${hasRL ? rlRules.length + ' rules' : 'none'}`, 'managed WAF + rate limiting', `Partial flow control: ${waf ? 'WAF active' : 'no WAF'}, ${hasRL ? 'rate limiting active' : 'no rate limiting'}.`, ['rulesets']);
      return ev('fail', 0, 'no WAF, no rate limiting', 'managed WAF + rate limiting', 'No information flow control mechanisms deployed.', ['rulesets']);
    },
  },

  // ================================================================
  // SC-23 — Session Authenticity
  // ================================================================
  {
    control_id: 'NIST-800-53-SC-23',
    control_ref: 'SC-23',
    framework: 'nist_800_53',
    section_id: 'sc',
    title: { es: 'SC-23: Autenticidad de Sesión', en: 'SC-23: Session Authenticity' },
    description: {
      es: 'El sistema debe proteger la autenticidad de las sesiones de comunicación mediante TLS 1.3 y SSL Full (Strict) para garantizar que las sesiones no pueden ser interceptadas o falsificadas.',
      en: 'The system must protect the authenticity of communication sessions through TLS 1.3 and SSL Full (Strict) to ensure sessions cannot be intercepted or spoofed.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'SC: Protección de Sistemas y Comunicaciones', en: 'SC: System and Communications Protection' },
      clause: 'SC-23',
      official_text: {
        es: 'El sistema de información protege la autenticidad de las sesiones de comunicación.',
        en: 'The information system protects the authenticity of communications sessions.',
      },
      applicability_note: {
        es: 'En Cloudflare: TLS 1.3 con sus propiedades de forward secrecy y SSL Full (Strict) con validación de certificados garantizan la autenticidad de las sesiones de comunicación.',
        en: 'In Cloudflare: TLS 1.3 with its forward secrecy properties and SSL Full (Strict) with certificate validation guarantee the authenticity of communication sessions.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.tls_1_3', 'zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar TLS 1.3 y SSL Full (Strict) para autenticidad de sesiones', en: 'Enable TLS 1.3 and SSL Full (Strict) for session authenticity' },
      risk_if_ignored: {
        es: 'Sin autenticidad de sesión, los atacantes pueden interceptar o falsificar sesiones de usuario.',
        en: 'Without session authenticity, attackers can intercept or spoof user sessions.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar TLS 1.3', en: 'Enable TLS 1.3' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar TLS 1.3 — ofrece forward secrecy mejorado.', en: 'Enable TLS 1.3 — provides improved forward secrecy.' } },
        { order: 2, action: { es: 'Configurar SSL Full (Strict)', en: 'Set SSL Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar Full (Strict) para validar certificados y garantizar autenticidad.', en: 'Select Full (Strict) to validate certificates and ensure authenticity.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/tls-13/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const tls13 = s(ctx, 'tls_1_3');
      const ssl = s(ctx, 'ssl');
      const isTls13 = tls13 === 'on' || tls13 === 'zrt';
      const isSslStrict = ssl === 'strict' || ssl === 'full_strict';
      if (isTls13 && isSslStrict) return ev('pass', 100, `TLS 1.3: ${tls13}, SSL: ${ssl}`, 'TLS 1.3 on + SSL Full (Strict)', 'Session authenticity is fully protected with TLS 1.3 and SSL Full Strict.', ['zone_settings.tls_1_3', 'zone_settings.ssl']);
      if (isTls13 || isSslStrict) return ev('partial', 50, `TLS 1.3: ${tls13 || 'off'}, SSL: ${ssl || 'unknown'}`, 'TLS 1.3 on + SSL Full (Strict)', `Partial session authenticity: ${isTls13 ? 'TLS 1.3 on' : 'TLS 1.3 off'}, ${isSslStrict ? 'SSL Strict' : 'SSL not Strict'}.`, ['zone_settings.tls_1_3', 'zone_settings.ssl']);
      return ev('fail', 0, `TLS 1.3: off, SSL: ${ssl || 'unknown'}`, 'TLS 1.3 on + SSL Full (Strict)', 'Session authenticity not configured — sessions may be intercepted or spoofed.', ['zone_settings.tls_1_3', 'zone_settings.ssl']);
    },
  },

  // ================================================================
  // CM-7 — Least Functionality
  // ================================================================
  {
    control_id: 'NIST-800-53-CM-7',
    control_ref: 'CM-7',
    framework: 'nist_800_53',
    section_id: 'cm',
    title: { es: 'CM-7: Funcionalidad Mínima', en: 'CM-7: Least Functionality' },
    description: {
      es: 'El sistema debe configurarse para proporcionar solo las capacidades esenciales, bloqueando funcionalidades no requeridas mediante Bot Fight Mode y nivel de seguridad adecuado.',
      en: 'The system must be configured to provide only essential capabilities, blocking non-required functionality through Bot Fight Mode and adequate security level.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'CM: Gestión de Configuración', en: 'CM: Configuration Management' },
      clause: 'CM-7',
      official_text: {
        es: 'La organización configura el sistema de información para proporcionar solo capacidades esenciales y específicamente prohíbe o restringe el uso de funciones, puertos, protocolos y servicios.',
        en: 'The organization configures the information system to provide only essential capabilities and specifically prohibits or restricts the use of functions, ports, protocols, and services.',
      },
      applicability_note: {
        es: 'En Cloudflare: Bot Fight Mode bloquea tráfico de bots no deseado y el nivel de seguridad restringe tráfico de IPs con reputación negativa, implementando el principio de funcionalidad mínima.',
        en: 'In Cloudflare: Bot Fight Mode blocks unwanted bot traffic and security level restricts traffic from IPs with negative reputation, implementing the least functionality principle.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.bot_fight_mode', 'zone_settings.security_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CM-6', clause: 'CM-6' },
      { framework: 'infra_baseline', control_id: 'INFRA-ACC-001', clause: 'ACC-001' },
    ],
    remediation_template: {
      summary: { es: 'Activar Bot Fight Mode y nivel de seguridad para funcionalidad mínima', en: 'Enable Bot Fight Mode and security level for least functionality' },
      risk_if_ignored: {
        es: 'Sin restricciones de funcionalidad, los bots y tráfico malicioso pueden acceder y usar el sistema libremente.',
        en: 'Without functionality restrictions, bots and malicious traffic can freely access and use the system.',
      },
      steps: [
        { order: 1, action: { es: 'Activar Bot Fight Mode', en: 'Enable Bot Fight Mode' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Activar Bot Fight Mode para bloquear bots verificados.', en: 'Enable Bot Fight Mode to block verified bots.' } },
        { order: 2, action: { es: 'Establecer nivel de seguridad apropiado', en: 'Set appropriate security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer Medium como mínimo para restringir IPs maliciosas conocidas.', en: 'Set Medium as minimum to restrict known malicious IPs.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/bots/get-started/free/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const botMode = s(ctx, 'bot_fight_mode');
      const secLevel = s(ctx, 'security_level');
      const hasBotMode = botMode === 'on' || botMode === true;
      const hasSecLevel = ['medium', 'high', 'under_attack'].includes(secLevel);
      if (hasBotMode && hasSecLevel) return ev('pass', 100, `Bot Fight Mode: on, security level: ${secLevel}`, 'Bot Fight Mode on + medium+ security level', 'Least functionality principle is applied via Bot Fight Mode and security level.', ['zone_settings']);
      if (hasBotMode || hasSecLevel) return ev('partial', 50, `Bot Fight Mode: ${hasBotMode ? 'on' : 'off'}, security level: ${secLevel || 'low'}`, 'Bot Fight Mode on + medium+ security level', `Partial functionality restriction: ${hasBotMode ? 'Bot Fight Mode on' : 'Bot Fight Mode off'}, security level: ${secLevel || 'low'}.`, ['zone_settings']);
      return ev('fail', 0, `Bot Fight Mode: off, security level: ${secLevel || 'off'}`, 'Bot Fight Mode on + medium+ security level', 'No functionality restriction configured.', ['zone_settings']);
    },
  },

  // ================================================================
  // AC-18 — Wireless Access Protection
  // ================================================================
  {
    control_id: 'NIST-800-53-AC-18',
    control_ref: 'AC-18',
    framework: 'nist_800_53',
    section_id: 'ac',
    title: { es: 'AC-18: Protección de Acceso Inalámbrico', en: 'AC-18: Wireless Access Protection' },
    description: {
      es: 'Las comunicaciones inalámbricas y de red están protegidas mediante HSTS y nosniff que aseguran que los clientes solo se conectan vía HTTPS, incluso en redes no confiables.',
      en: 'Wireless and network communications are protected through HSTS and nosniff ensuring clients only connect via HTTPS, even on untrusted networks.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'AC: Control de Acceso', en: 'AC: Access Control' },
      clause: 'AC-18',
      official_text: {
        es: 'La organización establece restricciones de uso, requisitos de configuración/conexión y guía de implementación para el acceso inalámbrico.',
        en: 'The organization establishes usage restrictions, configuration/connection requirements, and implementation guidance for wireless access.',
      },
      applicability_note: {
        es: 'En Cloudflare: HSTS instruye a los navegadores para siempre usar HTTPS, protegiendo el acceso desde redes inalámbricas no seguras. El header nosniff previene ataques de MIME sniffing en redes no confiables.',
        en: 'In Cloudflare: HSTS instructs browsers to always use HTTPS, protecting access from unsecured wireless networks. The nosniff header prevents MIME sniffing attacks on untrusted networks.',
      },
      source_url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'nist_csf', control_id: 'NIST-CSF-PR.DS-2', clause: 'PR.DS-2' },
      { framework: 'infra_baseline', control_id: 'INFRA-HDR-001', clause: 'HDR-001' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar HSTS con nosniff para proteger acceso inalámbrico', en: 'Enable HSTS with nosniff to protect wireless access' },
      risk_if_ignored: {
        es: 'Sin HSTS, los usuarios en redes WiFi abiertas pueden ser víctimas de ataques SSL stripping que degradan HTTPS a HTTP.',
        en: 'Without HSTS, users on open WiFi networks can fall victim to SSL stripping attacks that downgrade HTTPS to HTTP.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar HSTS con nosniff', en: 'Enable HSTS with nosniff' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' }, detail: { es: 'Activar HSTS con max-age 12 meses + No-sniff header.', en: 'Enable HSTS with max-age 12 months + No-sniff header.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-header/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      const hstsOk = hsts.enabled && hsts.max_age >= 15768000;
      const nosniff = hsts.nosniff;
      if (hstsOk && nosniff) return ev('pass', 100, `HSTS: ${hsts.max_age}s, nosniff: on`, 'HSTS 6m+ + nosniff', 'Wireless access is protected via HSTS and nosniff headers.', ['zone_settings.security_header']);
      if (hstsOk || nosniff) return ev('partial', 50, `HSTS: ${hsts.enabled ? hsts.max_age + 's' : 'off'}, nosniff: ${nosniff}`, 'HSTS 6m+ + nosniff', `Partial wireless protection: ${hstsOk ? 'HSTS OK' : 'HSTS insufficient'}, ${nosniff ? 'nosniff on' : 'nosniff off'}.`, ['zone_settings.security_header']);
      return ev('fail', 0, 'HSTS: off, nosniff: off', 'HSTS 6m+ + nosniff', 'No wireless access protection configured.', ['zone_settings.security_header']);
    },
  },
];
