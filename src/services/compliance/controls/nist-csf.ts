/**
 * Anga Security — NIST Cybersecurity Framework (CSF) 2.0 Controls
 *
 * SAMPLE: 3 controls for user validation before implementing all 42.
 *
 * Focuses on Protect (PR) and Detect (DE) functions applicable to
 * Cloudflare CDN/WAF infrastructure.
 *
 * The NIST CSF is a public domain framework by the National Institute of
 * Standards and Technology. This assessment covers ONLY infrastructure-level
 * controls evaluable via Cloudflare API within the Protect and Detect functions.
 * Full CSF compliance requires assessment of all 6 functions (Govern, Identify,
 * Protect, Detect, Respond, Recover) across your entire organization.
 */

import type { FrameworkControl } from '../../../types/compliance';
import { s, ev, enrichedOrPerm, getHsts, hasManagedWaf, hasOwaspRules, getRateLimitRules, getCustomWafRules } from './helpers';

export const NIST_CSF_CONTROLS: FrameworkControl[] = [
  // ================================================================
  // PR.DS — Protect: Data Security
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.DS-2',
    control_ref: 'PR.DS-2',
    framework: 'nist_csf',
    section_id: 'pr_ds',
    title: {
      es: 'PR.DS-2: Datos en Tránsito Protegidos',
      en: 'PR.DS-2: Data-in-Transit Protected',
    },
    description: {
      es: 'Los datos en tránsito están protegidos mediante cifrado TLS fuerte verificado, HSTS habilitado y modo SSL estricto que valida certificados de origen',
      en: 'Data in transit is protected using verified strong TLS encryption, HSTS enabled, and strict SSL mode that validates origin certificates',
    },
    severity: 'critical',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'PR: Proteger — DS: Seguridad de Datos',
        en: 'PR: Protect — DS: Data Security',
      },
      clause: 'PR.DS-2',
      official_text: {
        es: 'Los datos en tránsito están protegidos. La organización implementa mecanismos de protección para datos mientras se transmiten entre sistemas o redes.',
        en: 'Data-in-transit is protected. The organization implements protection mechanisms for data while it is being transmitted between systems or networks.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se evalúa el modo SSL (debe ser Full Strict para cifrado verificado de extremo a extremo), versión mínima TLS (debe ser 1.2+), y HSTS (debe estar habilitado para forzar HTTPS en navegadores).',
        en: 'In Cloudflare: Evaluates SSL mode (must be Full Strict for verified end-to-end encryption), minimum TLS version (must be 1.2+), and HSTS (must be enabled to force HTTPS in browsers).',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.24', clause: 'A.8.24' },
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
      { framework: 'infra_baseline', control_id: 'INFRA-TLS-002', clause: 'TLS-002' },
    ],
    remediation_template: {
      summary: {
        es: 'Configurar SSL en Full (Strict), establecer TLS mínimo en 1.2 y habilitar HSTS para protección completa de datos en tránsito',
        en: 'Set SSL to Full (Strict), establish minimum TLS at 1.2, and enable HSTS for complete data-in-transit protection',
      },
      risk_if_ignored: {
        es: 'Datos sensibles pueden ser interceptados en tránsito si el cifrado no es fuerte o verificado. Ataques man-in-the-middle, downgrade de protocolo y stripping de HTTPS son posibles.',
        en: 'Sensitive data can be intercepted in transit if encryption is not strong or verified. Man-in-the-middle attacks, protocol downgrades, and HTTPS stripping are possible.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Configurar SSL en Full (Strict)', en: 'Set SSL to Full (Strict)' },
          where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' },
          detail: {
            es: 'Selecciona "Completo (estricto)" como modo de encriptación. Este modo cifra todo el tráfico entre visitante-Cloudflare y Cloudflare-origen, validando el certificado del servidor de origen.',
            en: 'Select "Full (strict)" as encryption mode. This mode encrypts all traffic between visitor-Cloudflare and Cloudflare-origin, validating the origin server certificate.',
          },
        },
        {
          order: 2,
          action: { es: 'Establecer TLS mínimo en 1.2', en: 'Set minimum TLS to 1.2' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' },
          detail: {
            es: 'En "Versión mínima de TLS", selecciona "1.2". TLS 1.0 y 1.1 están deprecados y tienen vulnerabilidades conocidas (BEAST, POODLE).',
            en: 'Under "Minimum TLS Version", select "1.2". TLS 1.0 and 1.1 are deprecated and have known vulnerabilities (BEAST, POODLE).',
          },
        },
        {
          order: 3,
          action: { es: 'Habilitar HSTS', en: 'Enable HSTS' },
          where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' },
          detail: {
            es: 'Haz clic en "Habilitar HSTS". Configura: Max-Age = 12 meses (31536000s), incluir subdominios = sí. HSTS indica a los navegadores que siempre usen HTTPS, previniendo ataques de stripping SSL.',
            en: 'Click "Enable HSTS". Configure: Max-Age = 12 months (31536000s), include subdomains = yes. HSTS tells browsers to always use HTTPS, preventing SSL stripping attacks.',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const minTls = s(ctx, 'min_tls_version');
      const hsts = getHsts(ctx);

      const isSslStrict = ssl === 'strict' || ssl === 'full_strict';
      const isMinTlsOk = minTls === '1.2' || minTls === '1.3';
      const isHstsOk = hsts.enabled && hsts.max_age >= 15768000;

      const checks = [isSslStrict, isMinTlsOk, isHstsOk];
      const passed = checks.filter(Boolean).length;

      if (passed === 3) {
        return ev(
          'pass', 100,
          `SSL: ${ssl}, Min TLS: ${minTls}, HSTS: on (max-age: ${hsts.max_age})`,
          'SSL Full (Strict) + Min TLS 1.2+ + HSTS enabled',
          'Data-in-transit is fully protected with verified end-to-end encryption.',
          ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
        );
      }
      if (passed >= 1) {
        const missing: string[] = [];
        if (!isSslStrict) missing.push(`SSL mode "${ssl}" not Full (Strict)`);
        if (!isMinTlsOk) missing.push(`Min TLS ${minTls} below 1.2`);
        if (!isHstsOk) missing.push('HSTS not adequately configured');
        return ev(
          'partial', Math.round((passed / 3) * 100),
          `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}, HSTS: ${hsts.enabled ? 'on' : 'off'}`,
          'SSL Full (Strict) + Min TLS 1.2+ + HSTS enabled',
          `${passed}/3 data-in-transit protections active. Missing: ${missing.join('; ')}.`,
          ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
        );
      }
      return ev(
        'fail', 0,
        `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}, HSTS: off`,
        'SSL Full (Strict) + Min TLS 1.2+ + HSTS enabled',
        'Data-in-transit is not adequately protected. Critical encryption configurations are missing.',
        ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.security_header'],
      );
    },
  },

  // ================================================================
  // PR.AC — Protect: Access Control (Network Integrity)
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.AC-5',
    control_ref: 'PR.AC-5',
    framework: 'nist_csf',
    section_id: 'pr_ac',
    title: {
      es: 'PR.AC-5: Integridad de Red Protegida',
      en: 'PR.AC-5: Network Integrity Protected',
    },
    description: {
      es: 'La integridad de la red está protegida mediante DNSSEC habilitado para prevenir suplantación DNS y registros CAA configurados para controlar emisión de certificados',
      en: 'Network integrity is protected through DNSSEC enabled to prevent DNS spoofing and CAA records configured to control certificate issuance',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'PR: Proteger — AC: Control de Acceso',
        en: 'PR: Protect — AC: Access Control',
      },
      clause: 'PR.AC-5',
      official_text: {
        es: 'La integridad de la red está protegida (por ejemplo, segregación de red, segmentación de red). Las comunicaciones de red son monitoreadas, controladas y protegidas.',
        en: 'Network integrity is protected (e.g., network segregation, network segmentation). Network communications are monitored, controlled, and protected.',
      },
      applicability_note: {
        es: 'En Cloudflare: Se evalúa DNSSEC (protege integridad de resoluciones DNS contra ataques de envenenamiento de caché) y registros CAA (controlan qué autoridades certificadoras pueden emitir certificados para el dominio).',
        en: 'In Cloudflare: Evaluates DNSSEC (protects DNS resolution integrity against cache poisoning attacks) and CAA records (control which certificate authorities can issue certificates for the domain).',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['dns_summary', 'dns_records'],
    required_permissions: ['DNS:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-1.3.1', clause: '1.3.1' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.22', clause: 'A.8.22' },
      { framework: 'infra_baseline', control_id: 'INFRA-DNS-001', clause: 'DNS-001' },
    ],
    remediation_template: {
      summary: {
        es: 'Habilitar DNSSEC para proteger la integridad DNS y añadir registros CAA para controlar la emisión de certificados',
        en: 'Enable DNSSEC to protect DNS integrity and add CAA records to control certificate issuance',
      },
      risk_if_ignored: {
        es: 'Sin DNSSEC, atacantes pueden redirigir tráfico mediante envenenamiento de caché DNS. Sin registros CAA, cualquier autoridad certificadora puede emitir certificados para tu dominio.',
        en: 'Without DNSSEC, attackers can redirect traffic through DNS cache poisoning. Without CAA records, any certificate authority can issue certificates for your domain.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar DNSSEC', en: 'Enable DNSSEC' },
          where: { es: 'Dashboard > DNS > Configuración', en: 'Dashboard > DNS > Settings' },
          detail: {
            es: 'Haz clic en "Habilitar DNSSEC". Cloudflare generará los registros DS necesarios. Copia el registro DS y agrégalo en tu registrador de dominio. La propagación toma 1-2 días.',
            en: 'Click "Enable DNSSEC". Cloudflare will generate the necessary DS records. Copy the DS record and add it at your domain registrar. Propagation takes 1-2 days.',
          },
        },
        {
          order: 2,
          action: { es: 'Agregar registro DS en el registrador', en: 'Add DS record at registrar' },
          where: { es: 'Panel del registrador de dominio', en: 'Domain registrar panel' },
          detail: {
            es: 'En tu registrador (GoDaddy, Namecheap, etc.), busca la sección DNSSEC y pega los valores del registro DS proporcionados por Cloudflare (Tag, Algorithm, Digest Type, Digest).',
            en: 'In your registrar (GoDaddy, Namecheap, etc.), find the DNSSEC section and paste the DS record values provided by Cloudflare (Tag, Algorithm, Digest Type, Digest).',
          },
        },
        {
          order: 3,
          action: { es: 'Añadir registros CAA', en: 'Add CAA records' },
          where: { es: 'Dashboard > DNS > Registros', en: 'Dashboard > DNS > Records' },
          detail: {
            es: 'Crea registros DNS tipo CAA. Ejemplo: 0 issue "letsencrypt.org" y 0 issue "digicert.com" para permitir solo esas CAs. Añade 0 iodef "mailto:security@tudominio.com" para notificaciones de violaciones.',
            en: 'Create CAA type DNS records. Example: 0 issue "letsencrypt.org" and 0 issue "digicert.com" to allow only those CAs. Add 0 iodef "mailto:security@yourdomain.com" for violation notifications.',
          },
        },
        {
          order: 4,
          action: { es: 'Verificar DNSSEC activo', en: 'Verify DNSSEC active' },
          where: { es: 'Dashboard > DNS > Configuración', en: 'Dashboard > DNS > Settings' },
          detail: {
            es: 'Después de 24-48 horas, verifica que DNSSEC muestre estado "Active". También puedes verificar con: https://dnssec-analyzer.verisignlabs.com/',
            en: 'After 24-48 hours, verify DNSSEC shows "Active" status. You can also verify at: https://dnssec-analyzer.verisignlabs.com/',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/dns/dnssec/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const dnsRecords = ctx.audit_data.dns_records || [];
      const caaRecords = dnsRecords.filter((r: any) => r.type === 'CAA');
      const hasCaa = caaRecords.length > 0;

      if (dnssec && hasCaa) {
        return ev(
          'pass', 100,
          `DNSSEC: active, CAA records: ${caaRecords.length}`,
          'DNSSEC active + CAA records configured',
          'Network integrity is fully protected with DNSSEC and CAA certificate controls.',
          ['dns_summary', 'dns_records'],
        );
      }
      if (dnssec || hasCaa) {
        const issues: string[] = [];
        if (!dnssec) issues.push('DNSSEC not enabled');
        if (!hasCaa) issues.push('No CAA records to restrict certificate issuance');
        return ev(
          'partial', 50,
          `DNSSEC: ${dnssec ? 'active' : 'inactive'}, CAA records: ${caaRecords.length}`,
          'DNSSEC active + CAA records configured',
          `Partial network integrity protection. ${issues.join('; ')}.`,
          ['dns_summary', 'dns_records'],
        );
      }
      return ev(
        'fail', 0,
        'DNSSEC: inactive, CAA records: 0',
        'DNSSEC active + CAA records configured',
        'No network integrity protections configured. DNS is vulnerable to spoofing and unauthorized certificate issuance.',
        ['dns_summary', 'dns_records'],
      );
    },
  },

  // ================================================================
  // DE.CM — Detect: Continuous Monitoring
  // ================================================================
  {
    control_id: 'NIST-CSF-DE.CM-4',
    control_ref: 'DE.CM-4',
    framework: 'nist_csf',
    section_id: 'de_cm',
    title: {
      es: 'DE.CM-4: Detección de Código Malicioso',
      en: 'DE.CM-4: Malicious Code Detection',
    },
    description: {
      es: 'El código malicioso es detectado mediante WAF activo con reglas administradas y OWASP Core Rule Set desplegado para protección contra inyección SQL, XSS, RFI y otras amenazas OWASP Top 10',
      en: 'Malicious code is detected through active WAF with managed rules and OWASP Core Rule Set deployed for protection against SQL injection, XSS, RFI, and other OWASP Top 10 threats',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'DE: Detectar — CM: Monitoreo Continuo',
        en: 'DE: Detect — CM: Continuous Monitoring',
      },
      clause: 'DE.CM-4',
      official_text: {
        es: 'El código malicioso es detectado. La organización implementa mecanismos para detectar código malicioso en los límites de red y en los hosts internos.',
        en: 'Malicious code is detected. The organization implements mechanisms to detect malicious code at network boundaries and on internal hosts.',
      },
      applicability_note: {
        es: 'En Cloudflare: El WAF con reglas administradas detecta código malicioso en peticiones HTTP (SQLi, XSS, LFI, RFI, command injection). El OWASP Core Rule Set proporciona cobertura adicional con sistema de puntuación de anomalías.',
        en: 'In Cloudflare: The WAF with managed rules detects malicious code in HTTP requests (SQLi, XSS, LFI, RFI, command injection). The OWASP Core Rule Set provides additional coverage with anomaly scoring system.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.1', clause: '6.4.1' },
      { framework: 'pci_dss_4', control_id: 'PCI-6.4.2', clause: '6.4.2' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.25', clause: 'A.8.25' },
      { framework: 'soc2_type2', control_id: 'SOC2-CC6.8', clause: 'CC6.8' },
      { framework: 'infra_baseline', control_id: 'INFRA-WAF-002', clause: 'WAF-002' },
    ],
    remediation_template: {
      summary: {
        es: 'Desplegar reglas WAF administradas de Cloudflare y activar el OWASP Core Rule Set para detección de código malicioso',
        en: 'Deploy Cloudflare managed WAF rules and activate the OWASP Core Rule Set for malicious code detection',
      },
      risk_if_ignored: {
        es: 'Sin WAF activo, todas las solicitudes HTTP llegan directamente a la aplicación sin inspección. Ataques de inyección SQL, XSS y otras vulnerabilidades OWASP Top 10 no serán detectados ni bloqueados.',
        en: 'Without active WAF, all HTTP requests reach the application directly without inspection. SQL injection, XSS, and other OWASP Top 10 vulnerability attacks will not be detected or blocked.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Desplegar reglas administradas de Cloudflare', en: 'Deploy Cloudflare managed rules' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' },
          detail: {
            es: 'Haz clic en "Deploy" junto a "Cloudflare Managed Ruleset". Este conjunto incluye reglas para vulnerabilidades conocidas, zero-days y patrones de ataque comunes. Las reglas se actualizan automáticamente.',
            en: 'Click "Deploy" next to "Cloudflare Managed Ruleset". This set includes rules for known vulnerabilities, zero-days, and common attack patterns. Rules are updated automatically.',
          },
        },
        {
          order: 2,
          action: { es: 'Activar OWASP Core Rule Set', en: 'Activate OWASP Core Rule Set' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' },
          detail: {
            es: 'Haz clic en "Deploy" junto a "Cloudflare OWASP Core Ruleset". Configura el nivel de paranoia en PL2 (recomendado para producción). Establece la sensibilidad del score en "Medium" (umbral 40+). PL1 es mínimo, PL3-PL4 pueden generar falsos positivos.',
            en: 'Click "Deploy" next to "Cloudflare OWASP Core Ruleset". Set paranoia level to PL2 (recommended for production). Set score sensitivity to "Medium" (threshold 40+). PL1 is minimum, PL3-PL4 may generate false positives.',
          },
        },
        {
          order: 3,
          action: { es: 'Configurar acción predeterminada', en: 'Configure default action' },
          where: { es: 'Dashboard > Seguridad > WAF > Reglas administradas', en: 'Dashboard > Security > WAF > Managed rules' },
          detail: {
            es: 'Revisa la configuración de cada ruleset. Para el OWASP ruleset: Low score = Log, Medium = Managed Challenge, High = Block. Esto permite detectar sin bloquear amenazas de baja confianza.',
            en: 'Review configuration for each ruleset. For OWASP ruleset: Low score = Log, Medium = Managed Challenge, High = Block. This allows detecting without blocking low-confidence threats.',
          },
        },
        {
          order: 4,
          action: { es: 'Monitorear durante 48 horas', en: 'Monitor for 48 hours' },
          where: { es: 'Dashboard > Seguridad > Eventos', en: 'Dashboard > Security > Events' },
          detail: {
            es: 'Después de activar, monitorea los eventos de seguridad durante 48 horas. Revisa cualquier falso positivo y crea excepciones (WAF exceptions) si es necesario antes de pasar a modo block completo.',
            en: 'After activation, monitor security events for 48 hours. Review any false positives and create exceptions (WAF exceptions) if needed before switching to full block mode.',
          },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/managed-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const waf = hasManagedWaf(ctx);
      const owasp = hasOwaspRules(ctx);

      if (waf && owasp) {
        return ev(
          'pass', 100,
          'Managed WAF: active, OWASP CRS: deployed',
          'Managed WAF + OWASP Core Rule Set active',
          'Malicious code detection is fully configured with managed rules and OWASP coverage.',
          ['rulesets'],
        );
      }
      if (waf) {
        return ev(
          'partial', 60,
          'Managed WAF: active, OWASP CRS: not detected',
          'Managed WAF + OWASP Core Rule Set active',
          'Managed WAF is active but OWASP Core Rule Set was not detected. Deploy OWASP ruleset for comprehensive malicious code detection.',
          ['rulesets'],
        );
      }
      if (owasp) {
        return ev(
          'partial', 50,
          'Managed WAF: inactive, OWASP CRS: detected',
          'Managed WAF + OWASP Core Rule Set active',
          'OWASP rules detected but base managed ruleset not active. Deploy Cloudflare Managed Ruleset.',
          ['rulesets'],
        );
      }
      return ev(
        'fail', 0,
        'Managed WAF: inactive, OWASP CRS: not deployed',
        'Managed WAF + OWASP Core Rule Set active',
        'No malicious code detection is configured. Web application is exposed to OWASP Top 10 attacks.',
        ['rulesets'],
      );
    },
  },

  // ================================================================
  // ID.AM — Identify: Asset Management
  // ================================================================
  {
    control_id: 'NIST-CSF-ID.AM-1',
    control_ref: 'ID.AM-1',
    framework: 'nist_csf',
    section_id: 'id_am',
    title: {
      es: 'ID.AM-1: Inventario de Activos de Hardware',
      en: 'ID.AM-1: Physical Device and System Inventory',
    },
    description: {
      es: 'Los activos digitales (dominio, zona DNS, certificados) están inventariados y gestionados activamente en la plataforma Cloudflare',
      en: 'Digital assets (domain, DNS zone, certificates) are inventoried and actively managed in the Cloudflare platform',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'ID: Identificar — AM: Gestión de Activos', en: 'ID: Identify — AM: Asset Management' },
      clause: 'ID.AM-1',
      official_text: {
        es: 'Los dispositivos físicos y sistemas dentro de la organización están inventariados.',
        en: 'Physical devices and systems within the organization are inventoried.',
      },
      applicability_note: {
        es: 'En Cloudflare: La zona DNS activa con registros correctamente configurados representa el inventario de activos de infraestructura digital.',
        en: 'In Cloudflare: An active DNS zone with correctly configured records represents the inventory of digital infrastructure assets.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['dns_summary', 'dns_records'],
    required_permissions: ['DNS:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.9', clause: 'A.8.9' },
      { framework: 'infra_baseline', control_id: 'INFRA-DNS-001', clause: 'DNS-001' },
    ],
    remediation_template: {
      summary: { es: 'Mantener inventario DNS completo y DNSSEC activo', en: 'Maintain complete DNS inventory and active DNSSEC' },
      risk_if_ignored: {
        es: 'Sin inventario de activos, es imposible identificar activos no autorizados o vulnerables.',
        en: 'Without asset inventory, it is impossible to identify unauthorized or vulnerable assets.',
      },
      steps: [
        { order: 1, action: { es: 'Revisar registros DNS', en: 'Review DNS records' }, where: { es: 'Dashboard > DNS > Registros', en: 'Dashboard > DNS > Records' }, detail: { es: 'Auditar todos los registros DNS y eliminar los obsoletos.', en: 'Audit all DNS records and remove obsolete ones.' } },
        { order: 2, action: { es: 'Activar DNSSEC', en: 'Enable DNSSEC' }, where: { es: 'Dashboard > DNS > Configuración', en: 'Dashboard > DNS > Settings' }, detail: { es: 'Habilitar DNSSEC para asegurar la integridad del inventario DNS.', en: 'Enable DNSSEC to ensure DNS inventory integrity.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/dns/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const dnsRecords = ctx.audit_data.dns_records || [];
      const dnssec = ctx.audit_data.dns_summary?.dnssec_enabled === true;
      const hasRecords = dnsRecords.length > 0;
      if (hasRecords && dnssec) return ev('pass', 100, `DNS records: ${dnsRecords.length}, DNSSEC: active`, 'DNS records present + DNSSEC active', 'Asset inventory is maintained with active DNS records and DNSSEC protection.', ['dns_summary', 'dns_records']);
      if (hasRecords) return ev('partial', 60, `DNS records: ${dnsRecords.length}, DNSSEC: inactive`, 'DNS records present + DNSSEC active', 'DNS asset inventory exists but DNSSEC is not active — integrity not guaranteed.', ['dns_summary', 'dns_records']);
      return ev('fail', 0, 'no DNS records found', 'DNS records present', 'No DNS records found — asset inventory is incomplete.', ['dns_summary', 'dns_records']);
    },
  },

  // ================================================================
  // GV.OC — Govern: Organizational Context
  // ================================================================
  {
    control_id: 'NIST-CSF-GV.OC-1',
    control_ref: 'GV.OC-1',
    framework: 'nist_csf',
    section_id: 'gv_oc',
    title: {
      es: 'GV.OC-1: Misión y Contexto Organizacional',
      en: 'GV.OC-1: Organizational Mission and Context',
    },
    description: {
      es: 'La misión organizacional de ciberseguridad se refleja en configuraciones de seguridad base: nivel de seguridad definido y modo SSL establecido',
      en: 'The organizational cybersecurity mission is reflected in baseline security configurations: defined security level and established SSL mode',
    },
    severity: 'low',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'GV: Gobernar — OC: Contexto Organizacional', en: 'GV: Govern — OC: Organizational Context' },
      clause: 'GV.OC-1',
      official_text: {
        es: 'La misión organizacional es entendida y sirve de base para las prioridades, restricciones y decisiones de gestión de riesgos de ciberseguridad.',
        en: 'The organizational mission is understood and informs cybersecurity risk management priorities, constraints, and decisions.',
      },
      applicability_note: {
        es: 'En Cloudflare: Un nivel de seguridad definido (no "off") y modo SSL configurado indican una política de seguridad establecida y consciente.',
        en: 'In Cloudflare: A defined security level (not "off") and configured SSL mode indicate an established and intentional security policy.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.security_level', 'zone_settings.ssl'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'iso_27001', control_id: 'ISO-A.8.9', clause: 'A.8.9' },
    ],
    remediation_template: {
      summary: { es: 'Establecer nivel de seguridad y modo SSL como política base', en: 'Establish security level and SSL mode as baseline policy' },
      risk_if_ignored: {
        es: 'Sin una política de seguridad base definida, las decisiones de configuración son ad-hoc y no alineadas a objetivos organizacionales.',
        en: 'Without a defined baseline security policy, configuration decisions are ad-hoc and not aligned to organizational objectives.',
      },
      steps: [
        { order: 1, action: { es: 'Establecer nivel de seguridad', en: 'Set security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer en Medium como mínimo.', en: 'Set to Medium as minimum.' } },
        { order: 2, action: { es: 'Configurar modo SSL', en: 'Configure SSL mode' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Configurar Full (Strict) para máxima seguridad.', en: 'Set Full (Strict) for maximum security.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/reference/policies-compliances/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const secLevel = s(ctx, 'security_level');
      const ssl = s(ctx, 'ssl');
      const hasPolicy = secLevel && secLevel !== 'off';
      const hasSsl = ssl && ssl !== 'off';
      if (hasPolicy && hasSsl) return ev('pass', 100, `security level: ${secLevel}, SSL: ${ssl}`, 'security level set + SSL configured', 'Baseline security policy is established with security level and SSL mode defined.', ['zone_settings']);
      if (hasPolicy || hasSsl) return ev('partial', 50, `security level: ${secLevel || 'off'}, SSL: ${ssl || 'off'}`, 'security level set + SSL configured', 'Partial baseline: one of security level or SSL mode is not configured.', ['zone_settings']);
      return ev('fail', 0, 'security level: off, SSL: off', 'security level set + SSL configured', 'No baseline security policy established.', ['zone_settings']);
    },
  },

  // ================================================================
  // PR.DS-1 — Protect: Data Security — Data at Rest
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.DS-1',
    control_ref: 'PR.DS-1',
    framework: 'nist_csf',
    section_id: 'pr_ds',
    title: {
      es: 'PR.DS-1: Datos en Reposo Protegidos',
      en: 'PR.DS-1: Data-at-Rest Protected',
    },
    description: {
      es: 'Los datos en reposo están protegidos mediante headers de seguridad que previenen el almacenamiento incorrecto en caché del navegador y la exposición de tipos MIME',
      en: 'Data at rest is protected through security headers that prevent incorrect browser caching and MIME type exposure',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PR: Proteger — DS: Seguridad de Datos', en: 'PR: Protect — DS: Data Security' },
      clause: 'PR.DS-1',
      official_text: {
        es: 'Los datos en reposo están protegidos. La organización implementa mecanismos de protección para datos almacenados.',
        en: 'Data-at-rest is protected. The organization implements protection mechanisms for stored data.',
      },
      applicability_note: {
        es: 'En Cloudflare: El header X-Content-Type-Options (nosniff) previene que los navegadores interpreten incorrectamente tipos MIME, protegiendo datos almacenados en caché del cliente.',
        en: 'In Cloudflare: The X-Content-Type-Options (nosniff) header prevents browsers from misinterpreting MIME types, protecting data cached in the client.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.security_header'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'gdpr', control_id: 'GDPR-32.1.a', clause: 'Art. 32(1)(a)' },
      { framework: 'infra_baseline', control_id: 'INFRA-HDR-002', clause: 'HDR-002' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-28', clause: 'SC-28' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar nosniff header para proteger datos en reposo', en: 'Enable nosniff header to protect data at rest' },
      risk_if_ignored: {
        es: 'Sin nosniff, los navegadores pueden ejecutar archivos como scripts maliciosos interpretando incorrectamente el tipo de contenido.',
        en: 'Without nosniff, browsers may execute files as malicious scripts by misinterpreting content type.',
      },
      steps: [
        { order: 1, action: { es: 'Activar "No-sniff header"', en: 'Enable "No-sniff header"' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' }, detail: { es: 'En la sección HSTS, activar la opción "No-sniff header".', en: 'In the HSTS section, enable the "No-sniff header" option.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-header/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      if (hsts.nosniff) return ev('pass', 100, 'nosniff: enabled', 'nosniff enabled', 'Data-at-rest protection via X-Content-Type-Options nosniff is active.', ['zone_settings.security_header']);
      return ev('fail', 0, 'nosniff: disabled', 'nosniff enabled', 'X-Content-Type-Options nosniff is not enabled — browser MIME sniffing attacks possible.', ['zone_settings.security_header']);
    },
  },

  // ================================================================
  // PR.DS-6 — Protect: Data Security — Data Integrity
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.DS-6',
    control_ref: 'PR.DS-6',
    framework: 'nist_csf',
    section_id: 'pr_ds',
    title: {
      es: 'PR.DS-6: Mecanismos de Verificación de Integridad',
      en: 'PR.DS-6: Integrity Checking Mechanisms',
    },
    description: {
      es: 'Se utilizan mecanismos de verificación de integridad de datos mediante HSTS y forzado HTTPS para asegurar que los datos no son modificados en tránsito',
      en: 'Data integrity checking mechanisms are used through HSTS and HTTPS enforcement to ensure data is not modified in transit',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PR: Proteger — DS: Seguridad de Datos', en: 'PR: Protect — DS: Data Security' },
      clause: 'PR.DS-6',
      official_text: {
        es: 'Se utilizan mecanismos de verificación de integridad para verificar software, firmware e información.',
        en: 'Integrity checking mechanisms are used to verify software, firmware, and information.',
      },
      applicability_note: {
        es: 'En Cloudflare: HSTS con max-age adecuado y Always Use HTTPS aseguran que las comunicaciones no son degradadas, garantizando la integridad de los datos transmitidos.',
        en: 'In Cloudflare: HSTS with adequate max-age and Always Use HTTPS ensure communications are not downgraded, guaranteeing the integrity of transmitted data.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.security_header', 'zone_settings.always_use_https'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-8', clause: 'SC-8' },
      { framework: 'pci_dss_4', control_id: 'PCI-4.2.1', clause: '4.2.1' },
      { framework: 'infra_baseline', control_id: 'INFRA-TLS-003', clause: 'TLS-003' },
    ],
    remediation_template: {
      summary: { es: 'Habilitar HSTS y Always Use HTTPS para integridad de datos', en: 'Enable HSTS and Always Use HTTPS for data integrity' },
      risk_if_ignored: {
        es: 'Sin integridad verificada, los datos pueden ser modificados en tránsito mediante ataques MITM sin detección.',
        en: 'Without verified integrity, data can be modified in transit through MITM attacks without detection.',
      },
      steps: [
        { order: 1, action: { es: 'Habilitar HSTS', en: 'Enable HSTS' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge > HSTS', en: 'Dashboard > SSL/TLS > Edge Certificates > HSTS' }, detail: { es: 'Activar HSTS con max-age de al menos 6 meses.', en: 'Enable HSTS with max-age of at least 6 months.' } },
        { order: 2, action: { es: 'Habilitar Always Use HTTPS', en: 'Enable Always Use HTTPS' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar Always Use HTTPS para forzar conexiones seguras.', en: 'Enable Always Use HTTPS to force secure connections.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const hsts = getHsts(ctx);
      const alwaysHttps = s(ctx, 'always_use_https') === 'on';
      const hstsOk = hsts.enabled && hsts.max_age >= 15768000;
      if (hstsOk && alwaysHttps) return ev('pass', 100, `HSTS: ${hsts.max_age}s, Always HTTPS: on`, 'HSTS enabled + Always Use HTTPS on', 'Data integrity mechanisms are active via HSTS and forced HTTPS.', ['zone_settings.security_header', 'zone_settings.always_use_https']);
      if (hstsOk || alwaysHttps) return ev('partial', 50, `HSTS: ${hsts.enabled ? hsts.max_age + 's' : 'off'}, Always HTTPS: ${alwaysHttps}`, 'HSTS enabled + Always Use HTTPS on', `Partial integrity controls: ${hstsOk ? 'HSTS OK' : 'HSTS insufficient'}, ${alwaysHttps ? 'Always HTTPS on' : 'Always HTTPS off'}.`, ['zone_settings.security_header', 'zone_settings.always_use_https']);
      return ev('fail', 0, 'HSTS: off, Always HTTPS: off', 'HSTS enabled + Always Use HTTPS on', 'No data integrity mechanisms configured.', ['zone_settings.security_header', 'zone_settings.always_use_https']);
    },
  },

  // ================================================================
  // PR.IP-1 — Protect: Information Protection — Baseline Config
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.IP-1',
    control_ref: 'PR.IP-1',
    framework: 'nist_csf',
    section_id: 'pr_ip',
    title: {
      es: 'PR.IP-1: Configuración Baseline de Seguridad',
      en: 'PR.IP-1: Baseline Security Configuration',
    },
    description: {
      es: 'Se establece y mantiene una configuración baseline para los sistemas de información: SSL estricto, TLS mínimo 1.2 y siempre HTTPS',
      en: 'A baseline configuration is established and maintained for information systems: strict SSL, minimum TLS 1.2, and always HTTPS',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PR: Proteger — IP: Procesos y Procedimientos de Protección', en: 'PR: Protect — IP: Information Protection Processes' },
      clause: 'PR.IP-1',
      official_text: {
        es: 'Se crea y mantiene una configuración de referencia de la tecnología de la información/control de sistemas de tecnología operacional.',
        en: 'A baseline configuration of information technology/industrial control systems is created and maintained.',
      },
      applicability_note: {
        es: 'En Cloudflare: La combinación de SSL Full (Strict), TLS mínimo 1.2 y Always Use HTTPS constituye la configuración baseline de seguridad de la infraestructura.',
        en: 'In Cloudflare: The combination of SSL Full (Strict), minimum TLS 1.2, and Always Use HTTPS constitutes the baseline security configuration of the infrastructure.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.ssl', 'zone_settings.min_tls_version', 'zone_settings.always_use_https'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CM-6', clause: 'CM-6' },
      { framework: 'infra_baseline', control_id: 'INFRA-TLS-001', clause: 'TLS-001' },
    ],
    remediation_template: {
      summary: { es: 'Establecer SSL Full Strict + TLS 1.2+ + Always HTTPS como baseline', en: 'Establish SSL Full Strict + TLS 1.2+ + Always HTTPS as baseline' },
      risk_if_ignored: {
        es: 'Sin configuración baseline, la postura de seguridad es inconsistente y vulnerable a configuraciones erróneas.',
        en: 'Without baseline configuration, the security posture is inconsistent and vulnerable to misconfigurations.',
      },
      steps: [
        { order: 1, action: { es: 'Establecer SSL Full (Strict)', en: 'Set SSL Full (Strict)' }, where: { es: 'Dashboard > SSL/TLS > Vista general', en: 'Dashboard > SSL/TLS > Overview' }, detail: { es: 'Seleccionar Full (Strict).', en: 'Select Full (Strict).' } },
        { order: 2, action: { es: 'Establecer TLS mínimo 1.2', en: 'Set minimum TLS 1.2' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Seleccionar TLS 1.2 como versión mínima.', en: 'Select TLS 1.2 as minimum version.' } },
        { order: 3, action: { es: 'Activar Always Use HTTPS', en: 'Enable Always Use HTTPS' }, where: { es: 'Dashboard > SSL/TLS > Certificados Edge', en: 'Dashboard > SSL/TLS > Edge Certificates' }, detail: { es: 'Activar Always Use HTTPS.', en: 'Enable Always Use HTTPS.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ssl/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const ssl = s(ctx, 'ssl');
      const minTls = s(ctx, 'min_tls_version');
      const alwaysHttps = s(ctx, 'always_use_https');
      const isSslStrict = ssl === 'strict' || ssl === 'full_strict';
      const isMinTlsOk = minTls === '1.2' || minTls === '1.3';
      const isAlwaysHttps = alwaysHttps === 'on';
      const checks = [isSslStrict, isMinTlsOk, isAlwaysHttps];
      const passed = checks.filter(Boolean).length;
      if (passed === 3) return ev('pass', 100, `SSL: ${ssl}, Min TLS: ${minTls}, Always HTTPS: on`, 'SSL Strict + TLS 1.2+ + Always HTTPS', 'Baseline security configuration is fully established.', ['zone_settings']);
      if (passed >= 1) return ev('partial', Math.round((passed / 3) * 100), `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}, Always HTTPS: ${alwaysHttps || 'off'}`, 'SSL Strict + TLS 1.2+ + Always HTTPS', `${passed}/3 baseline controls active.`, ['zone_settings']);
      return ev('fail', 0, `SSL: ${ssl || 'unknown'}, Min TLS: ${minTls || 'unknown'}, Always HTTPS: off`, 'SSL Strict + TLS 1.2+ + Always HTTPS', 'Baseline security configuration is not established.', ['zone_settings']);
    },
  },

  // ================================================================
  // PR.IP-3 — Protect: Information Protection — Config Change Control
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.IP-3',
    control_ref: 'PR.IP-3',
    framework: 'nist_csf',
    section_id: 'pr_ip',
    title: {
      es: 'PR.IP-3: Procesos de Control de Cambios de Configuración',
      en: 'PR.IP-3: Configuration Change Control Processes',
    },
    description: {
      es: 'Los procesos de control de cambios están establecidos mediante reglas WAF personalizadas que representan decisiones de seguridad deliberadas y documentadas',
      en: 'Configuration change control processes are established through custom WAF rules that represent deliberate and documented security decisions',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PR: Proteger — IP: Procesos y Procedimientos de Protección', en: 'PR: Protect — IP: Information Protection Processes' },
      clause: 'PR.IP-3',
      official_text: {
        es: 'Los procesos de control de cambios de configuración están establecidos.',
        en: 'Configuration change control processes are in place.',
      },
      applicability_note: {
        es: 'En Cloudflare: Las reglas WAF personalizadas representan decisiones de seguridad intencionales y controladas, evidenciando un proceso de gestión de cambios activo.',
        en: 'In Cloudflare: Custom WAF rules represent intentional and controlled security decisions, evidencing an active change management process.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['rulesets'],
    required_permissions: ['Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CM-6', clause: 'CM-6' },
      { framework: 'iso_27001', control_id: 'ISO-A.8.9', clause: 'A.8.9' },
    ],
    remediation_template: {
      summary: { es: 'Crear reglas WAF personalizadas como evidencia de control de cambios', en: 'Create custom WAF rules as evidence of change control' },
      risk_if_ignored: {
        es: 'Sin control de cambios, las modificaciones de seguridad pueden ser no autorizadas o no documentadas.',
        en: 'Without change control, security modifications may be unauthorized or undocumented.',
      },
      steps: [
        { order: 1, action: { es: 'Crear reglas WAF personalizadas', en: 'Create custom WAF rules' }, where: { es: 'Dashboard > Seguridad > WAF > Reglas personalizadas', en: 'Dashboard > Security > WAF > Custom rules' }, detail: { es: 'Documentar y crear reglas de seguridad específicas para el negocio.', en: 'Document and create business-specific security rules.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/custom-rules/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const customRules = getCustomWafRules(ctx);
      const active = customRules.filter((r: any) => r.enabled !== false);
      if (active.length >= 3) return ev('pass', 100, `${active.length} custom WAF rules active`, '3+ custom WAF rules', `${active.length} custom WAF rules evidence an established change control process.`, ['rulesets']);
      if (active.length >= 1) return ev('partial', 50, `${active.length} custom WAF rule(s)`, '3+ custom WAF rules', `Only ${active.length} custom WAF rule(s) found. Consider adding more to demonstrate systematic change control.`, ['rulesets']);
      return ev('fail', 0, 'no custom WAF rules', '3+ custom WAF rules', 'No custom WAF rules found — no evidence of configuration change control process.', ['rulesets']);
    },
  },

  // ================================================================
  // DE.AE-1 — Detect: Anomalies and Events — Baseline Activity
  // ================================================================
  {
    control_id: 'NIST-CSF-DE.AE-1',
    control_ref: 'DE.AE-1',
    framework: 'nist_csf',
    section_id: 'de_ae',
    title: {
      es: 'DE.AE-1: Baseline de Actividad de Red',
      en: 'DE.AE-1: Network Activity Baseline',
    },
    description: {
      es: 'Se establece y gestiona una línea base de la actividad de red mediante el nivel de seguridad Cloudflare que define el comportamiento esperado del tráfico',
      en: 'A baseline of network activity and data flows is established and managed through Cloudflare security level that defines expected traffic behavior',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'DE: Detectar — AE: Anomalías y Eventos', en: 'DE: Detect — AE: Anomalies and Events' },
      clause: 'DE.AE-1',
      official_text: {
        es: 'Se establece y gestiona una línea base de la actividad de red y los flujos de datos para los usuarios y los sistemas.',
        en: 'A baseline of network activity and data flows for users and systems is established and managed.',
      },
      applicability_note: {
        es: 'En Cloudflare: El nivel de seguridad establece un umbral de sensibilidad ante tráfico anómalo, definiendo de facto una baseline de comportamiento de red.',
        en: 'In Cloudflare: The security level establishes a sensitivity threshold for anomalous traffic, de facto defining a baseline of network behavior.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.security_level'],
    required_permissions: ['Zone:Read'],
    cross_references: [
      { framework: 'infra_baseline', control_id: 'INFRA-DDOS-001', clause: 'DDOS-001' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CA-7', clause: 'CA-7' },
    ],
    remediation_template: {
      summary: { es: 'Establecer nivel de seguridad Medium o superior como baseline', en: 'Set security level to Medium or higher as baseline' },
      risk_if_ignored: {
        es: 'Sin una baseline de actividad de red, es imposible identificar desviaciones y anomalías de tráfico.',
        en: 'Without a network activity baseline, it is impossible to identify deviations and traffic anomalies.',
      },
      steps: [
        { order: 1, action: { es: 'Establecer nivel de seguridad', en: 'Set security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Seleccionar Medium como nivel mínimo. High para mayor protección.', en: 'Select Medium as minimum level. High for greater protection.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/waf/tools/security-level/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const secLevel = s(ctx, 'security_level');
      if (['medium', 'high', 'under_attack'].includes(secLevel)) return ev('pass', 100, `security level: ${secLevel}`, 'medium or higher security level', `Network baseline established with security level "${secLevel}".`, ['zone_settings.security_level']);
      if (secLevel === 'low') return ev('partial', 40, `security level: low`, 'medium or higher security level', 'Security level is "low" — baseline sensitivity is insufficient for proper anomaly detection.', ['zone_settings.security_level']);
      return ev('fail', 0, `security level: ${secLevel || 'off'}`, 'medium or higher security level', 'Security level is off or not configured — no network activity baseline established.', ['zone_settings.security_level']);
    },
  },

  // ================================================================
  // DE.AE-3 — Detect: Anomalies and Events — Event Data Aggregation
  // ================================================================
  {
    control_id: 'NIST-CSF-DE.AE-3',
    control_ref: 'DE.AE-3',
    framework: 'nist_csf',
    section_id: 'de_ae',
    title: {
      es: 'DE.AE-3: Agregación de Datos de Eventos de Seguridad',
      en: 'DE.AE-3: Security Event Data Aggregation',
    },
    description: {
      es: 'Los datos de eventos de seguridad son recolectados y correlacionados mediante Logpush que exporta eventos de firewall para análisis centralizado',
      en: 'Security event data is collected and correlated through Logpush that exports firewall events for centralized analysis',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'DE: Detectar — AE: Anomalías y Eventos', en: 'DE: Detect — AE: Anomalies and Events' },
      clause: 'DE.AE-3',
      official_text: {
        es: 'Los datos de eventos son recolectados y correlacionados de múltiples fuentes y sensores.',
        en: 'Event data are collected and correlated from multiple sources and sensors.',
      },
      applicability_note: {
        es: 'En Cloudflare: Logpush configurado para firewall_events y http_requests permite la agregación y correlación de eventos de seguridad en una plataforma SIEM o de análisis.',
        en: 'In Cloudflare: Logpush configured for firewall_events and http_requests enables aggregation and correlation of security events in a SIEM or analytics platform.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['logpush_jobs'],
    required_permissions: ['Logs:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-AU-2', clause: 'AU-2' },
      { framework: 'nist_800_53', control_id: 'NIST-800-53-CA-7', clause: 'CA-7' },
      { framework: 'infra_baseline', control_id: 'INFRA-LOG-001', clause: 'LOG-001' },
    ],
    remediation_template: {
      summary: { es: 'Configurar Logpush para exportar eventos de seguridad', en: 'Configure Logpush to export security events' },
      risk_if_ignored: {
        es: 'Sin agregación de eventos, no es posible detectar patrones de ataque ni correlacionar incidentes.',
        en: 'Without event aggregation, it is not possible to detect attack patterns or correlate incidents.',
      },
      steps: [
        { order: 1, action: { es: 'Crear job Logpush para Firewall Events', en: 'Create Logpush job for Firewall Events' }, where: { es: 'Dashboard > Analytics & Logs > Logpush', en: 'Dashboard > Analytics & Logs > Logpush' }, detail: { es: 'Configurar export de firewall_events a SIEM o almacenamiento.', en: 'Configure firewall_events export to SIEM or storage.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/logs/logpush/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const logpush = ctx.enriched_data?.logpush_jobs;
      if (!logpush) {
        if (!ctx.available_permissions.includes('Logs:Read')) {
          return ev('insufficient_permissions', 0, 'N/A', 'Requires: Logs:Read', 'Token lacks Logs:Read permission — cannot evaluate log aggregation.', ['logpush_jobs']);
        }
        return ev('fail', 0, 'no logpush data', '1+ logpush job with firewall logs', 'No Logpush configuration found.', ['logpush_jobs']);
      }
      const hasFirewallLogs = logpush?.has_firewall_logs === true;
      const hasHttpLogs = logpush?.has_http_logs === true;
      if (hasFirewallLogs && hasHttpLogs) return ev('pass', 100, `Logpush: FW logs + HTTP logs active (${logpush.total} jobs)`, 'firewall + HTTP logpush active', 'Security event data is being aggregated via Logpush.', ['logpush_jobs']);
      if (hasFirewallLogs || hasHttpLogs) return ev('partial', 60, `Logpush: FW: ${hasFirewallLogs}, HTTP: ${hasHttpLogs}`, 'firewall + HTTP logpush active', 'Partial log aggregation — only one log type configured.', ['logpush_jobs']);
      return ev('fail', 0, `Logpush: ${logpush?.total || 0} jobs, no FW/HTTP logs`, 'firewall + HTTP logpush active', 'No security event log export configured.', ['logpush_jobs']);
    },
  },

  // ================================================================
  // RS.CO-2 — Respond: Communications — Incident Reporting
  // ================================================================
  {
    control_id: 'NIST-CSF-RS.CO-2',
    control_ref: 'RS.CO-2',
    framework: 'nist_csf',
    section_id: 'rs_co',
    title: {
      es: 'RS.CO-2: Reporte de Incidentes de Seguridad',
      en: 'RS.CO-2: Security Incident Reporting',
    },
    description: {
      es: 'Los incidentes de seguridad son reportados conforme a criterios establecidos mediante Audit Logs activos que registran cambios de configuración y eventos de seguridad',
      en: 'Security incidents are reported consistent with established criteria through active Audit Logs that record configuration changes and security events',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'RS: Responder — CO: Comunicaciones', en: 'RS: Respond — CO: Communications' },
      clause: 'RS.CO-2',
      official_text: {
        es: 'Los incidentes son reportados conforme a los criterios establecidos.',
        en: 'Incidents are reported consistent with established criteria.',
      },
      applicability_note: {
        es: 'En Cloudflare: Los Audit Logs de cuenta registran todos los cambios de configuración y accesos, sirviendo como base para el reporte de incidentes.',
        en: 'In Cloudflare: Account Audit Logs record all configuration changes and accesses, serving as the basis for incident reporting.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['audit_logs'],
    required_permissions: ['Account Access: Audit Logs'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-AU-2', clause: 'AU-2' },
      { framework: 'gdpr', control_id: 'GDPR-33.1', clause: 'Art. 33(1)' },
    ],
    remediation_template: {
      summary: { es: 'Verificar Audit Logs activos y configurar alertas', en: 'Verify active Audit Logs and configure alerts' },
      risk_if_ignored: {
        es: 'Sin capacidad de reporte de incidentes, los incidentes de seguridad pueden no ser comunicados a tiempo.',
        en: 'Without incident reporting capability, security incidents may not be communicated in a timely manner.',
      },
      steps: [
        { order: 1, action: { es: 'Verificar Audit Logs', en: 'Verify Audit Logs' }, where: { es: 'Dashboard > Gestionar cuenta > Audit Log', en: 'Dashboard > Manage Account > Audit Log' }, detail: { es: 'Confirmar que los eventos de auditoría están siendo registrados.', en: 'Confirm audit events are being recorded.' } },
        { order: 2, action: { es: 'Configurar notificaciones', en: 'Configure notifications' }, where: { es: 'Dashboard > Notificaciones', en: 'Dashboard > Notifications' }, detail: { es: 'Configurar alertas de seguridad y de WAF para notificación inmediata.', en: 'Configure security and WAF alerts for immediate notification.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/fundamentals/account-and-billing/account-security/review-audit-logs/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const auditLogs = ctx.enriched_data?.audit_logs;
      const perm = enrichedOrPerm(ctx, auditLogs, 'Account Access: Audit Logs', ['audit_logs']);
      if (perm) return perm;
      const hasAuditLogs = auditLogs?.available === true && (auditLogs?.recent_count || 0) > 0;
      if (hasAuditLogs) return ev('pass', 100, `Audit Logs: active (${auditLogs.recent_count} events)`, 'Audit Logs active with recent events', 'Security incident reporting infrastructure is active with recent audit events.', ['audit_logs']);
      return ev('fail', 0, 'Audit Logs: inactive or empty', 'Audit Logs active with recent events', 'No recent audit events found — incident reporting capability may be absent.', ['audit_logs']);
    },
  },

  // ================================================================
  // RC.RP-1 — Recover: Recovery Planning
  // ================================================================
  {
    control_id: 'NIST-CSF-RC.RP-1',
    control_ref: 'RC.RP-1',
    framework: 'nist_csf',
    section_id: 'rc_rp',
    title: {
      es: 'RC.RP-1: Plan de Recuperación Ejecutado',
      en: 'RC.RP-1: Recovery Plan Executed',
    },
    description: {
      es: 'El plan de recuperación se ejecuta durante o después de un evento mediante rate limiting y protecciones DDoS que limitan el impacto y permiten la recuperación del servicio',
      en: 'The recovery plan is executed during or after an incident through rate limiting and DDoS protections that limit impact and allow service recovery',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'RC: Recuperar — RP: Planificación de Recuperación', en: 'RC: Recover — RP: Recovery Planning' },
      clause: 'RC.RP-1',
      official_text: {
        es: 'El plan de recuperación se ejecuta durante o después de un evento de ciberseguridad.',
        en: 'The recovery plan is executed during or after a cybersecurity incident.',
      },
      applicability_note: {
        es: 'En Cloudflare: Las reglas de rate limiting y la protección DDoS managed son la primera línea de recuperación automática ante ataques — permiten al sistema mantener disponibilidad durante un incidente.',
        en: 'In Cloudflare: Rate limiting rules and managed DDoS protection are the first line of automatic recovery during attacks — they allow the system to maintain availability during an incident.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['rulesets', 'zone_settings.security_level'],
    required_permissions: ['Zone:Read', 'Firewall Services:Read'],
    cross_references: [
      { framework: 'nist_800_53', control_id: 'NIST-800-53-SC-5', clause: 'SC-5' },
      { framework: 'infra_baseline', control_id: 'INFRA-RATE-001', clause: 'RATE-001' },
      { framework: 'infra_baseline', control_id: 'INFRA-DDOS-002', clause: 'DDOS-002' },
    ],
    remediation_template: {
      summary: { es: 'Configurar rate limiting y activar modo Under Attack cuando sea necesario', en: 'Configure rate limiting and enable Under Attack mode when necessary' },
      risk_if_ignored: {
        es: 'Sin capacidades de recuperación automática, los ataques pueden causar indisponibilidad prolongada del servicio.',
        en: 'Without automatic recovery capabilities, attacks can cause prolonged service unavailability.',
      },
      steps: [
        { order: 1, action: { es: 'Configurar rate limiting', en: 'Configure rate limiting' }, where: { es: 'Dashboard > Seguridad > WAF > Rate limiting', en: 'Dashboard > Security > WAF > Rate limiting' }, detail: { es: 'Configurar límites de velocidad para endpoints críticos.', en: 'Configure rate limits for critical endpoints.' } },
        { order: 2, action: { es: 'Verificar DDoS managed rules', en: 'Verify DDoS managed rules' }, where: { es: 'Dashboard > Seguridad > DDoS', en: 'Dashboard > Security > DDoS' }, detail: { es: 'Confirmar que las reglas DDoS administradas están activas en modo Block.', en: 'Confirm DDoS managed rules are active in Block mode.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/ddos-protection/',
      estimated_effort: 'hours',
      requires_plan_upgrade: false,
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const rlRules = getRateLimitRules(ctx);
      const secLevel = s(ctx, 'security_level');
      const hasRL = rlRules.filter((r: any) => r.enabled !== false).length > 0;
      const hasResiliency = ['medium', 'high', 'under_attack'].includes(secLevel);
      if (hasRL && hasResiliency) return ev('pass', 100, `rate limiting: ${rlRules.length} rules, security level: ${secLevel}`, 'rate limiting + medium+ security level', 'Recovery capabilities are in place via rate limiting and adequate security level.', ['rulesets', 'zone_settings']);
      if (hasRL || hasResiliency) return ev('partial', 50, `rate limiting: ${hasRL}, security level: ${secLevel}`, 'rate limiting + medium+ security level', `Partial recovery controls: ${hasRL ? 'rate limiting active' : 'no rate limiting'}, security level: ${secLevel || 'low'}.`, ['rulesets', 'zone_settings']);
      return ev('fail', 0, 'no rate limiting, low security level', 'rate limiting + medium+ security level', 'No automatic recovery capabilities configured.', ['rulesets', 'zone_settings']);
    },
  },

  // ================================================================
  // PR.AT-1 — Protect: Awareness and Training
  // ================================================================
  {
    control_id: 'NIST-CSF-PR.AT-1',
    control_ref: 'PR.AT-1',
    framework: 'nist_csf',
    section_id: 'pr_at',
    title: {
      es: 'PR.AT-1: Concienciación de Todos los Usuarios',
      en: 'PR.AT-1: All Users Informed and Trained',
    },
    description: {
      es: 'La primera capa de protección del sistema demuestra concienciación de seguridad mediante Bot Fight Mode activo y nivel de seguridad configurado como indicadores de una postura proactiva',
      en: 'The system first line of protection demonstrates security awareness through active Bot Fight Mode and configured security level as indicators of a proactive security posture',
    },
    severity: 'low',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: { es: 'PR: Proteger — AT: Concienciación y Entrenamiento', en: 'PR: Protect — AT: Awareness and Training' },
      clause: 'PR.AT-1',
      official_text: {
        es: 'Todos los usuarios de la organización están informados y entrenados.',
        en: 'All users are informed and trained.',
      },
      applicability_note: {
        es: 'En Cloudflare: El nivel de seguridad y Bot Fight Mode configurados reflejan una postura de seguridad consciente, indicando que los administradores entienden y aplican buenas prácticas de seguridad.',
        en: 'In Cloudflare: Configured security level and Bot Fight Mode reflect a conscious security posture, indicating that administrators understand and apply security best practices.',
      },
      source_url: 'https://www.nist.gov/cyberframework',
    },
    required_data_sources: ['zone_settings.security_level', 'zone_settings.bot_fight_mode'],
    required_permissions: ['Zone:Read'],
    cross_references: [],
    remediation_template: {
      summary: { es: 'Activar Bot Fight Mode y establecer nivel de seguridad como indicadores de concienciación', en: 'Enable Bot Fight Mode and set security level as awareness indicators' },
      risk_if_ignored: {
        es: 'Sin configuraciones de seguridad básicas activas, se evidencia falta de concienciación de seguridad en la administración del sistema.',
        en: 'Without basic active security configurations, there is evidence of lack of security awareness in system administration.',
      },
      steps: [
        { order: 1, action: { es: 'Activar Bot Fight Mode', en: 'Enable Bot Fight Mode' }, where: { es: 'Dashboard > Seguridad > Bots', en: 'Dashboard > Security > Bots' }, detail: { es: 'Activar Bot Fight Mode para protección básica contra bots.', en: 'Enable Bot Fight Mode for basic bot protection.' } },
        { order: 2, action: { es: 'Establecer nivel de seguridad', en: 'Set security level' }, where: { es: 'Dashboard > Seguridad > Configuración', en: 'Dashboard > Security > Settings' }, detail: { es: 'Establecer nivel Medium o superior.', en: 'Set level to Medium or higher.' } },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/bots/get-started/free/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: false,
      can_be_automated: true,
    },
    evaluate: (ctx) => {
      const secLevel = s(ctx, 'security_level');
      const botMode = s(ctx, 'bot_fight_mode');
      const hasSecurity = ['medium', 'high', 'under_attack'].includes(secLevel);
      const hasBotMode = botMode === 'on' || botMode === true;
      if (hasSecurity && hasBotMode) return ev('pass', 100, `security level: ${secLevel}, bot fight mode: on`, 'medium+ security level + bot fight mode on', 'Security awareness is demonstrated through active security configurations.', ['zone_settings']);
      if (hasSecurity || hasBotMode) return ev('partial', 50, `security level: ${secLevel || 'low'}, bot fight mode: ${botMode || 'off'}`, 'medium+ security level + bot fight mode on', 'Partial security awareness indicators active.', ['zone_settings']);
      return ev('fail', 0, `security level: ${secLevel || 'off'}, bot fight mode: off`, 'medium+ security level + bot fight mode on', 'No security awareness indicators configured.', ['zone_settings']);
    },
  },
];
