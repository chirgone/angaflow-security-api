/**
 * Anga Security — API Shield / API Gateway Controls
 *
 * 8 controls covering API security features available in Cloudflare Enterprise.
 * These controls are mapped to multiple frameworks (NIST, PCI DSS, SOC 2, ISO 27001).
 *
 * Enterprise Feature: For non-Enterprise zones, controls show informational status
 * rather than failing, to avoid blocking compliance report execution.
 *
 * Controls:
 * 1. API Discovery & Inventory
 * 2. Schema Validation (OpenAPI)
 * 3. JWT Token Validation
 * 4. Mutual TLS (mTLS)
 * 5. API Rate Limiting
 * 6. Session Identifiers
 * 7. Volumetric Abuse Detection
 * 8. Sequence Mitigation
 */

import type {
  FrameworkControl,
  EvaluationContext,
  ControlEvaluation,
  ComplianceFramework,
  APIShieldData,
} from '../../../types/compliance';
import { ev } from './helpers';

// ══════════════════════════════════════════════════════════════════════
// Helper: Check API Shield Data Availability
// ══════════════════════════════════════════════════════════════════════

/**
 * Checks if API Shield data is available and returns appropriate evaluation
 * for missing permission or non-Enterprise scenarios.
 *
 * Returns null if data is available and caller should proceed with evaluation.
 * Returns ControlEvaluation if data is unavailable (caller should return this).
 */
function checkAPIShieldAvailability(
  ctx: EvaluationContext,
  controlName: string,
): ControlEvaluation | null {
  const apiShield = ctx.enriched_data.api_shield;

  // Check if API Shield:Read permission is missing
  if (!apiShield || !apiShield.permission_granted) {
    if (!ctx.available_permissions.includes('API Shield:Read')) {
      return ev(
        'insufficient_permissions',
        0,
        'N/A',
        `Requires permission: API Shield:Read`,
        `API token lacks the API Shield:Read permission. Add this permission to evaluate ${controlName}.`,
        ['api_shield'],
      );
    }
    // Permission exists but no data - likely API error
    return ev(
      'not_applicable',
      0,
      'No data',
      'API Shield data',
      'API Shield data could not be collected. The feature may not be available on this zone.',
      ['api_shield'],
    );
  }

  // Check if zone is Enterprise
  if (!apiShield.is_enterprise) {
    return ev(
      'not_applicable',
      0,
      `Plan: ${apiShield.plan}`,
      'Enterprise plan',
      `${controlName} requires Cloudflare Enterprise plan. Current plan: ${apiShield.plan}. This control is informational only.`,
      ['api_shield'],
    );
  }

  // Data is available - caller should proceed
  return null;
}

// ══════════════════════════════════════════════════════════════════════
// Control Factories (Generate controls for each framework)
// ══════════════════════════════════════════════════════════════════════

/**
 * Creates the API Discovery control for a specific framework.
 */
export function createAPIDiscoveryControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-001',
    framework,
    section_id: sectionId,
    title: {
      es: 'Descubrimiento e Inventario de APIs',
      en: 'API Discovery and Inventory',
    },
    description: {
      es: 'Mantener un inventario completo de todas las APIs y endpoints expuestos usando API Shield Discovery.',
      en: 'Maintain a complete inventory of all exposed APIs and endpoints using API Shield Discovery.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Gestión de Activos API',
        en: 'API Asset Management',
      },
      clause: 'API-001',
      official_text: {
        es: 'Las organizaciones deben mantener un inventario preciso de todos los endpoints de API, incluyendo shadow APIs no documentadas.',
        en: 'Organizations must maintain an accurate inventory of all API endpoints, including undocumented shadow APIs.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield Discovery detecta automáticamente endpoints de API a través del análisis de tráfico.',
        en: 'Cloudflare API Shield Discovery automatically detects API endpoints through traffic analysis.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/management-and-monitoring/endpoint-management/',
    },
    required_data_sources: ['api_shield.discovery'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Habilitar API Discovery en API Shield',
        en: 'Enable API Discovery in API Shield',
      },
      risk_if_ignored: {
        es: 'Sin inventario de APIs, las shadow APIs pueden quedar expuestas sin protección.',
        en: 'Without API inventory, shadow APIs may remain exposed without protection.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Ir a Security > API Shield', en: 'Go to Security > API Shield' },
          where: { es: 'Dashboard > Security > API Shield', en: 'Dashboard > Security > API Shield' },
          detail: { es: 'Habilitar API Discovery para detectar endpoints automáticamente.', en: 'Enable API Discovery to automatically detect endpoints.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/management-and-monitoring/endpoint-management/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'API Discovery');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { discovery } = apiShield;

      if (!discovery.enabled || discovery.total_operations === 0) {
        return ev(
          'fail',
          0,
          `${discovery.total_operations} operations`,
          'API endpoints discovered',
          'API Discovery is not enabled or no API operations have been discovered. Enable API Discovery and wait for traffic analysis.',
          ['api_shield.discovery'],
        );
      }

      if (discovery.total_operations < 5) {
        return ev(
          'partial',
          50,
          `${discovery.total_operations} operations`,
          '5+ operations recommended',
          `Only ${discovery.total_operations} API operations discovered. Ensure all APIs are routed through Cloudflare for complete inventory.`,
          ['api_shield.discovery'],
        );
      }

      return ev(
        'pass',
        100,
        `${discovery.total_operations} operations`,
        'API endpoints discovered',
        `API Discovery is active with ${discovery.total_operations} operations inventoried.`,
        ['api_shield.discovery'],
      );
    },
  };
}

/**
 * Creates the Schema Validation control for a specific framework.
 */
export function createSchemaValidationControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-002',
    framework,
    section_id: sectionId,
    title: {
      es: 'Validación de Esquema API (OpenAPI)',
      en: 'API Schema Validation (OpenAPI)',
    },
    description: {
      es: 'Validar las solicitudes de API contra esquemas OpenAPI definidos para prevenir payloads malformados y ataques de inyección.',
      en: 'Validate API requests against defined OpenAPI schemas to prevent malformed payloads and injection attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Validación de Entrada',
        en: 'Input Validation',
      },
      clause: 'API-002',
      official_text: {
        es: 'Todas las entradas de API deben validarse contra esquemas definidos antes de procesarse.',
        en: 'All API inputs must be validated against defined schemas before processing.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield valida solicitudes contra esquemas OpenAPI 3.0.',
        en: 'Cloudflare API Shield validates requests against OpenAPI 3.0 schemas.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/security/schema-validation/',
    },
    required_data_sources: ['api_shield.schema_validation'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar Schema Validation para todas las APIs',
        en: 'Configure Schema Validation for all APIs',
      },
      risk_if_ignored: {
        es: 'Sin validación de esquema, las APIs son vulnerables a ataques de inyección y datos malformados.',
        en: 'Without schema validation, APIs are vulnerable to injection attacks and malformed data.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Subir esquema OpenAPI', en: 'Upload OpenAPI schema' },
          where: { es: 'Dashboard > Security > API Shield > Schema Validation', en: 'Dashboard > Security > API Shield > Schema Validation' },
          detail: { es: 'Subir archivo OpenAPI 3.0 (YAML o JSON) que defina los endpoints de API.', en: 'Upload OpenAPI 3.0 file (YAML or JSON) defining API endpoints.' },
        },
        {
          order: 2,
          action: { es: 'Habilitar validación', en: 'Enable validation' },
          where: { es: 'Schema settings', en: 'Schema settings' },
          detail: { es: 'Configurar acción para solicitudes no conformes (log, block).', en: 'Configure action for non-conforming requests (log, block).' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/security/schema-validation/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'Schema Validation');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { schema_validation, discovery } = apiShield;

      if (!schema_validation.enabled) {
        return ev(
          'fail',
          0,
          `${schema_validation.schemas_configured} schemas`,
          'Schema validation enabled',
          'Schema Validation is not configured. Upload OpenAPI schemas to validate API requests.',
          ['api_shield.schema_validation'],
        );
      }

      if (schema_validation.coverage_percent < 50) {
        return ev(
          'partial',
          schema_validation.coverage_percent,
          `${schema_validation.coverage_percent}% coverage`,
          '80%+ coverage',
          `Schema validation covers only ${schema_validation.coverage_percent}% of discovered operations. Add schemas for remaining endpoints.`,
          ['api_shield.schema_validation'],
        );
      }

      if (schema_validation.coverage_percent < 80) {
        return ev(
          'partial',
          schema_validation.coverage_percent,
          `${schema_validation.coverage_percent}% coverage`,
          '80%+ coverage',
          `Good coverage (${schema_validation.coverage_percent}%), but target 80%+ for full protection.`,
          ['api_shield.schema_validation'],
        );
      }

      return ev(
        'pass',
        100,
        `${schema_validation.coverage_percent}% coverage`,
        '80%+ coverage',
        `Schema validation is enabled with ${schema_validation.coverage_percent}% coverage across ${schema_validation.operations_covered} operations.`,
        ['api_shield.schema_validation'],
      );
    },
  };
}

/**
 * Creates the JWT Validation control for a specific framework.
 */
export function createJWTValidationControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-003',
    framework,
    section_id: sectionId,
    title: {
      es: 'Validación de Tokens JWT',
      en: 'JWT Token Validation',
    },
    description: {
      es: 'Validar tokens JWT en las solicitudes de API para garantizar autenticación y autorización adecuadas.',
      en: 'Validate JWT tokens in API requests to ensure proper authentication and authorization.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Autenticación de API',
        en: 'API Authentication',
      },
      clause: 'API-003',
      official_text: {
        es: 'Los tokens JWT deben validarse en el borde antes de permitir el acceso a recursos protegidos.',
        en: 'JWT tokens must be validated at the edge before allowing access to protected resources.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield valida JWT en el borde usando JWKS configurados.',
        en: 'Cloudflare API Shield validates JWTs at the edge using configured JWKS.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/security/jwt-validation/',
    },
    required_data_sources: ['api_shield.jwt_validation'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar JWT Validation para APIs autenticadas',
        en: 'Configure JWT Validation for authenticated APIs',
      },
      risk_if_ignored: {
        es: 'Sin validación JWT, tokens expirados o falsificados pueden acceder a APIs protegidas.',
        en: 'Without JWT validation, expired or forged tokens may access protected APIs.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Agregar configuración de token', en: 'Add token configuration' },
          where: { es: 'Dashboard > Security > API Shield > JWT Validation', en: 'Dashboard > Security > API Shield > JWT Validation' },
          detail: { es: 'Configurar ubicación del JWT (header/cookie) y agregar JWKS del IdP.', en: 'Configure JWT location (header/cookie) and add IdP JWKS.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/security/jwt-validation/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'JWT Validation');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { jwt_validation } = apiShield;

      if (!jwt_validation.enabled) {
        return ev(
          'fail',
          0,
          `${jwt_validation.configs_count} configs`,
          'JWT validation enabled',
          'JWT Validation is not configured. Add token configurations to validate JWT in API requests.',
          ['api_shield.jwt_validation'],
        );
      }

      return ev(
        'pass',
        100,
        `${jwt_validation.configs_count} configs`,
        'JWT validation enabled',
        `JWT Validation is enabled with ${jwt_validation.configs_count} token configuration(s).`,
        ['api_shield.jwt_validation'],
      );
    },
  };
}

/**
 * Creates the mTLS control for a specific framework.
 */
export function createMTLSControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-004',
    framework,
    section_id: sectionId,
    title: {
      es: 'Mutual TLS (mTLS) para APIs',
      en: 'Mutual TLS (mTLS) for APIs',
    },
    description: {
      es: 'Requerir certificados de cliente para autenticación mutua en conexiones de API.',
      en: 'Require client certificates for mutual authentication on API connections.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Autenticación de Certificados',
        en: 'Certificate Authentication',
      },
      clause: 'API-004',
      official_text: {
        es: 'Las APIs sensibles deben usar mTLS para verificar la identidad del cliente además del servidor.',
        en: 'Sensitive APIs should use mTLS to verify client identity in addition to the server.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield soporta mTLS con certificados de cliente gestionados o BYO-CA.',
        en: 'Cloudflare API Shield supports mTLS with managed or BYO-CA client certificates.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/security/mtls/',
    },
    required_data_sources: ['api_shield.mtls'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar mTLS para APIs sensibles',
        en: 'Configure mTLS for sensitive APIs',
      },
      risk_if_ignored: {
        es: 'Sin mTLS, cualquier cliente con credenciales válidas puede acceder a las APIs, incluso desde dispositivos comprometidos.',
        en: 'Without mTLS, any client with valid credentials can access APIs, even from compromised devices.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Crear certificados de cliente', en: 'Create client certificates' },
          where: { es: 'Dashboard > SSL/TLS > Client Certificates', en: 'Dashboard > SSL/TLS > Client Certificates' },
          detail: { es: 'Generar o importar certificados de cliente para dispositivos/servicios autorizados.', en: 'Generate or import client certificates for authorized devices/services.' },
        },
        {
          order: 2,
          action: { es: 'Configurar reglas mTLS', en: 'Configure mTLS rules' },
          where: { es: 'Dashboard > Security > API Shield', en: 'Dashboard > Security > API Shield' },
          detail: { es: 'Crear reglas que requieran certificados de cliente para endpoints específicos.', en: 'Create rules requiring client certificates for specific endpoints.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/security/mtls/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'mTLS');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { mtls } = apiShield;

      if (!mtls.enabled || mtls.certificates_configured === 0) {
        return ev(
          'fail',
          0,
          `${mtls.certificates_configured} certificates`,
          'mTLS enabled',
          'mTLS is not configured. Add client certificates to enable mutual authentication.',
          ['api_shield.mtls'],
        );
      }

      return ev(
        'pass',
        100,
        `${mtls.certificates_configured} certificates`,
        'mTLS enabled',
        `mTLS is enabled with ${mtls.certificates_configured} client certificate(s) configured.`,
        ['api_shield.mtls'],
      );
    },
  };
}

/**
 * Creates the API Rate Limiting control for a specific framework.
 */
export function createAPIRateLimitingControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-005',
    framework,
    section_id: sectionId,
    title: {
      es: 'Rate Limiting de APIs',
      en: 'API Rate Limiting',
    },
    description: {
      es: 'Implementar límites de tasa específicos para endpoints de API para prevenir abuso y ataques de fuerza bruta.',
      en: 'Implement rate limits specific to API endpoints to prevent abuse and brute force attacks.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Protección contra Abuso',
        en: 'Abuse Protection',
      },
      clause: 'API-005',
      official_text: {
        es: 'Las APIs deben tener límites de tasa configurados para prevenir ataques volumétricos y abuso.',
        en: 'APIs must have rate limits configured to prevent volumetric attacks and abuse.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield permite configurar rate limits granulares por endpoint.',
        en: 'Cloudflare API Shield allows configuring granular rate limits per endpoint.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/security/',
    },
    required_data_sources: ['api_shield.rate_limiting'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar rate limits para endpoints de API',
        en: 'Configure rate limits for API endpoints',
      },
      risk_if_ignored: {
        es: 'Sin rate limiting, las APIs son vulnerables a ataques de fuerza bruta, DDoS y abuso de recursos.',
        en: 'Without rate limiting, APIs are vulnerable to brute force attacks, DDoS and resource abuse.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Definir umbrales de tasa', en: 'Define rate thresholds' },
          where: { es: 'Dashboard > Security > API Shield > Operations', en: 'Dashboard > Security > API Shield > Operations' },
          detail: { es: 'Configurar límites de solicitudes por minuto/hora para cada endpoint.', en: 'Configure request limits per minute/hour for each endpoint.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'API Rate Limiting');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { rate_limiting, discovery } = apiShield;

      if (!rate_limiting.enabled || rate_limiting.rules_configured === 0) {
        return ev(
          'fail',
          0,
          `${rate_limiting.rules_configured} rules`,
          'Rate limiting enabled',
          'API Rate Limiting is not configured. Add rate limit rules to protect against abuse.',
          ['api_shield.rate_limiting'],
        );
      }

      const coveragePercent = discovery.total_operations > 0
        ? Math.round((rate_limiting.rules_configured / discovery.total_operations) * 100)
        : 100;

      if (coveragePercent < 50) {
        return ev(
          'partial',
          coveragePercent,
          `${rate_limiting.rules_configured} rules (${coveragePercent}% coverage)`,
          '80%+ coverage',
          `Rate limiting covers ${coveragePercent}% of discovered operations. Add limits for remaining endpoints.`,
          ['api_shield.rate_limiting'],
        );
      }

      return ev(
        'pass',
        100,
        `${rate_limiting.rules_configured} rules`,
        'Rate limiting enabled',
        `API Rate Limiting is configured with ${rate_limiting.rules_configured} rule(s).`,
        ['api_shield.rate_limiting'],
      );
    },
  };
}

/**
 * Creates the Session Identifiers control for a specific framework.
 */
export function createSessionIdentifiersControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-006',
    framework,
    section_id: sectionId,
    title: {
      es: 'Identificadores de Sesión API',
      en: 'API Session Identifiers',
    },
    description: {
      es: 'Configurar identificadores de sesión para rastrear y proteger sesiones de usuario en las APIs.',
      en: 'Configure session identifiers to track and protect user sessions in APIs.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Gestión de Sesiones',
        en: 'Session Management',
      },
      clause: 'API-006',
      official_text: {
        es: 'Las sesiones de API deben identificarse y rastrearse para detectar anomalías de uso.',
        en: 'API sessions must be identified and tracked to detect usage anomalies.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield Session Identifiers permiten rastrear sesiones por headers/cookies.',
        en: 'Cloudflare API Shield Session Identifiers allow tracking sessions by headers/cookies.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/management-and-monitoring/session-identifiers/',
    },
    required_data_sources: ['api_shield.session_identifiers'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar identificadores de sesión',
        en: 'Configure session identifiers',
      },
      risk_if_ignored: {
        es: 'Sin identificadores de sesión, es difícil detectar secuestro de sesiones o abuso por usuario.',
        en: 'Without session identifiers, it is difficult to detect session hijacking or per-user abuse.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Definir características de autenticación', en: 'Define authentication characteristics' },
          where: { es: 'Dashboard > Security > API Shield > Settings', en: 'Dashboard > Security > API Shield > Settings' },
          detail: { es: 'Configurar qué header o cookie identifica la sesión de usuario.', en: 'Configure which header or cookie identifies the user session.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/management-and-monitoring/session-identifiers/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'Session Identifiers');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { session_identifiers } = apiShield;

      if (!session_identifiers.enabled || session_identifiers.identifiers_configured === 0) {
        return ev(
          'fail',
          0,
          `${session_identifiers.identifiers_configured} identifiers`,
          'Session identifiers configured',
          'Session Identifiers are not configured. Define how to identify user sessions for better tracking.',
          ['api_shield.session_identifiers'],
        );
      }

      return ev(
        'pass',
        100,
        `${session_identifiers.identifiers_configured} identifiers`,
        'Session identifiers configured',
        `Session Identifiers are configured with ${session_identifiers.identifiers_configured} identifier(s).`,
        ['api_shield.session_identifiers'],
      );
    },
  };
}

/**
 * Creates the Volumetric Abuse Detection control for a specific framework.
 */
export function createVolumetricAbuseControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-007',
    framework,
    section_id: sectionId,
    title: {
      es: 'Detección de Abuso Volumétrico',
      en: 'Volumetric Abuse Detection',
    },
    description: {
      es: 'Detectar y mitigar automáticamente ataques volumétricos contra las APIs.',
      en: 'Automatically detect and mitigate volumetric attacks against APIs.',
    },
    severity: 'high',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Protección DDoS de API',
        en: 'API DDoS Protection',
      },
      clause: 'API-007',
      official_text: {
        es: 'Los sistemas deben detectar y mitigar automáticamente ataques volumétricos contra APIs.',
        en: 'Systems must automatically detect and mitigate volumetric attacks against APIs.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield Volumetric Abuse Detection analiza patrones de tráfico para detectar anomalías.',
        en: 'Cloudflare API Shield Volumetric Abuse Detection analyzes traffic patterns to detect anomalies.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/',
    },
    required_data_sources: ['api_shield.volumetric_abuse'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Habilitar detección de abuso volumétrico',
        en: 'Enable volumetric abuse detection',
      },
      risk_if_ignored: {
        es: 'Sin detección de abuso, las APIs pueden ser sobrecargadas por ataques volumétricos.',
        en: 'Without abuse detection, APIs can be overwhelmed by volumetric attacks.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar API Shield', en: 'Enable API Shield' },
          where: { es: 'Dashboard > Security > API Shield', en: 'Dashboard > Security > API Shield' },
          detail: { es: 'La detección de abuso volumétrico se habilita automáticamente con API Shield Enterprise.', en: 'Volumetric abuse detection is automatically enabled with API Shield Enterprise.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/',
      estimated_effort: 'minutes',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'Volumetric Abuse Detection');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { volumetric_abuse, discovery } = apiShield;

      // Volumetric abuse detection is automatically enabled for Enterprise with active Discovery
      if (!volumetric_abuse.enabled) {
        return ev(
          'fail',
          0,
          'Disabled',
          'Enabled',
          'Volumetric Abuse Detection is not enabled. Enable API Discovery with traffic to activate protection.',
          ['api_shield.volumetric_abuse'],
        );
      }

      return ev(
        'pass',
        100,
        'Enabled',
        'Enabled',
        'Volumetric Abuse Detection is active and monitoring API traffic patterns.',
        ['api_shield.volumetric_abuse'],
      );
    },
  };
}

/**
 * Creates the Sequence Mitigation control for a specific framework.
 */
export function createSequenceMitigationControl(
  framework: ComplianceFramework,
  controlId: string,
  sectionId: string,
  crossRefs: Array<{ framework: ComplianceFramework; control_id: string; clause: string }>,
): FrameworkControl {
  return {
    control_id: controlId,
    control_ref: 'API-008',
    framework,
    section_id: sectionId,
    title: {
      es: 'Mitigación de Secuencias de API',
      en: 'API Sequence Mitigation',
    },
    description: {
      es: 'Detectar y prevenir secuencias de llamadas API anómalas que indiquen ataques automatizados.',
      en: 'Detect and prevent anomalous API call sequences indicating automated attacks.',
    },
    severity: 'medium',
    evaluation_method: 'automated',
    regulatory_reference: {
      section: {
        es: 'Análisis de Comportamiento',
        en: 'Behavioral Analysis',
      },
      clause: 'API-008',
      official_text: {
        es: 'Los sistemas deben analizar secuencias de llamadas API para detectar patrones de abuso automatizado.',
        en: 'Systems must analyze API call sequences to detect automated abuse patterns.',
      },
      applicability_note: {
        es: 'Cloudflare API Shield Sequence Mitigation analiza el orden de las llamadas API para detectar bots.',
        en: 'Cloudflare API Shield Sequence Mitigation analyzes API call order to detect bots.',
      },
      source_url: 'https://developers.cloudflare.com/api-shield/',
    },
    required_data_sources: ['api_shield.sequence_mitigation'],
    required_permissions: ['API Shield:Read'],
    cross_references: crossRefs,
    remediation_template: {
      summary: {
        es: 'Configurar mitigación de secuencias',
        en: 'Configure sequence mitigation',
      },
      risk_if_ignored: {
        es: 'Sin análisis de secuencias, los bots pueden imitar comportamiento humano en APIs.',
        en: 'Without sequence analysis, bots can mimic human behavior on APIs.',
      },
      steps: [
        {
          order: 1,
          action: { es: 'Habilitar Sequence Mitigation', en: 'Enable Sequence Mitigation' },
          where: { es: 'Dashboard > Security > API Shield', en: 'Dashboard > Security > API Shield' },
          detail: { es: 'Configurar secuencias esperadas de llamadas API para detectar anomalías.', en: 'Configure expected API call sequences to detect anomalies.' },
        },
      ],
      cloudflare_doc_url: 'https://developers.cloudflare.com/api-shield/',
      estimated_effort: 'hours',
      requires_plan_upgrade: true,
      min_plan: 'enterprise',
      can_be_automated: false,
    },
    evaluate: (ctx) => {
      const check = checkAPIShieldAvailability(ctx, 'Sequence Mitigation');
      if (check) return check;

      const apiShield = ctx.enriched_data.api_shield!;
      const { sequence_mitigation } = apiShield;

      if (!sequence_mitigation.enabled) {
        return ev(
          'partial',
          50,
          'Not configured',
          'Configured',
          'Sequence Mitigation is not explicitly configured. This is an optional advanced feature for detecting bot behavior.',
          ['api_shield.sequence_mitigation'],
        );
      }

      return ev(
        'pass',
        100,
        'Enabled',
        'Enabled',
        'Sequence Mitigation is configured and analyzing API call patterns.',
        ['api_shield.sequence_mitigation'],
      );
    },
  };
}

// ══════════════════════════════════════════════════════════════════════
// Pre-built Control Sets for Each Framework
// ══════════════════════════════════════════════════════════════════════

/**
 * NIST 800-53 API Shield Controls
 * Mapped to: CM-8 (Configuration Management), SI-10 (Input Validation),
 * IA-2 (Identification & Auth), SC-8 (Transmission), SC-5 (DoS Protection)
 */
export const NIST_800_53_API_SHIELD_CONTROLS: FrameworkControl[] = [
  createAPIDiscoveryControl('nist_800_53', 'NIST-800-53-API-001', 'cm', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-001', clause: '6.4.2' },
    { framework: 'iso_27001', control_id: 'ISO-API-001', clause: 'A.8.1' },
  ]),
  createSchemaValidationControl('nist_800_53', 'NIST-800-53-API-002', 'si', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-002', clause: '6.5.1' },
    { framework: 'soc2_type2', control_id: 'SOC2-API-002', clause: 'CC6.1' },
  ]),
  createJWTValidationControl('nist_800_53', 'NIST-800-53-API-003', 'ia', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-003', clause: '8.2' },
    { framework: 'soc2_type2', control_id: 'SOC2-API-003', clause: 'CC6.1' },
  ]),
  createMTLSControl('nist_800_53', 'NIST-800-53-API-004', 'sc', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-004', clause: '4.1' },
    { framework: 'iso_27001', control_id: 'ISO-API-004', clause: 'A.10.1' },
  ]),
  createAPIRateLimitingControl('nist_800_53', 'NIST-800-53-API-005', 'sc', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-005', clause: '6.4.2' },
    { framework: 'soc2_type2', control_id: 'SOC2-API-005', clause: 'A1.2' },
  ]),
  createSessionIdentifiersControl('nist_800_53', 'NIST-800-53-API-006', 'sc', [
    { framework: 'soc2_type2', control_id: 'SOC2-API-006', clause: 'CC6.1' },
  ]),
  createVolumetricAbuseControl('nist_800_53', 'NIST-800-53-API-007', 'si', [
    { framework: 'pci_dss_4', control_id: 'PCI-API-007', clause: '11.4' },
    { framework: 'soc2_type2', control_id: 'SOC2-API-007', clause: 'CC7.2' },
  ]),
  createSequenceMitigationControl('nist_800_53', 'NIST-800-53-API-008', 'si', [
    { framework: 'soc2_type2', control_id: 'SOC2-API-008', clause: 'CC7.2' },
  ]),
];

/**
 * PCI DSS 4.0 API Shield Controls
 * Mapped to: Req 6 (Secure Development), Req 8 (Authentication)
 */
export const PCI_DSS_API_SHIELD_CONTROLS: FrameworkControl[] = [
  createAPIDiscoveryControl('pci_dss_4', 'PCI-API-001', 'req_6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-001', clause: 'CM-8' },
  ]),
  createSchemaValidationControl('pci_dss_4', 'PCI-API-002', 'req_6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-002', clause: 'SI-10' },
  ]),
  createJWTValidationControl('pci_dss_4', 'PCI-API-003', 'req_8', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-003', clause: 'IA-2' },
  ]),
  createMTLSControl('pci_dss_4', 'PCI-API-004', 'req_4', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-004', clause: 'SC-8' },
  ]),
  createAPIRateLimitingControl('pci_dss_4', 'PCI-API-005', 'req_6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-005', clause: 'SC-5' },
  ]),
  createVolumetricAbuseControl('pci_dss_4', 'PCI-API-007', 'req_11', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-007', clause: 'SI-4' },
  ]),
];

/**
 * SOC 2 Type II API Shield Controls
 * Mapped to: CC6 (Logical Access), CC7 (System Operations), A1 (Availability)
 */
export const SOC2_API_SHIELD_CONTROLS: FrameworkControl[] = [
  createAPIDiscoveryControl('soc2_type2', 'SOC2-API-001', 'cc6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-001', clause: 'CM-8' },
  ]),
  createSchemaValidationControl('soc2_type2', 'SOC2-API-002', 'cc6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-002', clause: 'SI-10' },
  ]),
  createJWTValidationControl('soc2_type2', 'SOC2-API-003', 'cc6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-003', clause: 'IA-2' },
  ]),
  createMTLSControl('soc2_type2', 'SOC2-API-004', 'cc6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-004', clause: 'SC-8' },
  ]),
  createAPIRateLimitingControl('soc2_type2', 'SOC2-API-005', 'a1', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-005', clause: 'SC-5' },
  ]),
  createSessionIdentifiersControl('soc2_type2', 'SOC2-API-006', 'cc6', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-006', clause: 'SC-23' },
  ]),
  createVolumetricAbuseControl('soc2_type2', 'SOC2-API-007', 'cc7', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-007', clause: 'SI-4' },
  ]),
  createSequenceMitigationControl('soc2_type2', 'SOC2-API-008', 'cc7', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-008', clause: 'SI-4' },
  ]),
];

/**
 * ISO 27001:2022 API Shield Controls
 * Mapped to: A.8 (Asset Management), A.10 (Cryptography), A.14 (Secure Development)
 */
export const ISO_27001_API_SHIELD_CONTROLS: FrameworkControl[] = [
  createAPIDiscoveryControl('iso_27001', 'ISO-API-001', 'annex_a8', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-001', clause: 'CM-8' },
  ]),
  createSchemaValidationControl('iso_27001', 'ISO-API-002', 'annex_a14', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-002', clause: 'SI-10' },
  ]),
  createJWTValidationControl('iso_27001', 'ISO-API-003', 'annex_a9', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-003', clause: 'IA-2' },
  ]),
  createMTLSControl('iso_27001', 'ISO-API-004', 'annex_a10', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-004', clause: 'SC-8' },
  ]),
  createAPIRateLimitingControl('iso_27001', 'ISO-API-005', 'annex_a12', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-005', clause: 'SC-5' },
  ]),
  createVolumetricAbuseControl('iso_27001', 'ISO-API-007', 'annex_a12', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-007', clause: 'SI-4' },
  ]),
];

/**
 * Infrastructure Baseline API Shield Controls
 */
export const INFRA_BASELINE_API_SHIELD_CONTROLS: FrameworkControl[] = [
  createAPIDiscoveryControl('infra_baseline', 'INFRA-API-001', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-001', clause: 'CM-8' },
  ]),
  createSchemaValidationControl('infra_baseline', 'INFRA-API-002', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-002', clause: 'SI-10' },
  ]),
  createJWTValidationControl('infra_baseline', 'INFRA-API-003', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-003', clause: 'IA-2' },
  ]),
  createMTLSControl('infra_baseline', 'INFRA-API-004', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-004', clause: 'SC-8' },
  ]),
  createAPIRateLimitingControl('infra_baseline', 'INFRA-API-005', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-005', clause: 'SC-5' },
  ]),
  createSessionIdentifiersControl('infra_baseline', 'INFRA-API-006', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-006', clause: 'SC-23' },
  ]),
  createVolumetricAbuseControl('infra_baseline', 'INFRA-API-007', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-007', clause: 'SI-4' },
  ]),
  createSequenceMitigationControl('infra_baseline', 'INFRA-API-008', 'api', [
    { framework: 'nist_800_53', control_id: 'NIST-800-53-API-008', clause: 'SI-4' },
  ]),
];

/**
 * All API Shield controls combined (for easy access)
 */
export const ALL_API_SHIELD_CONTROLS: FrameworkControl[] = [
  ...NIST_800_53_API_SHIELD_CONTROLS,
  ...PCI_DSS_API_SHIELD_CONTROLS,
  ...SOC2_API_SHIELD_CONTROLS,
  ...ISO_27001_API_SHIELD_CONTROLS,
  ...INFRA_BASELINE_API_SHIELD_CONTROLS,
];
