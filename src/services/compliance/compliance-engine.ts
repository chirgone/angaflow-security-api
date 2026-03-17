/**
 * Anga Security \u2014 Compliance Engine
 *
 * Orchestrates the full compliance evaluation pipeline:
 * 1. Load source audit data from an existing Pro/Complete report
 * 2. Run enriched compliance collectors (9 additional CF API calls)
 * 3. Evaluate all controls for the requested framework(s)
 * 4. Calculate severity-weighted scores per section, framework, and overall
 * 5. Generate executive summary with key findings and remediation estimates
 * 6. Build cross-framework matrix (for bundle reports)
 * 7. Assemble final ComplianceReport for storage
 */

import type {
  ComplianceFramework,
  ComplianceReport,
  FrameworkResult,
  ComplianceSection,
  ControlResult,
  ControlStatus,
  EvaluationContext,
  EnrichedComplianceData,
  CrossFrameworkEntry,
  CrossFrameworkRecommendation,
  BiStr,
} from '../../types/compliance';
import {
  COMPLIANCE_FRAMEWORKS,
  FRAMEWORK_INFO,
  COMPLIANCE_DISCLAIMER,
  calculateWeightedScore,
} from '../../types/compliance';
import type { CollectedData, AuditTier, CloudflarePlanTier } from '../../types/audit';
import { detectPlanTier } from '../../types/audit';
import { collectComplianceData } from './cf-compliance-collectors';
import {
  getControlsForFramework,
  getControlsBySection,
  getSectionInfo,
  ALL_CONTROLS,
} from './controls';

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Engine Input
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export interface RunComplianceParams {
  /** Source audit report data (from security_reports.data) */
  audit_data: CollectedData;
  audit_id: string;
  audit_tier: AuditTier;
  zone_name: string;
  zone_id: string;
  /** Cloudflare API token (needed for enriched collectors) */
  api_token: string;
  /** Cloudflare Account ID (needed for account-scoped collectors) */
  account_id: string;
  /** Which frameworks to evaluate */
  frameworks: ComplianceFramework[];
  /** Pre-discovered token permissions (from pre-check) */
  available_permissions: string[];
  /** Age of source audit in days */
  audit_age_days: number;
  /** Workers AI binding (for generating recommendations) */
  ai?: Ai;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Main Engine
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

export async function runComplianceEngine(
  params: RunComplianceParams,
): Promise<ComplianceReport> {
  const startTime = Date.now();
  const {
    audit_data,
    audit_id,
    audit_tier,
    zone_name,
    zone_id,
    api_token,
    account_id,
    frameworks,
    available_permissions,
    audit_age_days,
    ai,
  } = params;

  const cfPlan = detectPlanTier(audit_data.zone_info.plan.name);
  const isBundle = frameworks.length === COMPLIANCE_FRAMEWORKS.length;

  // ── Step 1: Run enriched compliance collectors ──
  const zoneSettings = audit_data.zone_settings?.map((zs) => ({
    id: zs.id,
    value: zs.value,
  }));

  const enrichedData = await collectComplianceData({
    zoneId: zone_id,
    accountId: account_id,
    token: api_token,
    zoneSettings,
  });

  // ── Step 2: Build evaluation context ──
  const ctx: EvaluationContext = {
    audit_data,
    enriched_data: enrichedData,
    cf_plan: cfPlan,
    available_permissions,
  };

  // ── Step 3: Evaluate all controls per framework ──
  const frameworkResults: FrameworkResult[] = [];
  const allControlResults: ControlResult[] = [];

  for (const fw of frameworks) {
    const result = evaluateFramework(fw, ctx);
    frameworkResults.push(result);
    for (const section of result.sections) {
      allControlResults.push(...section.controls);
    }
  }

  // ── Step 4: Calculate overall score ──
  const { score: complianceScore, grade: complianceGrade } =
    calculateWeightedScore(allControlResults);

  // ── Step 5: Build summary counters ──
  const summary = buildSummary(allControlResults);

  // ── Step 6: Build cross-framework matrix (if bundle) ──
  const crossFrameworkMatrix = isBundle
    ? buildCrossFrameworkMatrix(allControlResults, ctx)
    : undefined;

  // ── Step 6b: Generate AI-powered recommendations (if bundle) ──
  const crossFrameworkRecommendations = isBundle && crossFrameworkMatrix
    ? await generateCrossFrameworkRecommendations(crossFrameworkMatrix, allControlResults, ai)
    : undefined;

  // ── Step 7: Generate executive summary ──
  const executiveSummary = generateExecutiveSummary(
    allControlResults,
    frameworkResults,
    complianceScore,
  );

  // ── Step 8: Token audit ──
  const allRequiredPerms = new Set<string>();
  for (const fw of frameworks) {
    for (const ctrl of getControlsForFramework(fw)) {
      ctrl.required_permissions.forEach((p) => allRequiredPerms.add(p));
    }
  }
  const permsMissing = [...allRequiredPerms].filter(
    (p) => !available_permissions.includes(p),
  );

  const durationMs = Date.now() - startTime;

  // ── Step 9: Assemble final report ──
  const report: ComplianceReport = {
    version: '1.0',
    frameworks,
    is_bundle: isBundle,

    source_audit_id: audit_id,
    source_audit_tier: audit_tier,
    zone_name,
    zone_id,
    cf_plan: cfPlan,

    generated_at: new Date().toISOString(),
    duration_ms: durationMs,
    analysis_period: {
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      end: new Date().toISOString(),
    },

    compliance_score: complianceScore,
    compliance_grade: complianceGrade,

    summary,
    framework_results: frameworkResults,
    cross_framework_matrix: crossFrameworkMatrix,
    cross_framework_recommendations: crossFrameworkRecommendations,
    executive_summary: executiveSummary,

    enriched_data: enrichedData,

    token_audit: {
      permissions_available: available_permissions,
      permissions_missing: permsMissing,
      controls_limited_by_permissions: summary.insufficient_permissions,
    },

    source_audit_age_days: audit_age_days,
    staleness_warning: audit_age_days > 7,

    disclaimer: COMPLIANCE_DISCLAIMER,

    collectors_run: enrichedData.collector_results.filter(
      (r) => r.status === 'success',
    ).length,
    collectors_failed: enrichedData.collector_results.filter(
      (r) => r.status === 'failed' || r.status === 'skipped',
    ).length,
  };

  return report;
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Framework Evaluation
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function evaluateFramework(
  framework: ComplianceFramework,
  ctx: EvaluationContext,
): FrameworkResult {
  const sectionMap = getControlsBySection(framework);
  const sections: ComplianceSection[] = [];
  let totalControls = 0;
  let passed = 0;
  let failed = 0;
  let partial = 0;
  let notApplicable = 0;
  let manualRequired = 0;
  let insufficientPerms = 0;

  for (const [sectionId, controls] of sectionMap) {
    const sectionInfo = getSectionInfo(sectionId, framework);
    const controlResults: ControlResult[] = [];

    for (const ctrl of controls) {
      let evaluation;
      try {
        evaluation = ctrl.evaluate(ctx);
      } catch (err: any) {
        evaluation = {
          status: 'fail' as ControlStatus,
          score: 0,
          evidence: {
            current_value: 'Evaluation error',
            expected_value: 'N/A',
            details: `Error evaluating control: ${err.message || 'Unknown'}`,
            data_sources_used: ctrl.required_data_sources,
          },
        };
      }

      const result: ControlResult = {
        control_id: ctrl.control_id,
        control_ref: ctrl.control_ref,
        title: ctrl.title,
        description: ctrl.description,
        regulatory_reference: {
          framework_name: FRAMEWORK_INFO[framework].name,
          section: ctrl.regulatory_reference.section,
          clause: ctrl.regulatory_reference.clause,
          official_text: ctrl.regulatory_reference.official_text,
          applicability_note: ctrl.regulatory_reference.applicability_note,
          source_url: ctrl.regulatory_reference.source_url,
        },
        status: evaluation.status,
        severity: ctrl.severity,
        score: evaluation.score,
        evaluation_method: ctrl.evaluation_method,
        evidence: {
          data_sources: evaluation.evidence.data_sources_used,
          current_value: evaluation.evidence.current_value,
          expected_value: evaluation.evidence.expected_value,
          details: evaluation.evidence.details,
          raw_data: evaluation.evidence.raw_data,
        },
        remediation: ctrl.remediation_template,
        cross_references: ctrl.cross_references,
        manual_checklist:
          ctrl.evaluation_method === 'manual_flag'
            ? { verified: false }
            : undefined,
        evaluated_at: new Date().toISOString(),
      };

      controlResults.push(result);
      totalControls++;

      switch (evaluation.status) {
        case 'pass':
          passed++;
          break;
        case 'fail':
          failed++;
          break;
        case 'partial':
          partial++;
          break;
        case 'not_applicable':
          notApplicable++;
          break;
        case 'manual_required':
          manualRequired++;
          break;
        case 'insufficient_permissions':
          insufficientPerms++;
          break;
      }
    }

    const { score: sectionScore, grade: sectionGrade } =
      calculateWeightedScore(controlResults);

    const sectionCounts = countStatuses(controlResults);

    sections.push({
      id: sectionId,
      title: sectionInfo?.title || { es: sectionId, en: sectionId },
      description: sectionInfo?.description || { es: '', en: '' },
      controls: controlResults,
      section_score: sectionScore,
      section_grade: sectionGrade,
      ...sectionCounts,
    });
  }

  const allSectionControls = sections.flatMap((sec) => sec.controls);
  const { score: frameworkScore, grade: frameworkGrade } =
    calculateWeightedScore(allSectionControls);

  return {
    framework,
    framework_info: FRAMEWORK_INFO[framework],
    sections,
    framework_score: frameworkScore,
    framework_grade: frameworkGrade,
    summary: {
      total_controls: totalControls,
      passed,
      failed,
      partial,
      not_applicable: notApplicable,
      manual_required: manualRequired,
      insufficient_permissions: insufficientPerms,
    },
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Summary Builder
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

function buildSummary(controls: ControlResult[]) {
  const counts = countStatuses(controls);
  const autoVerifiable = controls.filter(
    (c) =>
      c.status !== 'manual_required' &&
      c.status !== 'not_applicable' &&
      c.status !== 'insufficient_permissions',
  ).length;
  const coveragePct =
    controls.length > 0
      ? Math.round((autoVerifiable / controls.length) * 100)
      : 0;

  return {
    total_controls: controls.length,
    ...counts,
    coverage_pct: coveragePct,
  };
}

function countStatuses(controls: ControlResult[]) {
  let passed = 0;
  let failed = 0;
  let partial = 0;
  let not_applicable = 0;
  let manual_required = 0;
  let insufficient_permissions = 0;

  for (const c of controls) {
    switch (c.status) {
      case 'pass':
        passed++;
        break;
      case 'fail':
        failed++;
        break;
      case 'partial':
        partial++;
        break;
      case 'not_applicable':
        not_applicable++;
        break;
      case 'manual_required':
        manual_required++;
        break;
      case 'insufficient_permissions':
        insufficient_permissions++;
        break;
    }
  }

  return {
    passed,
    failed,
    partial,
    not_applicable,
    manual_required,
    insufficient_permissions,
  };
}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
// Cross-Framework Matrix (bundle only)
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

/** Key Cloudflare settings that map to multiple frameworks */
const CROSS_FRAMEWORK_DATA_POINTS: Array<{
  data_point: string;
  cloudflare_setting: string;
  getValue: (ctx: EvaluationContext) => string;
}> = [
  {
    data_point: 'SSL/TLS Mode',
    cloudflare_setting: 'zone_settings.ssl',
    getValue: (ctx) => {
      const v = ctx.audit_data.zone_settings?.find((s) => s.id === 'ssl')?.value;
      return String(v || 'unknown');
    },
  },
  {
    data_point: 'Minimum TLS Version',
    cloudflare_setting: 'zone_settings.min_tls_version',
    getValue: (ctx) => {
      const v = ctx.audit_data.zone_settings?.find((s) => s.id === 'min_tls_version')?.value;
      return String(v || 'unknown');
    },
  },
  {
    data_point: 'Always HTTPS',
    cloudflare_setting: 'zone_settings.always_use_https',
    getValue: (ctx) => {
      const v = ctx.audit_data.zone_settings?.find((s) => s.id === 'always_use_https')?.value;
      return String(v || 'unknown');
    },
  },
  {
    data_point: 'HSTS',
    cloudflare_setting: 'zone_settings.security_header',
    getValue: (ctx) => {
      const h = ctx.audit_data.zone_settings?.find((s) => s.id === 'security_header')?.value as any;
      return h?.strict_transport_security?.enabled ? 'Enabled' : 'Disabled';
    },
  },
  {
    data_point: 'WAF Managed Rules',
    cloudflare_setting: 'rulesets',
    getValue: (ctx) => {
      const managed = ctx.audit_data.rulesets?.filter(
        (r) => r.phase === 'http_request_firewall_managed' && r.rules?.length > 0,
      );
      return managed && managed.length > 0 ? 'Active' : 'Inactive';
    },
  },
  {
    data_point: 'DNSSEC',
    cloudflare_setting: 'dns_summary.dnssec_enabled',
    getValue: (ctx) => (ctx.audit_data.dns_summary?.dnssec_enabled ? 'Enabled' : 'Disabled'),
  },
  {
    data_point: 'Authenticated Origin Pulls (mTLS)',
    cloudflare_setting: 'authenticated_origin_pulls',
    getValue: (ctx) =>
      ctx.enriched_data.authenticated_origin_pulls?.enabled ? 'Enabled' : 'Disabled',
  },
  {
    data_point: 'Audit Logging',
    cloudflare_setting: 'audit_logs',
    getValue: (ctx) =>
      ctx.enriched_data.audit_logs?.available ? `Active (${ctx.enriched_data.audit_logs.recent_count} events)` : 'Not available',
  },
  {
    data_point: 'Logpush',
    cloudflare_setting: 'logpush_jobs',
    getValue: (ctx) =>
      ctx.enriched_data.logpush_jobs?.total
        ? `${ctx.enriched_data.logpush_jobs.total} job(s)`
        : 'Not configured',
  },
  {
    data_point: 'Health Checks',
    cloudflare_setting: 'health_checks',
    getValue: (ctx) =>
      ctx.enriched_data.health_checks?.total
        ? `${ctx.enriched_data.health_checks.total} check(s)`
        : 'Not configured',
  },
];

function buildCrossFrameworkMatrix(
  allControls: ControlResult[],
  ctx: EvaluationContext,
): CrossFrameworkEntry[] {
  const matrix: CrossFrameworkEntry[] = [];

  for (const dp of CROSS_FRAMEWORK_DATA_POINTS) {
    // Find all controls that reference this data point
    const matching = allControls.filter((ctrl) =>
      ctrl.evidence.data_sources.some((ds) =>
        dp.cloudflare_setting.includes(ds) || ds.includes(dp.cloudflare_setting.split('.')[0]),
      ),
    );

    if (matching.length === 0) continue;

    // Deduplicate by framework
    const seen = new Set<string>();
    const frameworksCovered: CrossFrameworkEntry['frameworks_covered'] = [];
    for (const ctrl of matching) {
      // Determine framework from control_id prefix
      const fw = determineFramework(ctrl.control_id);
      if (fw && !seen.has(fw)) {
        seen.add(fw);
        frameworksCovered.push({
          framework: fw,
          control_id: ctrl.control_id,
          status: ctrl.status,
        });
      }
    }

    if (frameworksCovered.length >= 2) {
      matrix.push({
        data_point: dp.data_point,
        cloudflare_setting: dp.cloudflare_setting,
        current_value: dp.getValue(ctx),
        frameworks_covered: frameworksCovered,
      });
    }
  }

  return matrix;
}

function determineFramework(controlId: string): ComplianceFramework | null {
  if (controlId.startsWith('PCI-')) return 'pci_dss_4';
  if (controlId.startsWith('ISO-')) return 'iso_27001';
  if (controlId.startsWith('SOC2-')) return 'soc2_type2';
  if (controlId.startsWith('LFPDPPP-')) return 'lfpdppp';
  if (controlId.startsWith('GDPR-')) return 'gdpr';
  return null;
}

// ══════════════════════════════════════════════════════════════════
// AI-Powered Recommendations Generator
// ══════════════════════════════════════════════════════════════════

async function generateCrossFrameworkRecommendations(
  matrix: CrossFrameworkEntry[],
  allControls: ControlResult[],
  ai?: Ai,
): Promise<CrossFrameworkRecommendation[]> {
  const recommendations: CrossFrameworkRecommendation[] = [];

  for (const entry of matrix) {
    // Count failed/partial frameworks
    const failedOrPartial = entry.frameworks_covered.filter(
      (fc) => fc.status === 'fail' || fc.status === 'partial',
    );
    const failedFrameworks = failedOrPartial.length;
    const frameworksImpacted = entry.frameworks_covered.length;

    // If all frameworks pass, skip (no recommendation needed)
    if (failedFrameworks === 0) continue;

    // Find matching controls for this data point
    const matchingControls = allControls.filter((ctrl) =>
      ctrl.evidence.data_sources.some(
        (ds) =>
          entry.cloudflare_setting.includes(ds) ||
          ds.includes(entry.cloudflare_setting.split('.')[0]),
      ),
    );

    // Get effort estimate from controls
    const effortEstimate =
      matchingControls[0]?.remediation.estimated_effort || 'hours';

    // Determine if any control can be auto-fixed
    const canAutofix = matchingControls.some(
      (c) => c.remediation.can_be_automated && c.status !== 'pass',
    );

    // Calculate priority score (ROI-based)
    const effortWeight =
      effortEstimate === 'minutes' ? 1 : effortEstimate === 'hours' ? 2 : 4;
    const priorityScore = Math.min(
      100,
      Math.round((frameworksImpacted * failedFrameworks * 20) / effortWeight),
    );

    // Determine risk level
    const criticalCount = matchingControls.filter(
      (c) => c.severity === 'critical',
    ).length;
    const highCount = matchingControls.filter((c) => c.severity === 'high').length;
    const riskLevel: 'low' | 'medium' | 'high' | 'critical' =
      criticalCount > 0
        ? 'critical'
        : highCount > 1
          ? 'high'
          : failedFrameworks > 2
            ? 'medium'
            : 'low';

    // Quick win = high priority + low effort
    const quickWin = priorityScore >= 60 && effortEstimate === 'minutes';

    // Get remediation summary from first failing control
    const failingControl =
      matchingControls.find(
        (c) => c.status === 'fail' || c.status === 'partial',
      ) || matchingControls[0];

    const recommendation: BiStr = failingControl
      ? failingControl.remediation.summary
      : {
          es: 'Revisar y actualizar esta configuración para cumplir con los marcos de cumplimiento.',
          en: 'Review and update this configuration to meet compliance frameworks.',
        };

    // Generate AI insight (or use fallback)
    const aiInsight = await generateAIInsight(entry, failedOrPartial, ai);

    // Business impact based on frameworks and risk
    const businessImpact: BiStr = {
      es: `${riskLevel === 'critical' ? 'Riesgo crítico' : riskLevel === 'high' ? 'Alto riesgo' : riskLevel === 'medium' ? 'Riesgo moderado' : 'Bajo riesgo'}. Corregir esto mejorará el cumplimiento en ${frameworksImpacted} marcos de seguridad.`,
      en: `${riskLevel === 'critical' ? 'Critical risk' : riskLevel === 'high' ? 'High risk' : riskLevel === 'medium' ? 'Moderate risk' : 'Low risk'}. Fixing this will improve compliance across ${frameworksImpacted} security frameworks.`,
    };

    // Technical details from evidence
    const technicalDetails =
      failingControl?.evidence.details ||
      `Current value: ${entry.current_value}`;

    // Related control IDs for AutoFix
    const relatedControlIds = matchingControls
      .filter((c) => c.remediation.can_be_automated && c.status !== 'pass')
      .map((c) => c.control_id);

    recommendations.push({
      data_point: entry.data_point,
      priority_score: priorityScore,
      frameworks_impacted: frameworksImpacted,
      failed_frameworks: failedFrameworks,
      effort_estimate: effortEstimate,
      risk_level: riskLevel,
      ai_insight: aiInsight,
      quick_win: quickWin,
      can_autofix: canAutofix,
      recommendation,
      business_impact: businessImpact,
      technical_details: technicalDetails,
      related_control_ids: relatedControlIds,
    });
  }

  // Sort by priority score (highest first)
  return recommendations.sort((a, b) => b.priority_score - a.priority_score);
}

/**
 * Generate AI-powered insight using Workers AI (Llama 3.1)
 * Falls back to template-based insight if AI fails
 */
async function generateAIInsight(
  entry: CrossFrameworkEntry,
  failedOrPartial: CrossFrameworkEntry['frameworks_covered'],
  ai?: Ai,
): Promise<BiStr> {
  const failedFrameworkNames = failedOrPartial
    .map((fc) => FRAMEWORK_INFO[fc.framework]?.name || fc.framework)
    .join(', ');

  // Template-based fallback
  const fallbackInsight: BiStr = {
    es: `La configuración "${entry.data_point}" (valor actual: ${entry.current_value}) no cumple con los requisitos de ${failedFrameworkNames}. Esta configuración es crítica para mantener el cumplimiento normativo.`,
    en: `The "${entry.data_point}" configuration (current: ${entry.current_value}) does not meet requirements for ${failedFrameworkNames}. This setting is critical for maintaining regulatory compliance.`,
  };

  // If no AI binding, return fallback
  if (!ai) {
    return fallbackInsight;
  }

  try {
    const prompt = `You are a security compliance expert. In exactly 2 sentences, explain why "${entry.data_point}" (currently set to "${entry.current_value}") matters for compliance with these frameworks: ${failedFrameworkNames}. Focus on business risk and what could happen if not fixed. Be concise and actionable.`;

    const response = await ai.run('@cf/meta/llama-3.1-8b-instruct' as any, {
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 150,
    });

    const aiText =
      (response as any).response ||
      (response as any).text ||
      '';

    if (aiText && aiText.length > 20) {
      return {
        es: aiText, // TODO: Add Spanish translation via separate AI call
        en: aiText,
      };
    }

    return fallbackInsight;
  } catch (error) {
    console.error('AI insight generation failed:', error);
    return fallbackInsight;
  }
}

// ══════════════════════════════════════════════════════════════════
// Executive Summary Generator
// ══════════════════════════════════════════════════════════════════

function generateExecutiveSummary(
  controls: ControlResult[],
  frameworkResults: FrameworkResult[],
  overallScore: number,
): ComplianceReport['executive_summary'] {
  // Risk level
  const riskLevel: 'low' | 'medium' | 'high' | 'critical' =
    overallScore >= 85
      ? 'low'
      : overallScore >= 65
        ? 'medium'
        : overallScore >= 40
          ? 'high'
          : 'critical';

  // Key findings: collect critical/high failures
  const keyFindings: BiStr[] = [];
  const criticalFails = controls.filter(
    (c) => c.status === 'fail' && (c.severity === 'critical' || c.severity === 'high'),
  );
  for (const f of criticalFails.slice(0, 5)) {
    keyFindings.push({
      es: `[${f.severity.toUpperCase()}] ${f.title.es}: ${f.evidence.current_value}`,
      en: `[${f.severity.toUpperCase()}] ${f.title.en}: ${f.evidence.current_value}`,
    });
  }

  if (keyFindings.length === 0) {
    keyFindings.push({
      es: 'No se encontraron fallas cr\u00edticas o altas en los controles evaluados.',
      en: 'No critical or high failures found in evaluated controls.',
    });
  }

  // Strengths: collect passed critical/high controls
  const strengths: BiStr[] = [];
  const strongPasses = controls.filter(
    (c) => c.status === 'pass' && (c.severity === 'critical' || c.severity === 'high'),
  );
  for (const s of strongPasses.slice(0, 5)) {
    strengths.push({
      es: `${s.title.es}: Cumple correctamente`,
      en: `${s.title.en}: Fully compliant`,
    });
  }

  // Immediate actions: top 3 critical failures
  const immediateActions: BiStr[] = [];
  for (const f of criticalFails.filter((c) => c.severity === 'critical').slice(0, 3)) {
    immediateActions.push({
      es: `${f.remediation.summary.es} (${f.regulatory_reference.clause})`,
      en: `${f.remediation.summary.en} (${f.regulatory_reference.clause})`,
    });
  }

  // If no critical, pick high failures
  if (immediateActions.length === 0) {
    for (const f of criticalFails.slice(0, 3)) {
      immediateActions.push({
        es: `${f.remediation.summary.es} (${f.regulatory_reference.clause})`,
        en: `${f.remediation.summary.en} (${f.regulatory_reference.clause})`,
      });
    }
  }

  // Estimate remediation hours
  const effortMap = { minutes: 0.25, hours: 2, days: 8 };
  let totalHours = 0;
  for (const c of controls.filter((c) => c.status === 'fail' || c.status === 'partial')) {
    totalHours += effortMap[c.remediation.estimated_effort] || 2;
  }

  return {
    risk_level: riskLevel,
    key_findings: keyFindings,
    strengths,
    immediate_actions: immediateActions,
    estimated_remediation_hours: Math.round(totalHours),
  };
}
