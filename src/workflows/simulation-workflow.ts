/**
 * Anga Security -- Attack Simulation Workflow (Cloudflare Workflows)
 *
 * Replaces the old waitUntil() pattern with durable multi-step execution.
 * Each phase gets its own 30s CPU budget, solving the timeout issue that
 * caused 100% simulation failure rate.
 *
 * Steps:
 *   1. Intelligence Gathering   (CF REST API)
 *   2. Attack Apex              (76 tests - full suite)
 *   3-N. Attack Subdomains      (15 tests each - probe subset, up to 5 subs)
 *   N+1. Firewall Correlation   (CF GraphQL)
 *   N+2. Report Assembly        (pure computation + per-target summaries)
 *
 * The Workflow RETURNS the SimulationReport as its output.
 * DB persistence is handled by the polling endpoint (GET /:id) in the
 * Worker's fetch handler, which has its own subrequest budget -- this
 * avoids the Workers Free plan 50 subrequest-per-instance limit.
 *
 * On failure: the Workflow ends in "errored" state, and the polling
 * endpoint handles cleanup (mark failed + refund credits).
 */

import { WorkflowEntrypoint, WorkflowStep } from 'cloudflare:workers';
import type { WorkflowEvent } from 'cloudflare:workers';

import type { Env } from '../types';
import type { SimulationReport, TargetTestSummary, AttackTestResult } from '../types/simulation';

import { gatherIntelligence } from '../services/simulation/intelligence';
import { executeAttacks } from '../services/simulation/attacker';
import { correlateFirewallEvents } from '../services/simulation/correlation';
import { runSimulationAssembly } from '../services/simulation/engine';
import { SUBDOMAIN_PROBE_IDS, STATIC_PAYLOADS } from '../services/simulation/payloads';

// ================================================================
// Workflow Params (passed when creating the instance)
// ================================================================

export interface SimulationWorkflowParams {
  zoneId: string;
  apiToken: string;
  accountId: string;
  domain: string;           // Backward compatibility - apex domain fallback
  domains?: string[];       // Multi-target: array of domains to attack
  reportId: string;
  supabaseAccountId: string;
  creditCost: number;
}

// ================================================================
// Workflow Class
// ================================================================

export class SimulationWorkflow extends WorkflowEntrypoint<Env, SimulationWorkflowParams> {
  async run(
    event: WorkflowEvent<SimulationWorkflowParams>,
    step: WorkflowStep,
  ): Promise<SimulationReport> {
    const params = event.payload;
    const logPrefix = `[SIM-WF ${params.reportId}]`;

    // ---- Step 1: Intelligence Gathering ----
    const intelligence = await step.do(
      'intelligence-gathering',
      {
        retries: { limit: 2, delay: '2 seconds', backoff: 'linear' },
        timeout: '45 seconds',
      },
      async () => {
        console.log(`${logPrefix} Step 1: Intelligence gathering starting...`);
        const intel = await gatherIntelligence(params.zoneId, params.apiToken);
        console.log(`${logPrefix} Step 1: Done. Zone: ${intel.zone_name}, Plan: ${intel.cf_plan}`);
        return intel;
      },
    );

    // Determine target domains (multi-target support)
    const targets = params.domains || [params.domain || intelligence.zone_name];
    const apexDomain = targets[0]; // First is always apex
    const subdomains = targets.slice(1).slice(0, 5); // Max 5 additional subdomains

    console.log(`${logPrefix} Targets: apex=${apexDomain}, subs=${subdomains.length}`);

    // ---- Step 2: Attack Execution (Apex - Full Suite) ----
    const phase2StartISO = new Date().toISOString();

    const apexTests = await step.do(
      'attack-apex',
      {
        retries: { limit: 1, delay: '1 second', backoff: 'constant' },
        timeout: '60 seconds',
      },
      async () => {
        console.log(`${logPrefix} Step 2: Attacking apex ${apexDomain} (full suite: 76 tests)...`);
        const tests = await executeAttacks(apexDomain, intelligence);
        console.log(`${logPrefix} Step 2: Apex done. ${tests.length} tests.`);
        return tests;
      },
    );

    // ---- Steps 3+: Attack Subdomains (Probe Subset ~15 tests each) ----
    // Build the module list for subdomain probes (from the 15 test IDs)
    const probeModules = Array.from(
      new Set(
        SUBDOMAIN_PROBE_IDS.map((id) => {
          const payload = STATIC_PAYLOADS.find((p) => p.id === id);
          return payload?.module;
        }).filter(Boolean),
      ),
    );

    const subTests: any[] = [];
    for (let i = 0; i < subdomains.length; i++) {
      const subdomain = subdomains[i];
      const stepTests = await step.do(
        `attack-sub-${i + 1}`,
        {
          retries: { limit: 1, delay: '1 second', backoff: 'constant' },
          timeout: '30 seconds',
        },
        async () => {
          console.log(`${logPrefix} Step ${3 + i}: Probing subdomain ${subdomain} (~15 tests)...`);
          const tests = await executeAttacks(subdomain, intelligence, probeModules as any);
          console.log(`${logPrefix} Step ${3 + i}: Sub done. ${tests.length} tests.`);
          return tests;
        },
      );
      subTests.push(...stepTests);
    }

    // Merge all attack results
    const rawTests = [...apexTests, ...subTests];
    console.log(`${logPrefix} All attacks done. ${rawTests.length} total tests across ${targets.length} targets.`);

    // ---- Step 3: Firewall Correlation ----
    const correlationResult = await step.do(
      'firewall-correlation',
      {
        retries: { limit: 2, delay: '3 seconds', backoff: 'linear' },
        timeout: '30 seconds',
      },
      async () => {
        console.log(`${logPrefix} Step 3: Correlating firewall events...`);
        const result = await correlateFirewallEvents(
          params.zoneId,
          params.apiToken,
          rawTests,
          phase2StartISO,
        );
        console.log(
          `${logPrefix} Step 3: Done. Matched ${result.matched_events}/${result.total_events} events.`,
        );
        return result;
      },
    );

    // ---- Step 4: Report Assembly (pure computation) ----
    const report = await step.do(
      'report-assembly',
      {
        retries: { limit: 1, delay: '1 second', backoff: 'constant' },
        timeout: '15 seconds',
      },
      async () => {
        console.log(`${logPrefix} Step 4: Assembling report...`);
        const assembled = runSimulationAssembly({
          intelligence,
          tests: correlationResult.tests,
          zoneId: params.zoneId,
          domain: apexDomain,
        });

        // If multi-target, generate per-target summaries
        if (targets.length > 1) {
          const targetSummaries: TargetTestSummary[] = targets.map((targetDomain) => {
            const targetTests = correlationResult.tests.filter((t: AttackTestResult) =>
              t.request.url.includes(targetDomain),
            );
            const blocked = targetTests.filter((t: AttackTestResult) => t.outcome === 'blocked').length;
            const challenged = targetTests.filter((t: AttackTestResult) => t.outcome === 'challenged').length;
            const bypassed = targetTests.filter((t: AttackTestResult) => t.outcome === 'bypassed').length;
            const errors = targetTests.filter((t: AttackTestResult) => t.outcome === 'error').length;
            const score = targetTests.length > 0
              ? Math.round(((blocked + challenged) / targetTests.length) * 100)
              : 0;
            const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
            const risk_level = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 40 ? 'high' : 'critical';

            return {
              domain: targetDomain,
              is_apex: targetDomain === apexDomain,
              total_tests: targetTests.length,
              blocked,
              challenged,
              bypassed,
              errors,
              score,
              grade,
              risk_level,
            };
          });
          assembled.targets = targetSummaries;
        }

        console.log(
          `${logPrefix} Step 4: Done. Score: ${assembled.overall_score}, Grade: ${assembled.overall_grade}`,
        );
        return assembled;
      },
    );

    console.log(
      `${logPrefix} Workflow completed. Score: ${report.overall_score}. Returning report for persistence.`,
    );

    // Return the report -- it becomes available via instance.status().output
    // The polling endpoint will save it to the DB.
    return report;
  }
}
