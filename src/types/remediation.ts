/**
 * Anga AutoFix - Remediation Types
 * 
 * Types for the semi-automated remediation service that allows users
 * to fix compliance issues via Cloudflare API with approval.
 */

import type { BiStr, ComplianceFramework } from './compliance';
import type { CloudflarePlanTier } from './audit';

// ══════════════════════════════════════════════════════════════════
// Remediation Action
// ══════════════════════════════════════════════════════════════════

export interface RemediationAction {
  /** Unique identifier for this action */
  action_id: string;
  
  /** Control reference (e.g., 'NIST-SC-8', 'PCI-4.2') */
  control_id: string;
  control_ref: string;
  title: BiStr;
  
  /** Cloudflare API call details */
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  endpoint: string;              // e.g., "/zones/{zone_id}/settings/ssl"
  body?: Record<string, unknown>;
  expected_response_code: number;
  
  /** Validation requirements */
  required_permissions: string[];
  requires_plan: CloudflarePlanTier;
  safe_to_automate: boolean;     // false = requires extra review
  
  /** Pricing */
  credit_cost: number;           // 500 credits per fix
  
  /** Change preview */
  current_value: string;
  new_value: string;
  impact_description: BiStr;
  
  /** Risk assessment */
  risk_level: 'low' | 'medium' | 'high';
  reversible: boolean;
  rollback_endpoint?: string;    // How to undo
  rollback_body?: Record<string, unknown>;
  
  /** Related frameworks affected */
  frameworks_affected: ComplianceFramework[];
  
  /** Documentation link */
  cloudflare_doc_url?: string;
}

// ══════════════════════════════════════════════════════════════════
// Preview Response
// ══════════════════════════════════════════════════════════════════

export interface RemediationPreviewResponse {
  zone_id: string;
  zone_name: string;
  
  /** Available actions that can be auto-fixed */
  actions: RemediationAction[];
  
  /** Cost summary */
  total_cost: number;            // Sum of all action costs
  estimated_duration: string;    // "2-5 minutes"
  
  /** Permission validation */
  permissions_check: {
    all_permissions_available: boolean;
    missing_permissions: string[];
  };
  
  /** Plan validation */
  plan_check: {
    current_plan: CloudflarePlanTier;
    plan_upgrade_required: boolean;
    required_plan?: CloudflarePlanTier;
  };
  
  /** Warnings for user review */
  warnings: string[];
  
  /** Summary stats */
  summary: {
    total_actions: number;
    quick_fixes: number;        // low risk + minutes effort
    high_risk: number;          // actions requiring extra review
    irreversible: number;       // actions that can't be easily undone
  };
}

// ══════════════════════════════════════════════════════════════════
// Execution Request & Response
// ══════════════════════════════════════════════════════════════════

export interface RemediationExecutionRequest {
  /** User context */
  user_id: string;
  account_id: string;
  
  /** Zone context */
  zone_id: string;
  zone_name: string;
  
  /** Cloudflare API token */
  api_token: string;
  
  /** Actions to execute (subset of preview.actions) */
  action_ids: string[];
  
  /** Confirmation */
  user_confirmed: boolean;
  total_cost_confirmed: number;
}

export interface RemediationExecutionResult {
  action_id: string;
  control_id: string;
  status: 'success' | 'failed' | 'skipped';
  message: string;
  api_response?: Record<string, unknown>;
  error?: string;
  duration_ms?: number;
}

export interface RemediationExecutionResponse {
  /** Execution tracking */
  execution_id: string;
  started_at: string;
  completed_at: string;
  
  /** Results per action */
  results: RemediationExecutionResult[];
  
  /** Summary */
  summary: {
    total: number;
    succeeded: number;
    failed: number;
    skipped: number;
  };
  
  /** Credits */
  credits_charged: number;
  credits_refunded: number;      // If some actions failed
  
  /** Next steps */
  recommendations: string[];     // e.g., "Run compliance again to verify fixes"
}

// ══════════════════════════════════════════════════════════════════
// History & Audit Log
// ══════════════════════════════════════════════════════════════════

export interface RemediationLogEntry {
  execution_id: string;
  account_id: string;
  zone_id: string;
  zone_name: string;
  
  actions_executed: number;
  actions_succeeded: number;
  actions_failed: number;
  
  credits_charged: number;
  credits_refunded: number;
  
  status: 'completed' | 'partial' | 'failed';
  
  created_at: string;
  completed_at: string;
}

// ══════════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════════

/** Credit cost per remediation action */
export const REMEDIATION_CREDIT_COST = 500;

/** Maximum actions per batch execution */
export const MAX_ACTIONS_PER_BATCH = 20;

/** Supported remediation action types */
export const SUPPORTED_REMEDIATIONS = [
  // Security Settings (low risk)
  'min_tls_version',
  'always_use_https',
  'security_header',  // HSTS
  'ssl',              // SSL mode
  
  // DNS (low risk)
  'dnssec',
  
  // WAF (medium risk)
  'managed_rulesets',
  'rate_limiting',
  
  // Advanced (varies)
  'authenticated_origin_pulls',
  'logpush',
] as const;

export type SupportedRemediation = typeof SUPPORTED_REMEDIATIONS[number];
