import type { Workflow } from 'cloudflare:workers';
import type { SimulationWorkflowParams } from './workflows/simulation-workflow';

export interface Env {
  // Supabase (shared instance with anga)
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  SUPABASE_SERVICE_ROLE_KEY: string;

  // MercadoPago (same credentials as anga)
  MERCADOPAGO_ACCESS_TOKEN: string;
  MERCADOPAGO_PUBLIC_KEY: string;
  MERCADOPAGO_WEBHOOK_SECRET: string;

  // Webhook Router (internal auth)
  INTERNAL_WEBHOOK_SECRET: string;

  // Workers AI
  AI: Ai;

  // Simulation Workflow
  SIMULATION_WORKFLOW: Workflow<SimulationWorkflowParams>;

  // App config
  ENVIRONMENT: string;
  CORS_ORIGIN: string;
  FRONTEND_URL: string;
}

export interface Variables {
  user: {
    id: string;
    email?: string;
  };
  userId: string;
}

// Credit packages matching the pricing model
export const CREDIT_PACKAGES = {
  starter: { credits: 1500, price: 1499, name: 'Starter' },      // Precio normal - descuento 50% solo primera compra
  pro: { credits: 4500, price: 3299, name: 'Pro' },              // Actualizado: 4000→4500, 3499→3299
  business: { credits: 9000, price: 5999, name: 'Business' },    // Actualizado: 8000→9000
  enterprise: { credits: 16000, price: 9999, name: 'Enterprise' }, // Actualizado: 15000→16000
} as const;

// Service credit costs
export const SERVICE_COSTS = {
  quick_scan: 0,
  audit_basic: 1500,
  audit_pro: 3000,
  audit_complete: 5000,
  compliance_individual: 800,
  compliance_lfpdppp: 500,
  compliance_bundle: 2500,
  simulation: 3500,
  assessment: 7000,
  quick_call: 1000,
  config_review: 2000,
  security_workshop: 4000,
} as const;

// Audit tier credit costs (re-exported from types/audit.ts for convenience)
export const AUDIT_COSTS = {
  basic: 1500,
  pro: 3000,
  complete: 5000,
} as const;

// Compliance framework credit costs
export const COMPLIANCE_COSTS = {
  pci_dss_4: 800,
  iso_27001: 800,
  soc2_type2: 800,
  lfpdppp: 500,
  gdpr: 800,
  bundle: 2500,
} as const;

export type ComplianceFrameworkId = keyof Omit<typeof COMPLIANCE_COSTS, 'bundle'>;

// Subscription plans (monthly)
export const SUBSCRIPTION_PLANS = {
  watch: { price: 499, name: 'Watch' },
  guard: { price: 1499, name: 'Guard' },
  shield: { price: 3999, name: 'Shield' },
} as const;

export type CreditPackageId = keyof typeof CREDIT_PACKAGES;
export type SubscriptionPlanId = keyof typeof SUBSCRIPTION_PLANS;

// ============================================================
// Quick Scan Types
// ============================================================

export type ScanCategory =
  | 'ssl'
  | 'headers'
  | 'dns'
  | 'cookies'
  | 'technology'
  | 'performance';

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';
export type ScanGrade = 'A' | 'B' | 'C' | 'D' | 'F';
export type RecommendationPriority = 'critical' | 'high' | 'medium' | 'low';

export interface ScanCheck {
  name: string;
  status: CheckStatus;
  value: string;
  description: string;
  maxPoints: number;
  earnedPoints: number;
}

export interface CategoryResult {
  category: ScanCategory;
  label: string;
  score: number; // 0-100
  grade: ScanGrade;
  weight: number;
  weightedScore: number;
  checks: ScanCheck[];
  // Upsell: how many more checks available in full audit
  additionalChecksInAudit: number;
  auditBenefitHint: string;
}

export interface QuickScanRecommendation {
  priority: RecommendationPriority;
  category: ScanCategory;
  title: string;
  description: string;
  // Upsell: does fixing this require a paid service?
  requiresAudit: boolean;
  auditUpsellText?: string;
}

export interface QuickScanUpsell {
  quickScanChecks: number;
  auditChecks: number;
  categoriesUnlocked: string[];
  ctaText: { es: string; en: string };
}

export interface QuickScanData {
  domain: string;
  scannedAt: string;
  durationMs: number;

  // Raw collected data per category
  ssl: SSLData;
  headers: HeadersData;
  dns: DNSData;
  cookies: CookieData;
  technology: TechnologyData;
  performance: PerformanceData;
}

export interface QuickScanResult {
  reportId: string;
  domain: string;
  overallScore: number;
  overallGrade: ScanGrade;
  categories: CategoryResult[];
  recommendations: QuickScanRecommendation[];
  upsell: QuickScanUpsell;
  scannedAt: string;
  durationMs: number;
}

// --- SSL/TLS ---

export interface SSLData {
  httpsWorks: boolean;
  httpRedirectsToHttps: boolean;
  tlsVersion: string | null;
  certificateIssuer: string | null;
  certificateExpiry: string | null;
  certificateDaysLeft: number | null;
  certificateValid: boolean;
  protocol: string | null;
}

// --- Security Headers ---

export interface HeaderCheck {
  name: string;
  present: boolean;
  value: string | null;
  recommended: string;
}

export interface HeadersData {
  headers: HeaderCheck[];
  serverHeader: string | null;
  poweredBy: string | null;
}

// --- DNS ---

export interface DNSRecord {
  type: string;
  name: string;
  value: string;
  ttl?: number;
}

export interface DNSData {
  hasAAAA: boolean;
  hasMX: boolean;
  hasSPF: boolean;
  hasDMARC: boolean;
  hasDNSSEC: boolean;
  hasCAA: boolean;
  nameservers: string[];
  isCloudflare: boolean;
  recordCounts: Record<string, number>;
}

// --- Cookies ---

export interface CookieCheck {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  domain: string | null;
  path: string | null;
}

export interface CookieData {
  cookies: CookieCheck[];
  totalCookies: number;
  secureCount: number;
  httpOnlyCount: number;
  sameSiteCount: number;
}

// --- Technology Detection ---

export interface TechnologyData {
  server: string | null;
  poweredBy: string | null;
  cdn: string | null;
  cms: string | null;
  framework: string | null;
  jsLibraries: string[];
  detectedTechnologies: string[];
  exposesServerInfo: boolean;
}

// --- Performance ---

export interface PerformanceData {
  responseTimeMs: number;
  httpVersion: string | null;
  supportsHttp2: boolean;
  supportsHttp3: boolean;
  compression: string | null;
  contentLength: number | null;
  cacheControl: string | null;
  hasCaching: boolean;
}

// Category weights for Quick Scan scoring
export const QUICK_SCAN_WEIGHTS: Record<ScanCategory, number> = {
  ssl: 0.25,
  headers: 0.25,
  dns: 0.20,
  cookies: 0.10,
  technology: 0.05,
  performance: 0.15,
};

// Free scan limit per calendar month
export const FREE_SCANS_PER_MONTH = 1;

// ============================================================
// AI Chat Types
// ============================================================

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface ChatRequest {
  messages: ChatMessage[];
  context?: 'general' | 'audit' | 'simulation' | 'compliance';
  report_id?: string;
}

export interface ChatResponse {
  message: string;
  tokens_used?: number;
}

// Credit cost for a paid Quick Scan (after free scans exhausted)
export const QUICK_SCAN_CREDIT_COST = 100;
