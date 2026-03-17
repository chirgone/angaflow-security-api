/**
 * Quick Scan Scoring Engine
 * 6 categories, weighted scoring, grade assignment, recommendations.
 * Each category includes upsell hints pointing to the full audit.
 */

import type {
  QuickScanData,
  QuickScanResult,
  CategoryResult,
  ScanCheck,
  ScanCategory,
  ScanGrade,
  QuickScanRecommendation,
  QuickScanUpsell,
  RecommendationPriority,
} from '../types';
import { QUICK_SCAN_WEIGHTS } from '../types';

// ============================================================
// Main scoring function
// ============================================================

export function calculateQuickScore(
  data: QuickScanData,
  reportId: string
): QuickScanResult {
  const categories: CategoryResult[] = [
    scoreSSL(data),
    scoreHeaders(data),
    scoreDNS(data),
    scoreCookies(data),
    scoreTechnology(data),
    scorePerformance(data),
  ];

  // Calculate overall weighted score
  const overallScore = Math.round(
    categories.reduce((sum, cat) => sum + cat.weightedScore, 0)
  );
  const overallGrade = gradeFromScore(overallScore);

  // Generate recommendations
  const recommendations = generateRecommendations(data, categories);

  // Build upsell data
  const upsell = buildUpsell(categories);

  return {
    reportId,
    domain: data.domain,
    overallScore,
    overallGrade,
    categories,
    recommendations,
    upsell,
    scannedAt: data.scannedAt,
    durationMs: data.durationMs,
  };
}

// ============================================================
// Grade helper
// ============================================================

function gradeFromScore(score: number): ScanGrade {
  if (score >= 90) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

function normalizeChecks(checks: ScanCheck[]): number {
  const maxPossible = checks.reduce((sum, c) => sum + c.maxPoints, 0);
  if (maxPossible === 0) return 100;
  const earned = checks.reduce((sum, c) => sum + c.earnedPoints, 0);
  return Math.round((earned / maxPossible) * 100);
}

// ============================================================
// SSL/TLS Scoring
// ============================================================

function scoreSSL(data: QuickScanData): CategoryResult {
  const { ssl } = data;
  const checks: ScanCheck[] = [];

  // HTTPS works (30 pts)
  checks.push({
    name: 'HTTPS Available',
    status: ssl.httpsWorks ? 'pass' : 'fail',
    value: ssl.httpsWorks ? 'Yes' : 'No',
    description: 'Site is accessible over HTTPS',
    maxPoints: 30,
    earnedPoints: ssl.httpsWorks ? 30 : 0,
  });

  // Certificate valid (25 pts)
  checks.push({
    name: 'Certificate Valid',
    status: ssl.certificateValid ? 'pass' : 'fail',
    value: ssl.certificateValid ? 'Valid' : 'Invalid or missing',
    description: 'TLS certificate is valid and trusted',
    maxPoints: 25,
    earnedPoints: ssl.certificateValid ? 25 : 0,
  });

  // HTTP → HTTPS redirect (25 pts)
  checks.push({
    name: 'HTTP → HTTPS Redirect',
    status: ssl.httpRedirectsToHttps ? 'pass' : 'warn',
    value: ssl.httpRedirectsToHttps ? 'Yes' : 'No',
    description: 'HTTP requests are redirected to HTTPS',
    maxPoints: 25,
    earnedPoints: ssl.httpRedirectsToHttps ? 25 : 0,
  });

  // Certificate expiry (20 pts)
  let certExpiryPoints = 0;
  let certExpiryStatus: ScanCheck['status'] = 'info';
  let certExpiryValue = 'Unknown';
  if (ssl.certificateDaysLeft !== null) {
    if (ssl.certificateDaysLeft > 30) {
      certExpiryPoints = 20;
      certExpiryStatus = 'pass';
      certExpiryValue = `${ssl.certificateDaysLeft} days remaining`;
    } else if (ssl.certificateDaysLeft > 7) {
      certExpiryPoints = 10;
      certExpiryStatus = 'warn';
      certExpiryValue = `${ssl.certificateDaysLeft} days remaining (expiring soon)`;
    } else {
      certExpiryPoints = 0;
      certExpiryStatus = 'fail';
      certExpiryValue = `${ssl.certificateDaysLeft} days remaining (critical)`;
    }
  } else if (ssl.certificateValid) {
    // Valid cert but no expiry data — give partial credit
    certExpiryPoints = 15;
    certExpiryStatus = 'info';
    certExpiryValue = 'Valid (expiry details unavailable from external scan)';
  }
  checks.push({
    name: 'Certificate Expiry',
    status: certExpiryStatus,
    value: certExpiryValue,
    description: 'Certificate is not expiring soon',
    maxPoints: 20,
    earnedPoints: certExpiryPoints,
  });

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.ssl;

  return {
    category: 'ssl',
    label: 'SSL / TLS',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 5,
    auditBenefitHint:
      'Full audit checks: TLS version negotiation, cipher suites, HSTS preload status, SSL mode (Flexible/Full/Strict), minimum TLS version policy',
  };
}

// ============================================================
// Security Headers Scoring
// ============================================================

function scoreHeaders(data: QuickScanData): CategoryResult {
  const { headers } = data;
  const checks: ScanCheck[] = [];

  // Critical headers worth more points
  const headerWeights: Record<string, number> = {
    'Strict-Transport-Security': 20,
    'Content-Security-Policy': 20,
    'X-Frame-Options': 15,
    'X-Content-Type-Options': 15,
    'Referrer-Policy': 10,
    'Permissions-Policy': 8,
    'X-XSS-Protection': 4,
    'Cross-Origin-Opener-Policy': 4,
    'Cross-Origin-Resource-Policy': 2,
    'Cross-Origin-Embedder-Policy': 2,
  };

  for (const h of headers.headers) {
    const maxPts = headerWeights[h.name] || 5;
    checks.push({
      name: h.name,
      status: h.present ? 'pass' : h.name.startsWith('Cross-Origin') ? 'info' : 'warn',
      value: h.present ? (h.value || 'Present').slice(0, 100) : 'Missing',
      description: `Recommended: ${h.recommended}`,
      maxPoints: maxPts,
      earnedPoints: h.present ? maxPts : 0,
    });
  }

  // Bonus penalty: server info leak
  if (headers.poweredBy) {
    checks.push({
      name: 'X-Powered-By Hidden',
      status: 'warn',
      value: `Exposes: ${headers.poweredBy}`,
      description: 'X-Powered-By header should be removed to prevent server fingerprinting',
      maxPoints: 5,
      earnedPoints: 0,
    });
  }

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.headers;

  return {
    category: 'headers',
    label: 'Security Headers',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 8,
    auditBenefitHint:
      'Full audit adds: WAF rules analysis, managed rulesets, custom firewall rules, rate limiting configuration, WAF event analysis, bot protection settings',
  };
}

// ============================================================
// DNS Scoring
// ============================================================

function scoreDNS(data: QuickScanData): CategoryResult {
  const { dns } = data;
  const checks: ScanCheck[] = [];

  // DNSSEC (25 pts)
  checks.push({
    name: 'DNSSEC',
    status: dns.hasDNSSEC ? 'pass' : 'warn',
    value: dns.hasDNSSEC ? 'Enabled' : 'Not detected',
    description: 'DNSSEC prevents DNS spoofing and cache poisoning attacks',
    maxPoints: 25,
    earnedPoints: dns.hasDNSSEC ? 25 : 0,
  });

  // SPF (20 pts)
  checks.push({
    name: 'SPF Record',
    status: dns.hasSPF ? 'pass' : 'warn',
    value: dns.hasSPF ? 'Present' : 'Missing',
    description: 'SPF helps prevent email spoofing from your domain',
    maxPoints: 20,
    earnedPoints: dns.hasSPF ? 20 : 0,
  });

  // DMARC (20 pts)
  checks.push({
    name: 'DMARC Record',
    status: dns.hasDMARC ? 'pass' : 'warn',
    value: dns.hasDMARC ? 'Present' : 'Missing',
    description: 'DMARC enforces SPF/DKIM alignment and provides reporting',
    maxPoints: 20,
    earnedPoints: dns.hasDMARC ? 20 : 0,
  });

  // CAA (15 pts)
  checks.push({
    name: 'CAA Record',
    status: dns.hasCAA ? 'pass' : 'info',
    value: dns.hasCAA ? 'Present' : 'Not set',
    description: 'CAA restricts which CAs can issue certificates for your domain',
    maxPoints: 15,
    earnedPoints: dns.hasCAA ? 15 : 0,
  });

  // IPv6 (10 pts)
  checks.push({
    name: 'IPv6 (AAAA Records)',
    status: dns.hasAAAA ? 'pass' : 'info',
    value: dns.hasAAAA ? 'Enabled' : 'Not found',
    description: 'IPv6 support ensures future-proof connectivity',
    maxPoints: 10,
    earnedPoints: dns.hasAAAA ? 10 : 0,
  });

  // Nameservers info (10 pts — bonus for Cloudflare)
  checks.push({
    name: 'Managed DNS',
    status: dns.isCloudflare ? 'pass' : 'info',
    value: dns.isCloudflare
      ? 'Cloudflare DNS'
      : dns.nameservers.slice(0, 2).join(', ') || 'Unknown',
    description: 'Using a managed DNS provider with DDoS protection',
    maxPoints: 10,
    earnedPoints: dns.isCloudflare ? 10 : 5,
  });

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.dns;

  return {
    category: 'dns',
    label: 'DNS Security',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 6,
    auditBenefitHint:
      'Full audit adds: Proxied vs exposed record analysis, DKIM validation, DNS record anomaly detection, subdomain enumeration risk, zone transfer protections',
  };
}

// ============================================================
// Cookie Scoring
// ============================================================

function scoreCookies(data: QuickScanData): CategoryResult {
  const { cookies } = data;
  const checks: ScanCheck[] = [];

  if (cookies.totalCookies === 0) {
    checks.push({
      name: 'No Cookies Detected',
      status: 'pass',
      value: 'No cookies set on initial page load',
      description: 'No cookies means no cookie-related vulnerabilities',
      maxPoints: 100,
      earnedPoints: 100,
    });
  } else {
    // Secure flag (35 pts)
    const secureRatio = cookies.secureCount / cookies.totalCookies;
    checks.push({
      name: 'Secure Flag',
      status: secureRatio === 1 ? 'pass' : secureRatio > 0.5 ? 'warn' : 'fail',
      value: `${cookies.secureCount}/${cookies.totalCookies} cookies have Secure flag`,
      description: 'All cookies should have the Secure flag to prevent transmission over HTTP',
      maxPoints: 35,
      earnedPoints: Math.round(secureRatio * 35),
    });

    // HttpOnly flag (35 pts)
    const httpOnlyRatio = cookies.httpOnlyCount / cookies.totalCookies;
    checks.push({
      name: 'HttpOnly Flag',
      status: httpOnlyRatio === 1 ? 'pass' : httpOnlyRatio > 0.5 ? 'warn' : 'fail',
      value: `${cookies.httpOnlyCount}/${cookies.totalCookies} cookies have HttpOnly flag`,
      description: 'Session cookies should have HttpOnly to prevent XSS access',
      maxPoints: 35,
      earnedPoints: Math.round(httpOnlyRatio * 35),
    });

    // SameSite attribute (30 pts)
    const sameSiteRatio = cookies.sameSiteCount / cookies.totalCookies;
    checks.push({
      name: 'SameSite Attribute',
      status: sameSiteRatio === 1 ? 'pass' : sameSiteRatio > 0.5 ? 'warn' : 'fail',
      value: `${cookies.sameSiteCount}/${cookies.totalCookies} cookies have SameSite attribute`,
      description: 'SameSite prevents CSRF attacks by controlling cross-site cookie sending',
      maxPoints: 30,
      earnedPoints: Math.round(sameSiteRatio * 30),
    });
  }

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.cookies;

  return {
    category: 'cookies',
    label: 'Cookie Security',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 4,
    auditBenefitHint:
      'Full audit adds: Cookie prefix analysis (__Host-, __Secure-), session duration review, third-party cookie inventory, consent compliance check',
  };
}

// ============================================================
// Technology Scoring
// ============================================================

function scoreTechnology(data: QuickScanData): CategoryResult {
  const { technology } = data;
  const checks: ScanCheck[] = [];

  // Server info exposure (40 pts)
  checks.push({
    name: 'Server Header Hidden',
    status: !technology.exposesServerInfo ? 'pass' : 'warn',
    value: technology.exposesServerInfo
      ? `Exposes: ${technology.server || ''} ${technology.poweredBy || ''}`.trim()
      : 'Hidden or minimal',
    description: 'Server headers should not reveal detailed version information',
    maxPoints: 40,
    earnedPoints: technology.exposesServerInfo ? 10 : 40,
  });

  // CDN detected (30 pts)
  checks.push({
    name: 'CDN / Reverse Proxy',
    status: technology.cdn ? 'pass' : 'info',
    value: technology.cdn || 'Not detected',
    description: 'Using a CDN/reverse proxy helps protect the origin server',
    maxPoints: 30,
    earnedPoints: technology.cdn ? 30 : 0,
  });

  // Technology count info (30 pts — fewer exposed technologies is better)
  const techCount = technology.detectedTechnologies.length;
  const techScore = techCount <= 3 ? 30 : techCount <= 6 ? 20 : 10;
  checks.push({
    name: 'Technology Fingerprint',
    status: techCount <= 3 ? 'pass' : techCount <= 6 ? 'info' : 'warn',
    value: `${techCount} technologies detected`,
    description: 'Minimal technology exposure reduces attack surface',
    maxPoints: 30,
    earnedPoints: techScore,
  });

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.technology;

  return {
    category: 'technology',
    label: 'Technology Exposure',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 5,
    auditBenefitHint:
      'Full audit adds: Full technology stack enumeration, outdated library detection, known CVE matching, open port analysis, API endpoint discovery',
  };
}

// ============================================================
// Performance Scoring
// ============================================================

function scorePerformance(data: QuickScanData): CategoryResult {
  const { performance } = data;
  const checks: ScanCheck[] = [];

  // Response time (30 pts)
  let rtPoints = 0;
  let rtStatus: ScanCheck['status'] = 'info';
  if (performance.responseTimeMs > 0) {
    if (performance.responseTimeMs < 500) {
      rtPoints = 30;
      rtStatus = 'pass';
    } else if (performance.responseTimeMs < 1500) {
      rtPoints = 20;
      rtStatus = 'info';
    } else if (performance.responseTimeMs < 3000) {
      rtPoints = 10;
      rtStatus = 'warn';
    } else {
      rtPoints = 0;
      rtStatus = 'fail';
    }
  }
  checks.push({
    name: 'Response Time',
    status: rtStatus,
    value:
      performance.responseTimeMs > 0
        ? `${performance.responseTimeMs}ms`
        : 'Failed',
    description: 'Server response time under 500ms is ideal',
    maxPoints: 30,
    earnedPoints: rtPoints,
  });

  // Compression (25 pts)
  checks.push({
    name: 'Compression',
    status: performance.compression ? 'pass' : 'warn',
    value: performance.compression || 'None',
    description: 'Brotli or gzip compression reduces transfer size',
    maxPoints: 25,
    earnedPoints: performance.compression
      ? performance.compression.includes('br')
        ? 25
        : 20
      : 0,
  });

  // HTTP/2+ (20 pts)
  checks.push({
    name: 'HTTP/2+ Support',
    status: performance.supportsHttp2 ? 'pass' : 'warn',
    value: performance.httpVersion || 'Unknown',
    description: 'HTTP/2 or HTTP/3 enables multiplexed, faster connections',
    maxPoints: 20,
    earnedPoints: performance.supportsHttp3 ? 20 : performance.supportsHttp2 ? 15 : 0,
  });

  // Caching (25 pts)
  checks.push({
    name: 'Cache Headers',
    status: performance.hasCaching ? 'pass' : 'warn',
    value: performance.hasCaching
      ? (performance.cacheControl || 'Present').slice(0, 80)
      : 'No cache or no-store',
    description: 'Proper cache headers improve repeat visits and reduce server load',
    maxPoints: 25,
    earnedPoints: performance.hasCaching ? 25 : 0,
  });

  const score = normalizeChecks(checks);
  const weight = QUICK_SCAN_WEIGHTS.performance;

  return {
    category: 'performance',
    label: 'Performance & Caching',
    score,
    grade: gradeFromScore(score),
    weight,
    weightedScore: score * weight,
    checks,
    additionalChecksInAudit: 6,
    auditBenefitHint:
      'Full audit adds: Cache hit ratio analysis, bandwidth breakdown, Brotli configuration, H2 prioritization, Early Hints, WebSocket support, edge cache TTL optimization',
  };
}

// ============================================================
// Recommendations Generator
// ============================================================

function generateRecommendations(
  data: QuickScanData,
  categories: CategoryResult[]
): QuickScanRecommendation[] {
  const recs: QuickScanRecommendation[] = [];

  // SSL recommendations
  if (!data.ssl.httpsWorks) {
    recs.push({
      priority: 'critical',
      category: 'ssl',
      title: 'Enable HTTPS',
      description:
        'Your site is not accessible over HTTPS. This exposes all traffic to interception. Configure an SSL certificate immediately.',
      requiresAudit: false,
    });
  }
  if (data.ssl.httpsWorks && !data.ssl.httpRedirectsToHttps) {
    recs.push({
      priority: 'high',
      category: 'ssl',
      title: 'Redirect HTTP to HTTPS',
      description:
        'Your site is accessible over HTTP without redirect. Configure automatic HTTP → HTTPS redirection to prevent insecure connections.',
      requiresAudit: false,
    });
  }

  // Header recommendations
  const missingCriticalHeaders = data.headers.headers.filter(
    (h) =>
      !h.present &&
      ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options'].includes(
        h.name
      )
  );
  for (const h of missingCriticalHeaders) {
    recs.push({
      priority: h.name === 'Strict-Transport-Security' || h.name === 'Content-Security-Policy' ? 'high' : 'medium',
      category: 'headers',
      title: `Add ${h.name} header`,
      description: `Missing ${h.name}. Recommended value: ${h.recommended}`,
      requiresAudit: false,
    });
  }
  if (data.headers.poweredBy) {
    recs.push({
      priority: 'medium',
      category: 'headers',
      title: 'Remove X-Powered-By header',
      description: `Your server exposes "${data.headers.poweredBy}". Remove this header to prevent technology fingerprinting.`,
      requiresAudit: false,
    });
  }

  // DNS recommendations
  if (!data.dns.hasDNSSEC) {
    recs.push({
      priority: 'medium',
      category: 'dns',
      title: 'Enable DNSSEC',
      description:
        'DNSSEC is not enabled. Enable it to prevent DNS spoofing and cache poisoning attacks.',
      requiresAudit: false,
    });
  }
  if (!data.dns.hasSPF) {
    recs.push({
      priority: 'high',
      category: 'dns',
      title: 'Add SPF record',
      description:
        'No SPF record found. Without SPF, attackers can send emails appearing to come from your domain.',
      requiresAudit: false,
    });
  }
  if (!data.dns.hasDMARC) {
    recs.push({
      priority: 'high',
      category: 'dns',
      title: 'Add DMARC record',
      description:
        'No DMARC record found. DMARC enforces email authentication and provides visibility into spoofing attempts.',
      requiresAudit: false,
    });
  }

  // Cookie recommendations
  if (data.cookies.totalCookies > 0) {
    if (data.cookies.secureCount < data.cookies.totalCookies) {
      recs.push({
        priority: 'high',
        category: 'cookies',
        title: 'Set Secure flag on all cookies',
        description: `${data.cookies.totalCookies - data.cookies.secureCount} cookie(s) lack the Secure flag and may be sent over unencrypted HTTP.`,
        requiresAudit: false,
      });
    }
    if (data.cookies.httpOnlyCount < data.cookies.totalCookies) {
      recs.push({
        priority: 'medium',
        category: 'cookies',
        title: 'Set HttpOnly flag on session cookies',
        description: `${data.cookies.totalCookies - data.cookies.httpOnlyCount} cookie(s) lack HttpOnly and are accessible via JavaScript (XSS risk).`,
        requiresAudit: false,
      });
    }
  }

  // Performance recommendations
  if (!data.performance.compression) {
    recs.push({
      priority: 'medium',
      category: 'performance',
      title: 'Enable compression',
      description:
        'No content compression detected. Enable Brotli or gzip to reduce page size and improve load times.',
      requiresAudit: false,
    });
  }
  if (!data.performance.hasCaching) {
    recs.push({
      priority: 'medium',
      category: 'performance',
      title: 'Configure cache headers',
      description:
        'No caching detected. Set appropriate Cache-Control headers for static assets to improve performance.',
      requiresAudit: false,
    });
  }

  // Technology recommendations
  if (data.technology.exposesServerInfo) {
    recs.push({
      priority: 'medium',
      category: 'technology',
      title: 'Hide server technology details',
      description:
        'Your server exposes version information through headers. Remove or mask Server and X-Powered-By headers.',
      requiresAudit: false,
    });
  }

  // --- UPSELL recommendations (always added) ---

  // WAF analysis upsell
  recs.push({
    priority: 'medium',
    category: 'headers',
    title: 'Deep WAF & Firewall Analysis',
    description:
      'Quick Scan checks headers from outside. A full Security Audit analyzes your WAF rules, managed rulesets, rate limiting, and real attack traffic patterns from the last 30 days.',
    requiresAudit: true,
    auditUpsellText: 'Unlock with Security Audit (1,500 credits)',
  });

  // Bot protection upsell
  recs.push({
    priority: 'medium',
    category: 'technology',
    title: 'Bot Traffic & Threat Intelligence',
    description:
      'Quick Scan detects your CDN and basic tech stack. A full audit reveals bot score distributions, attacker IPs, malicious ASNs, and JA3/JA4 TLS fingerprints.',
    requiresAudit: true,
    auditUpsellText: 'Unlock with Security Audit (1,500 credits)',
  });

  // Attack simulation upsell
  recs.push({
    priority: 'low',
    category: 'ssl',
    title: 'Real Attack Simulation',
    description:
      'Test your defenses with 75+ real-world attack payloads including SQLi, XSS, path traversal, and API exploitation. See exactly what gets blocked and what gets through.',
    requiresAudit: true,
    auditUpsellText: 'Unlock with Attack Simulation (3,500 credits)',
  });

  // Sort: critical > high > medium > low, non-upsell before upsell
  const priorityOrder: Record<RecommendationPriority, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  recs.sort((a, b) => {
    // Non-upsell first
    if (a.requiresAudit !== b.requiresAudit) return a.requiresAudit ? 1 : -1;
    return priorityOrder[a.priority] - priorityOrder[b.priority];
  });

  return recs;
}

// ============================================================
// Upsell Data Builder
// ============================================================

function buildUpsell(categories: CategoryResult[]): QuickScanUpsell {
  const quickScanChecks = categories.reduce(
    (sum, cat) => sum + cat.checks.length,
    0
  );
  const additionalInAudit = categories.reduce(
    (sum, cat) => sum + cat.additionalChecksInAudit,
    0
  );

  return {
    quickScanChecks,
    auditChecks: quickScanChecks + additionalInAudit,
    categoriesUnlocked: [
      'WAF & Firewall Rules',
      'Bot Protection',
      'DDoS Configuration',
      'API Security',
      'Access Control',
      'Attack Traffic Analysis',
    ],
    ctaText: {
      es: `Tu Quick Scan analizó ${quickScanChecks} puntos de control. Desbloquea ${quickScanChecks + additionalInAudit}+ checks con una Auditoría Completa — incluyendo análisis WAF, protección bot, y tráfico de ataques reales.`,
      en: `Your Quick Scan analyzed ${quickScanChecks} checkpoints. Unlock ${quickScanChecks + additionalInAudit}+ checks with a Full Security Audit — including WAF analysis, bot protection, and real attack traffic patterns.`,
    },
  };
}
