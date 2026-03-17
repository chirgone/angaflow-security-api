/**
 * External Scanner Service
 * Performs security analysis from outside — no Cloudflare credentials needed.
 * Uses fetch + DNS-over-HTTPS to analyze: SSL, headers, DNS, cookies, tech, performance.
 */

import type {
  SSLData,
  HeadersData,
  HeaderCheck,
  DNSData,
  DNSRecord,
  CookieData,
  CookieCheck,
  TechnologyData,
  PerformanceData,
  QuickScanData,
} from '../types';
import { normalizeDomainInput } from '../utils/url-safety';

// ============================================================
// Main Orchestrator
// ============================================================

export async function performQuickScan(domain: string): Promise<QuickScanData> {
  const start = Date.now();
  const cleanDomain = normalizeDomainInput(domain);

  // Run all checks in parallel for speed
  const [ssl, headersResult, dns, cookies, technology, performance] =
    await Promise.all([
      scanSSL(cleanDomain),
      scanHeaders(cleanDomain),
      scanDNS(cleanDomain),
      scanCookies(cleanDomain),
      detectTechnology(cleanDomain),
      scanPerformance(cleanDomain),
    ]);

  return {
    domain: cleanDomain,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - start,
    ssl,
    headers: headersResult,
    dns,
    cookies,
    technology,
    performance,
  };
}

// ============================================================
// Domain normalization (now using centralized utility)
// ============================================================
// Removed: now using normalizeDomainInput from url-safety.ts

// ============================================================
// SSL/TLS Scanner
// ============================================================

async function scanSSL(domain: string): Promise<SSLData> {
  const result: SSLData = {
    httpsWorks: false,
    httpRedirectsToHttps: false,
    tlsVersion: null,
    certificateIssuer: null,
    certificateExpiry: null,
    certificateDaysLeft: null,
    certificateValid: false,
    protocol: null,
  };

  // Check HTTPS
  try {
    const httpsRes = await fetchWithTimeout(`https://${domain}`, {
      redirect: 'manual',
    });
    result.httpsWorks = httpsRes.status < 500;
    result.certificateValid = true; // If fetch succeeds, TLS handshake passed
    result.protocol = httpsRes.headers.get('alt-svc')?.includes('h3')
      ? 'HTTP/3'
      : 'HTTP/2';

    // Try to extract TLS info from response headers
    // Workers can see cf-ray and other CF headers if the target is on CF
    const cfRay = httpsRes.headers.get('cf-ray');
    if (cfRay) {
      result.tlsVersion = 'TLS 1.3 (Cloudflare)';
    }
  } catch (e: any) {
    // HTTPS failed — could be cert issue or no HTTPS
    result.httpsWorks = false;
    result.certificateValid = false;
    if (e.message?.includes('SSL') || e.message?.includes('certificate')) {
      result.certificateIssuer = 'INVALID';
    }
  }

  // Check HTTP → HTTPS redirect
  try {
    const httpRes = await fetchWithTimeout(`http://${domain}`, {
      redirect: 'manual',
    });
    const location = httpRes.headers.get('location') || '';
    result.httpRedirectsToHttps = location.startsWith('https://');
  } catch {
    // HTTP might not work at all (that's fine if HTTPS works)
  }

  return result;
}

// ============================================================
// Security Headers Scanner
// ============================================================

const SECURITY_HEADERS: { name: string; header: string; recommended: string }[] = [
  {
    name: 'Strict-Transport-Security',
    header: 'strict-transport-security',
    recommended: 'max-age=31536000; includeSubDomains; preload',
  },
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    recommended: "default-src 'self'; script-src 'self'",
  },
  {
    name: 'X-Frame-Options',
    header: 'x-frame-options',
    recommended: 'DENY or SAMEORIGIN',
  },
  {
    name: 'X-Content-Type-Options',
    header: 'x-content-type-options',
    recommended: 'nosniff',
  },
  {
    name: 'Referrer-Policy',
    header: 'referrer-policy',
    recommended: 'strict-origin-when-cross-origin',
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    recommended: 'camera=(), microphone=(), geolocation=()',
  },
  {
    name: 'X-XSS-Protection',
    header: 'x-xss-protection',
    recommended: '1; mode=block (deprecated but still checked)',
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    header: 'cross-origin-opener-policy',
    recommended: 'same-origin',
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    header: 'cross-origin-resource-policy',
    recommended: 'same-origin',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    header: 'cross-origin-embedder-policy',
    recommended: 'require-corp',
  },
];

async function scanHeaders(domain: string): Promise<HeadersData> {
  const headers: HeaderCheck[] = [];
  let serverHeader: string | null = null;
  let poweredBy: string | null = null;

  try {
    const res = await fetchWithTimeout(`https://${domain}`, {
      redirect: 'follow',
    });

    serverHeader = res.headers.get('server');
    poweredBy = res.headers.get('x-powered-by');

    for (const def of SECURITY_HEADERS) {
      const value = res.headers.get(def.header);
      headers.push({
        name: def.name,
        present: !!value,
        value,
        recommended: def.recommended,
      });
    }
  } catch {
    // If HTTPS fails, all headers are missing
    for (const def of SECURITY_HEADERS) {
      headers.push({
        name: def.name,
        present: false,
        value: null,
        recommended: def.recommended,
      });
    }
  }

  return { headers, serverHeader, poweredBy };
}

// ============================================================
// DNS Scanner (via DNS-over-HTTPS — Cloudflare 1.1.1.1)
// ============================================================

interface DoHAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DoHResponse {
  Status: number;
  Answer?: DoHAnswer[];
  Authority?: DoHAnswer[];
  AD?: boolean; // DNSSEC authenticated data
}

async function queryDNS(domain: string, type: string): Promise<DoHResponse> {
  try {
    const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    const res = await fetchWithTimeout(url, {
      headers: { Accept: 'application/dns-json' },
    });
    return (await res.json()) as DoHResponse;
  } catch {
    return { Status: -1 };
  }
}

async function scanDNS(domain: string): Promise<DNSData> {
  // Query all DNS record types in parallel
  const [aRes, aaaaRes, mxRes, txtRes, nsRes, caaRes, dnskeyRes] =
    await Promise.all([
      queryDNS(domain, 'A'),
      queryDNS(domain, 'AAAA'),
      queryDNS(domain, 'MX'),
      queryDNS(domain, 'TXT'),
      queryDNS(domain, 'NS'),
      queryDNS(domain, 'CAA'),
      queryDNS(domain, 'DNSKEY'),
    ]);

  const txtRecords = (txtRes.Answer || []).map((a) => a.data);
  const nsRecords = (nsRes.Answer || []).map((a) => a.data.replace(/\.$/, ''));

  const hasSPF = txtRecords.some(
    (txt) => txt.includes('v=spf1') || txt.includes('"v=spf1')
  );
  const hasDMARC = await checkDMARC(domain);

  const isCloudflare = nsRecords.some(
    (ns) => ns.includes('.ns.cloudflare.com') || ns.includes('cloudflare')
  );

  // DNSSEC: check if AD flag is set on A record query, or if DNSKEY records exist
  const hasDNSSEC = aRes.AD === true || (dnskeyRes.Answer || []).length > 0;

  const recordCounts: Record<string, number> = {};
  const countRecords = (res: DoHResponse, type: string) => {
    recordCounts[type] = (res.Answer || []).length;
  };
  countRecords(aRes, 'A');
  countRecords(aaaaRes, 'AAAA');
  countRecords(mxRes, 'MX');
  countRecords(nsRes, 'NS');
  countRecords(caaRes, 'CAA');

  return {
    hasAAAA: (aaaaRes.Answer || []).length > 0,
    hasMX: (mxRes.Answer || []).length > 0,
    hasSPF,
    hasDMARC,
    hasDNSSEC,
    hasCAA: (caaRes.Answer || []).length > 0,
    nameservers: nsRecords,
    isCloudflare,
    recordCounts,
  };
}

async function checkDMARC(domain: string): Promise<boolean> {
  const dmarcRes = await queryDNS(`_dmarc.${domain}`, 'TXT');
  const dmarcRecords = (dmarcRes.Answer || []).map((a) => a.data);
  return dmarcRecords.some(
    (txt) => txt.includes('v=DMARC1') || txt.includes('"v=DMARC1')
  );
}

// ============================================================
// Cookie Scanner
// ============================================================

async function scanCookies(domain: string): Promise<CookieData> {
  const cookies: CookieCheck[] = [];

  try {
    const res = await fetchWithTimeout(`https://${domain}`, {
      redirect: 'follow',
    });

    // Collect all Set-Cookie headers
    // Note: Workers may not expose all Set-Cookie headers via .headers.get()
    // We use .headers.getSetCookie() if available, otherwise parse raw
    const setCookieHeaders = getSetCookieHeaders(res);

    for (const cookieStr of setCookieHeaders) {
      cookies.push(parseCookie(cookieStr));
    }
  } catch {
    // No cookies if fetch fails
  }

  const secureCount = cookies.filter((c) => c.secure).length;
  const httpOnlyCount = cookies.filter((c) => c.httpOnly).length;
  const sameSiteCount = cookies.filter((c) => c.sameSite !== null).length;

  return {
    cookies,
    totalCookies: cookies.length,
    secureCount,
    httpOnlyCount,
    sameSiteCount,
  };
}

function getSetCookieHeaders(res: Response): string[] {
  // Try the standard getSetCookie() method first
  if (typeof (res.headers as any).getSetCookie === 'function') {
    return (res.headers as any).getSetCookie();
  }
  // Fallback: get combined header (may lose individual cookies)
  const combined = res.headers.get('set-cookie');
  if (!combined) return [];
  // Split on comma followed by a cookie name pattern (rough heuristic)
  return combined.split(/,(?=\s*[a-zA-Z0-9_-]+=)/);
}

function parseCookie(cookieStr: string): CookieCheck {
  const parts = cookieStr.split(';').map((p) => p.trim());
  const [nameValue] = parts;
  const eqIdx = nameValue.indexOf('=');
  const name = eqIdx > 0 ? nameValue.slice(0, eqIdx).trim() : nameValue;

  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  let domain: string | null = null;
  let path: string | null = null;

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower === 'secure') secure = true;
    else if (lower === 'httponly') httpOnly = true;
    else if (lower.startsWith('samesite='))
      sameSite = part.split('=')[1]?.trim() || null;
    else if (lower.startsWith('domain='))
      domain = part.split('=')[1]?.trim() || null;
    else if (lower.startsWith('path='))
      path = part.split('=')[1]?.trim() || null;
  }

  return { name, secure, httpOnly, sameSite, domain, path };
}

// ============================================================
// Technology Detection
// ============================================================

const CDN_SIGNATURES: Record<string, (headers: Headers) => boolean> = {
  Cloudflare: (h) =>
    !!h.get('cf-ray') || h.get('server')?.toLowerCase().includes('cloudflare') === true,
  'AWS CloudFront': (h) =>
    !!h.get('x-amz-cf-id') || !!h.get('x-amz-cf-pop'),
  Fastly: (h) =>
    !!h.get('x-served-by') && !!h.get('x-cache'),
  Akamai: (h) =>
    !!h.get('x-akamai-transformed') || h.get('server')?.includes('AkamaiGHost') === true,
  Vercel: (h) =>
    !!h.get('x-vercel-id') || h.get('server')?.includes('Vercel') === true,
  Netlify: (h) =>
    !!h.get('x-nf-request-id') || h.get('server')?.includes('Netlify') === true,
  'Google Cloud CDN': (h) =>
    h.get('via')?.includes('google') === true,
};

const CMS_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'WordPress', pattern: /wp-content|wp-includes|wp-json/i },
  { name: 'Drupal', pattern: /drupal|sites\/default\/files/i },
  { name: 'Joomla', pattern: /joomla|com_content/i },
  { name: 'Shopify', pattern: /cdn\.shopify\.com|shopify/i },
  { name: 'Wix', pattern: /wix\.com|wixsite/i },
  { name: 'Squarespace', pattern: /squarespace/i },
  { name: 'Magento', pattern: /magento|mage\/cookies/i },
  { name: 'Ghost', pattern: /ghost\.io|ghost-api/i },
];

const FRAMEWORK_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'Next.js', pattern: /__next|_next\/static/i },
  { name: 'Nuxt.js', pattern: /__nuxt|_nuxt/i },
  { name: 'React', pattern: /react|__reactFiber/i },
  { name: 'Vue.js', pattern: /vue\.js|vue\.min\.js|v-app/i },
  { name: 'Angular', pattern: /ng-version|angular/i },
  { name: 'Svelte', pattern: /svelte/i },
  { name: 'Astro', pattern: /astro/i },
  { name: 'Laravel', pattern: /laravel|csrf-token/i },
  { name: 'Django', pattern: /csrfmiddleware|djdt/i },
  { name: 'Rails', pattern: /rails|csrf-param/i },
  { name: 'Express', pattern: /x-powered-by.*express/i },
];

const JS_LIBRARY_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: 'jQuery', pattern: /jquery[.-]?\d|jquery\.min\.js/i },
  { name: 'Bootstrap', pattern: /bootstrap[.-]?\d|bootstrap\.min/i },
  { name: 'Tailwind CSS', pattern: /tailwindcss|tailwind/i },
  { name: 'Google Analytics', pattern: /google-analytics|gtag|ga\.js/i },
  { name: 'Google Tag Manager', pattern: /googletagmanager/i },
  { name: 'Facebook Pixel', pattern: /fbevents|facebook\.net\/en_US\/fbevents/i },
  { name: 'Hotjar', pattern: /hotjar/i },
  { name: 'Sentry', pattern: /sentry/i },
  { name: 'Cloudflare Web Analytics', pattern: /cloudflareinsights|beacon\.min\.js/i },
];

async function detectTechnology(domain: string): Promise<TechnologyData> {
  const result: TechnologyData = {
    server: null,
    poweredBy: null,
    cdn: null,
    cms: null,
    framework: null,
    jsLibraries: [],
    detectedTechnologies: [],
    exposesServerInfo: false,
  };

  try {
    const res = await fetchWithTimeout(`https://${domain}`, {
      redirect: 'follow',
    });

    const headers = res.headers;
    result.server = headers.get('server');
    result.poweredBy = headers.get('x-powered-by');
    result.exposesServerInfo = !!(result.server && result.server.toLowerCase() !== 'cloudflare') || !!result.poweredBy;

    // Detect CDN
    for (const [cdn, check] of Object.entries(CDN_SIGNATURES)) {
      if (check(headers)) {
        result.cdn = cdn;
        result.detectedTechnologies.push(`CDN: ${cdn}`);
        break;
      }
    }

    // Read a chunk of the HTML body for CMS/framework/JS detection
    const body = await res.text();
    const snippet = body.slice(0, 50000); // First 50KB is enough

    // Detect CMS
    for (const sig of CMS_SIGNATURES) {
      if (sig.pattern.test(snippet) || sig.pattern.test(headers.get('x-powered-by') || '')) {
        result.cms = sig.name;
        result.detectedTechnologies.push(`CMS: ${sig.name}`);
        break;
      }
    }

    // Detect Framework
    for (const sig of FRAMEWORK_SIGNATURES) {
      if (
        sig.pattern.test(snippet) ||
        sig.pattern.test(headers.get('x-powered-by') || '')
      ) {
        result.framework = sig.name;
        result.detectedTechnologies.push(`Framework: ${sig.name}`);
        break;
      }
    }

    // Detect JS Libraries
    for (const sig of JS_LIBRARY_SIGNATURES) {
      if (sig.pattern.test(snippet)) {
        result.jsLibraries.push(sig.name);
        result.detectedTechnologies.push(sig.name);
      }
    }

    // Generator meta tag
    const generatorMatch = snippet.match(
      /<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i
    );
    if (generatorMatch && !result.cms) {
      result.cms = generatorMatch[1];
      result.detectedTechnologies.push(`Generator: ${generatorMatch[1]}`);
    }
  } catch {
    // Leave defaults
  }

  return result;
}

// ============================================================
// Performance Scanner
// ============================================================

async function scanPerformance(domain: string): Promise<PerformanceData> {
  const result: PerformanceData = {
    responseTimeMs: 0,
    httpVersion: null,
    supportsHttp2: false,
    supportsHttp3: false,
    compression: null,
    contentLength: null,
    cacheControl: null,
    hasCaching: false,
  };

  try {
    const start = Date.now();
    const res = await fetchWithTimeout(`https://${domain}`, {
      redirect: 'follow',
      headers: {
        'Accept-Encoding': 'gzip, deflate, br',
      },
    });
    result.responseTimeMs = Date.now() - start;

    // Compression
    result.compression = res.headers.get('content-encoding');

    // Content length
    const cl = res.headers.get('content-length');
    result.contentLength = cl ? parseInt(cl, 10) : null;

    // Cache
    result.cacheControl = res.headers.get('cache-control');
    result.hasCaching = !!(
      result.cacheControl &&
      !result.cacheControl.includes('no-store') &&
      !result.cacheControl.includes('no-cache')
    );

    // HTTP/2 detection — Workers fetch over HTTP/2 by default
    // HTTP/3 detection via alt-svc header
    const altSvc = res.headers.get('alt-svc') || '';
    result.supportsHttp3 = altSvc.includes('h3');
    result.supportsHttp2 = true; // Workers use H2 for outbound

    result.httpVersion = result.supportsHttp3 ? 'HTTP/3' : 'HTTP/2';

    // Consume body to avoid resource leak
    await res.text();
  } catch {
    result.responseTimeMs = -1;
  }

  return result;
}

// ============================================================
// Helpers
// ============================================================

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 10000
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent':
          'AngaSecurity/1.0 (+https://angaflow.com; security-scanner)',
        ...(options.headers || {}),
      },
    });
    return res;
  } finally {
    clearTimeout(timeoutId);
  }
}
