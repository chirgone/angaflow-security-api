/**
 * URL Safety Utilities - SSRF Protection
 * Sprint 0.7: Security Hardening - Fix C2 (SSRF)
 * 
 * Protects against Server-Side Request Forgery by:
 * 1. Resolving domains via DNS-over-HTTPS
 * 2. Blocking RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
 * 3. Blocking loopback (127.0.0.0/8, ::1)
 * 4. Blocking link-local (169.254.0.0/16, fe80::/10)
 * 5. Blocking cloud metadata endpoints (169.254.169.254)
 */

// Blocked IP ranges (CIDR notation)
const BLOCKED_RANGES = [
  // RFC1918 private networks
  { start: ip2long('10.0.0.0'), end: ip2long('10.255.255.255'), name: 'RFC1918 (10.0.0.0/8)' },
  { start: ip2long('172.16.0.0'), end: ip2long('172.31.255.255'), name: 'RFC1918 (172.16.0.0/12)' },
  { start: ip2long('192.168.0.0'), end: ip2long('192.168.255.255'), name: 'RFC1918 (192.168.0.0/16)' },
  
  // Loopback
  { start: ip2long('127.0.0.0'), end: ip2long('127.255.255.255'), name: 'Loopback (127.0.0.0/8)' },
  
  // Link-local
  { start: ip2long('169.254.0.0'), end: ip2long('169.254.255.255'), name: 'Link-local (169.254.0.0/16)' },
  
  // Cloud metadata (AWS, GCP, Azure, etc.)
  { start: ip2long('169.254.169.254'), end: ip2long('169.254.169.254'), name: 'Cloud metadata' },
  
  // Broadcast
  { start: ip2long('255.255.255.255'), end: ip2long('255.255.255.255'), name: 'Broadcast' },
];

// IPv6 blocked patterns (simple string matching for common cases)
const BLOCKED_IPV6_PATTERNS = [
  '::1',           // Loopback
  'fe80:',         // Link-local
  'fc00:',         // Unique local
  'fd00:',         // Unique local
];

function ip2long(ip: string): number {
  const parts = ip.split('.').map(Number);
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function isIPv4(str: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str);
}

function isIPv6(str: string): boolean {
  return /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(str);
}

function isBlockedIPv4(ip: string): { blocked: boolean; reason?: string } {
  const ipLong = ip2long(ip);
  
  for (const range of BLOCKED_RANGES) {
    if (ipLong >= range.start && ipLong <= range.end) {
      return { blocked: true, reason: range.name };
    }
  }
  
  return { blocked: false };
}

function isBlockedIPv6(ip: string): { blocked: boolean; reason?: string } {
  const ipLower = ip.toLowerCase();
  
  for (const pattern of BLOCKED_IPV6_PATTERNS) {
    if (ipLower.startsWith(pattern)) {
      return { blocked: true, reason: `IPv6 ${pattern}` };
    }
  }
  
  return { blocked: false };
}

async function resolveDomain(domain: string): Promise<string[]> {
  // Use Cloudflare DNS-over-HTTPS (1.1.1.1)
  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`;
  
  try {
    const response = await fetch(dohUrl, {
      headers: { 'Accept': 'application/dns-json' },
    });
    
    if (!response.ok) {
      throw new Error(`DNS query failed: ${response.status}`);
    }
    
    const data = await response.json() as {
      Status: number;
      Answer?: Array<{ type: number; data: string }>;
    };
    
    if (data.Status !== 0 || !data.Answer) {
      throw new Error('DNS resolution failed');
    }
    
    // Type 1 = A record (IPv4)
    const ips = data.Answer.filter(a => a.type === 1).map(a => a.data);
    
    return ips;
  } catch (err) {
    throw new Error(`Failed to resolve domain: ${err instanceof Error ? err.message : 'Unknown error'}`);
  }
}

export interface SafetyCheckResult {
  safe: boolean;
  reason?: string;
  resolvedIPs?: string[];
}

/**
 * Validates that a domain is safe to fetch (not pointing to internal/private IPs)
 * @param domain - Domain name or IP address (without protocol or path)
 * @returns SafetyCheckResult with safe=true if allowed, or safe=false with reason if blocked
 */
export async function validateDomainSafety(domain: string): Promise<SafetyCheckResult> {
  // If it's already an IP, check directly
  if (isIPv4(domain)) {
    const check = isBlockedIPv4(domain);
    if (check.blocked) {
      return { safe: false, reason: `Blocked IP range: ${check.reason}` };
    }
    return { safe: true };
  }
  
  if (isIPv6(domain)) {
    const check = isBlockedIPv6(domain);
    if (check.blocked) {
      return { safe: false, reason: `Blocked IP range: ${check.reason}` };
    }
    return { safe: true };
  }
  
  // It's a domain name - resolve it
  let ips: string[];
  try {
    ips = await resolveDomain(domain);
  } catch (err) {
    return { 
      safe: false, 
      reason: `DNS resolution failed: ${err instanceof Error ? err.message : 'Unknown error'}` 
    };
  }
  
  if (ips.length === 0) {
    return { safe: false, reason: 'Domain does not resolve to any IP' };
  }
  
  // Check all resolved IPs
  for (const ip of ips) {
    const check = isBlockedIPv4(ip);
    if (check.blocked) {
      return { 
        safe: false, 
        reason: `Domain resolves to blocked IP ${ip} (${check.reason})`,
        resolvedIPs: ips,
      };
    }
  }
  
  return { safe: true, resolvedIPs: ips };
}

/**
 * Normalizes a user input to a clean domain name
 * Strips protocol, path, port, and www. prefix
 */
export function normalizeDomainInput(input: string): string {
  let d = input.trim().toLowerCase();
  
  // Strip protocol
  d = d.replace(/^https?:\/\//, '');
  
  // Strip path
  d = d.split('/')[0];
  
  // Strip port
  d = d.split(':')[0];
  
  // Strip www. prefix
  if (d.startsWith('www.')) {
    d = d.slice(4);
  }
  
  return d;
}
