/**
 * Anga Security — Cloudflare REST API Collectors
 *
 * 5 REST collectors (all run at Tier 1 — Basic):
 *   1. Zone Info
 *   2. Zone Settings
 *   3. DNS Records + DNSSEC → DNSSummary
 *   4. Rulesets / WAF (by phase entrypoint)
 *
 * Improved over sentinel:
 *   - Typed CF API response wrapper
 *   - Better error classification (auth vs not-found vs rate-limit)
 *   - Explicit DNS pagination with safety limit
 */

import type {
  ZoneInfo,
  ZoneSetting,
  Ruleset,
  CFDNSRecord,
  DNSSummary,
} from '../../types/audit';

// ════════════════════════════════════════════════════════════════════
// CF REST Client
// ════════════════════════════════════════════════════════════════════

const CF_API = 'https://api.cloudflare.com/client/v4';

interface CfApiResponse<T> {
  success: boolean;
  errors: Array<{ code: number; message: string }>;
  messages: string[];
  result: T;
  result_info?: {
    page: number;
    per_page: number;
    total_count: number;
    total_pages: number;
  };
}

export class CfApiError extends Error {
  constructor(
    public readonly path: string,
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(`CF API ${status} for ${path}: ${detail}`);
    this.name = 'CfApiError';
  }

  get isAuthError(): boolean {
    return this.status === 401 || this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  get isRateLimit(): boolean {
    return this.status === 429;
  }
}

async function cfFetch<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${CF_API}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    signal: AbortSignal.timeout(8000),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '(no body)');
    throw new CfApiError(path, res.status, text);
  }

  const json = (await res.json()) as CfApiResponse<T>;
  if (!json.success) {
    const errMsg = json.errors?.map((e) => `[${e.code}] ${e.message}`).join('; ') || 'Unknown error';
    throw new CfApiError(path, 200, errMsg);
  }

  return json.result;
}

// ════════════════════════════════════════════════════════════════════
// Collector 1: Zone Info
// ════════════════════════════════════════════════════════════════════

export async function getZoneInfo(zoneId: string, token: string): Promise<ZoneInfo> {
  return cfFetch<ZoneInfo>(`/zones/${zoneId}`, token);
}

// ════════════════════════════════════════════════════════════════════
// Collector 2: Zone Settings
// ════════════════════════════════════════════════════════════════════

export async function getZoneSettings(zoneId: string, token: string): Promise<ZoneSetting[]> {
  return cfFetch<ZoneSetting[]>(`/zones/${zoneId}/settings`, token);
}

// ════════════════════════════════════════════════════════════════════
// Collector 3: Rulesets / WAF
// ════════════════════════════════════════════════════════════════════

/**
 * Fetches rulesets by phase entrypoint — more reliable than /rulesets list,
 * which can return 403 on some zone configurations.
 */
export async function getZoneRulesets(zoneId: string, token: string): Promise<Ruleset[]> {
  const phases = [
    'http_request_firewall_managed',
    'http_request_firewall_custom',
    'http_ratelimit',
  ];

  const results = await Promise.all(
    phases.map(async (phase) => {
      try {
        return await cfFetch<Ruleset>(
          `/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`,
          token,
        );
      } catch (err) {
        // 403 on individual phase entrypoint is NOT a fatal token error —
        // the token may have Firewall:Read but lack access to this specific
        // phase entrypoint. Treat as "no rules for this phase" like 404.
        // 404 = no rules configured for this phase — normal.
        return null;
      }
    }),
  );

  return results.filter((rs): rs is Ruleset => rs !== null);
}

// ════════════════════════════════════════════════════════════════════
// Collector 4 + 5: DNS Records + DNSSEC → DNSSummary
// ════════════════════════════════════════════════════════════════════

const MAX_DNS_PAGES = 10; // Safety limit: 1000 records max

export async function getDNSRecords(zoneId: string, token: string): Promise<CFDNSRecord[]> {
  const allRecords: CFDNSRecord[] = [];
  let page = 1;
  const perPage = 100;

  while (page <= MAX_DNS_PAGES) {
    const res = await fetch(`${CF_API}/zones/${zoneId}/dns_records?page=${page}&per_page=${perPage}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        throw new CfApiError(`/zones/${zoneId}/dns_records`, res.status, 'Unauthorized');
      }
      break;
    }

    const json = (await res.json()) as CfApiResponse<CFDNSRecord[]>;
    if (!json.success || !json.result?.length) break;

    allRecords.push(...json.result);

    const totalPages = json.result_info?.total_pages || 1;
    if (page >= totalPages) break;
    page++;
  }

  return allRecords;
}

async function getDNSSECStatus(zoneId: string, token: string): Promise<boolean> {
  try {
    const dnssec = await cfFetch<{ status: string }>(`/zones/${zoneId}/dnssec`, token);
    return dnssec.status === 'active';
  } catch {
    return false;
  }
}

/**
 * Combined collector: fetches DNS records + DNSSEC status in parallel
 * and returns an aggregated summary.
 */
export async function getDNSSummary(zoneId: string, token: string): Promise<DNSSummary> {
  const [records, dnssecEnabled] = await Promise.all([
    getDNSRecords(zoneId, token),
    getDNSSECStatus(zoneId, token),
  ]);

  const recordTypes: Record<string, number> = {};
  let proxied = 0;
  let dnsOnly = 0;

  for (const r of records) {
    recordTypes[r.type] = (recordTypes[r.type] || 0) + 1;
    if (r.proxied) proxied++;
    else dnsOnly++;
  }

  return {
    total_records: records.length,
    proxied_count: proxied,
    dns_only_count: dnsOnly,
    record_types: recordTypes,
    dnssec_enabled: dnssecEnabled,
  };
}
