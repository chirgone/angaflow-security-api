/**
 * Anga Security — Cloudflare GraphQL Analytics Query Templates
 *
 * All queries target: https://api.cloudflare.com/client/v4/graphql
 * Variables: $zoneTag (string!), $start (Time!), $end (Time!)
 *
 * Organized by audit tier:
 *   Tier 2 (Pro):     WAF Events, Cache, Traffic, HTTP Methods, WAF TS, Attacker IPs, Bot Scores
 *   Tier 3 (Complete): Bot ASNs, Traffic TS, Bot Histogram, Detection Engines, JA3, JA4
 */

// ════════════════════════════════════════════════════════════════════
// Tier 2 — Pro Queries
// ════════════════════════════════════════════════════════════════════

export const WAF_EVENTS_QUERY = `
query WAFEvents($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      totalEvents: firewallEventsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) { count }
      byAction: firewallEventsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { action }
      }
      topCountries: firewallEventsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { clientCountryName }
      }
      topPaths: firewallEventsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { clientRequestPath }
      }
    }
  }
}`;

export const CACHE_ANALYTICS_QUERY = `
query CacheAnalytics($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      cacheGroups: httpRequestsAdaptiveGroups(
        limit: 20
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        sum { edgeResponseBytes }
        dimensions { cacheStatus }
      }
    }
  }
}`;

export const TRAFFIC_OVERVIEW_QUERY = `
query TrafficOverview($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      totals: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        sum { edgeResponseBytes }
      }
      statusCodes: httpRequestsAdaptiveGroups(
        limit: 20
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { edgeResponseStatus }
      }
      topPaths: httpRequestsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { clientRequestPath }
      }
      topCountries: httpRequestsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { clientCountryName }
      }
      topUserAgents: httpRequestsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { userAgent }
      }
    }
  }
}`;

export const HTTP_METHOD_QUERY = `
query HTTPMethods($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      methods: httpRequestsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { clientRequestHTTPMethodName }
      }
    }
  }
}`;

export const WAF_TIME_SERIES_QUERY = `
query WAFTimeSeries($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      series: firewallEventsAdaptiveGroups(
        limit: 500
        orderBy: [datetimeHour_ASC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { datetimeHour, action }
      }
    }
  }
}`;

export const TOP_ATTACKER_IPS_QUERY = `
query TopAttackerIPs($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      attackerIPs: firewallEventsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions {
          clientIP
          clientCountryName
          clientAsn
          clientASNDescription
          action
          userAgent
        }
      }
    }
  }
}`;

export const BOT_SCORE_QUERY = `
query BotScoreDistribution($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      automated: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end, botScore: 1 }
      ) { count }
      likelyAutomated: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_geq: 2, botScore_leq: 29 }
      ) { count }
      likelyHuman: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_geq: 30, botScore_leq: 99 }
      ) { count }
      verified: httpRequestsAdaptiveGroups(
        limit: 1
        filter: { datetime_geq: $start, datetime_lt: $end, botManagementDecision: "verified_bot" }
      ) { count }
    }
  }
}`;

// ════════════════════════════════════════════════════════════════════
// Tier 3 — Complete Queries
// ════════════════════════════════════════════════════════════════════

export const BOT_ASN_QUERY = `
query BotTrafficByASN($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      botASNs: httpRequestsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_leq: 29 }
      ) {
        count
        dimensions { clientASNDescription, clientAsn }
      }
    }
  }
}`;

export const TRAFFIC_TIME_SERIES_QUERY = `
query TrafficTimeSeries($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      automated: httpRequestsAdaptiveGroups(
        limit: 200
        orderBy: [datetimeHour_ASC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore: 1 }
      ) {
        count
        dimensions { datetimeHour }
      }
      likelyAutomated: httpRequestsAdaptiveGroups(
        limit: 200
        orderBy: [datetimeHour_ASC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_geq: 2, botScore_leq: 29 }
      ) {
        count
        dimensions { datetimeHour }
      }
      likelyHuman: httpRequestsAdaptiveGroups(
        limit: 200
        orderBy: [datetimeHour_ASC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_geq: 30, botScore_leq: 99 }
      ) {
        count
        dimensions { datetimeHour }
      }
      verified: httpRequestsAdaptiveGroups(
        limit: 200
        orderBy: [datetimeHour_ASC]
        filter: { datetime_geq: $start, datetime_lt: $end, botManagementDecision: "verified_bot" }
      ) {
        count
        dimensions { datetimeHour }
      }
    }
  }
}`;

export const BOT_SCORE_HISTOGRAM_QUERY = `
query BotScoreHistogram($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      histogram: httpRequestsAdaptiveGroups(
        limit: 100
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_geq: 1, botScore_leq: 99 }
      ) {
        count
        dimensions { botScore }
      }
    }
  }
}`;

export const DETECTION_ENGINE_QUERY = `
query DetectionEngine($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      engines: httpRequestsAdaptiveGroups(
        limit: 10
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end }
      ) {
        count
        dimensions { botScoreSrcName }
      }
    }
  }
}`;

export const JA3_FINGERPRINT_QUERY = `
query JA3Fingerprints($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      ja3: httpRequestsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_leq: 29 }
      ) {
        count
        dimensions { ja3Hash, clientRequestHTTPHost }
      }
    }
  }
}`;

export const JA4_FINGERPRINT_QUERY = `
query JA4Fingerprints($zoneTag: string!, $start: Time!, $end: Time!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      ja4: httpRequestsAdaptiveGroups(
        limit: 15
        orderBy: [count_DESC]
        filter: { datetime_geq: $start, datetime_lt: $end, botScore_leq: 29 }
      ) {
        count
        dimensions { ja4, clientRequestHTTPHost }
      }
    }
  }
}`;
