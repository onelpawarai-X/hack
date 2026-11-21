import type {
  CyberIncident,
  RdapDomainProfile,
  WaybackArchiveProfile,
} from '../../src/types/cyber.ts';
import {
  extractCertSpotterSubdomains,
  parseRdapDomainProfile,
  parseWaybackCdx,
} from '../osintParsers.ts';
import { extractDomain, parseRssFeed } from '../parsers.ts';
import { classifyIncidentSeverity, extractTargetIdentifiers } from '../threatRules.ts';
import { fetchJsonWithTimeout, type ScanModulePlugin } from './types.ts';

async function fetchDiscoveredSubdomains(rootDomain: string): Promise<string[]> {
  const json = await fetchJsonWithTimeout<unknown>(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(rootDomain)}&include_subdomains=true&expand=dns_names`,
    6000,
  );
  return json ? extractCertSpotterSubdomains(json, rootDomain) : [];
}

async function fetchRdapDomainProfile(rootDomain: string): Promise<RdapDomainProfile | null> {
  const tld = rootDomain.split('.').pop()?.toLowerCase() || '';
  const rdapUrl =
    tld === 'com' || tld === 'net'
      ? `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(rootDomain)}`
      : `https://rdap.org/domain/${encodeURIComponent(rootDomain)}`;
  const json = await fetchJsonWithTimeout<unknown>(rdapUrl, 5500);
  return json ? parseRdapDomainProfile(json) : null;
}

async function fetchWaybackArchiveProfile(domain: string): Promise<WaybackArchiveProfile | null> {
  const [oldest, latest] = await Promise.all([
    fetchJsonWithTimeout<unknown>(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=1&fl=timestamp,statuscode`,
      5000,
    ),
    fetchJsonWithTimeout<unknown>(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&output=json&limit=-1&from=20240101&fl=timestamp,statuscode`,
      5000,
    ),
  ]);
  return parseWaybackCdx(oldest, latest, domain);
}

export async function searchWebBreachSignals(term: string): Promise<CyberIncident[]> {
  try {
    const q = encodeURIComponent(`${term} cyber attack breach phishing vulnerability`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    try {
      const res = await fetch(
        `https://www.bing.com/news/search?q=${q}&format=rss`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0' },
        },
      );
      if (!res.ok) return [];
      const xml = await res.text();
      const items = parseRssFeed(xml, 'Global Web Scan', 'bing').slice(0, 6);
      return items.map((item, idx) => ({
        id: `scan-web-${idx + 1}`,
        title: item.title,
        summary: item.summary,
        source: extractDomain(item.url),
        url: item.url,
        publishedAt: item.publishedAt,
        severity: classifyIncidentSeverity(item.title, item.summary),
        extractedTargets: extractTargetIdentifiers(`${item.title} ${item.summary}`),
      }));
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return [];
  }
}

export const osintMetaModule: ScanModulePlugin = {
  id: 'osintMeta',
  label: 'RDAP, CT Subdomains, Wayback & Web Breach Signals',
  isActive: false,
  supportsTargetType: (t) => t === 'ip' || t === 'domain' || t === 'url',
  async run(ctx) {
    if (ctx.targetType === 'ip') {
      ctx.log(`Searching global breach dispatches for ${ctx.host}`, 'info', 'osintMeta');
      ctx.webBreachSignals = await searchWebBreachSignals(ctx.host);
      ctx.log(
        `Found ${ctx.webBreachSignals.length} web security dispatch(es)`,
        ctx.webBreachSignals.length > 0 ? 'warn' : 'info',
        'osintMeta',
      );
      return;
    }

    ctx.log(
      `Querying certificate transparency, RDAP and Wayback for ${ctx.rootDomain}`,
      'info',
      'osintMeta',
    );
    const [subdomains, rdapProfile, waybackProfile, webSignals] = await Promise.all([
      fetchDiscoveredSubdomains(ctx.rootDomain),
      fetchRdapDomainProfile(ctx.rootDomain),
      fetchWaybackArchiveProfile(ctx.host),
      searchWebBreachSignals(ctx.host),
    ]);

    ctx.discoveredSubdomains = subdomains;
    ctx.rdapProfile = rdapProfile;
    ctx.waybackProfile = waybackProfile;
    ctx.webBreachSignals = webSignals;

    ctx.log(
      `Certificate transparency returned ${subdomains.length} subdomain(s)`,
      'info',
      'osintMeta',
    );
    if (rdapProfile?.registrar) {
      ctx.log(`RDAP registrar: ${rdapProfile.registrar}`, 'info', 'osintMeta');
    }
    if (waybackProfile?.firstSnapshot) {
      ctx.log(
        `Wayback archive first snapshot: ${waybackProfile.firstSnapshot}`,
        'info',
        'osintMeta',
      );
    }
    ctx.log(
      `Found ${webSignals.length} web breach/attack dispatch(es)`,
      webSignals.length > 0 ? 'warn' : 'info',
      'osintMeta',
    );
  },
};
