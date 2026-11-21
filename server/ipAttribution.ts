import type { ThreatNode } from '../src/types/cyber.ts';
import { localIoc } from './localIoc.ts';
import {
  isHostingAsn,
  lookupAsn,
  lookupGeo,
  lookupPtr,
  lookupWhoisIp,
} from './nativeIntel.ts';
import { isValidIpv4 } from './threatRules.ts';

export interface TraceOptions {
  includeWhois?: boolean;
}

function tagsFromIoc(ip: string): string[] {
  return Array.from(new Set(localIoc.lookupIp(ip).flatMap((entry) => entry.tags)));
}

function severityFromTags(tags: string[], hosting: boolean): ThreatNode['severity'] {
  if (tags.includes('c2') || tags.includes('botnet') || tags.includes('phishing')) return 'CRITICAL';
  if (tags.includes('tor') || tags.includes('scanner') || tags.includes('bruteforce')) return 'HIGH';
  if (hosting || tags.includes('hosting') || tags.includes('vpn')) return 'ELEVATED';
  return 'CLEAN';
}

function threatTypeFromTags(tags: string[]): string {
  if (tags.includes('c2')) return 'Known Command & Control Infrastructure';
  if (tags.includes('botnet')) return 'Known Botnet Node';
  if (tags.includes('phishing')) return 'Known Phishing Infrastructure';
  if (tags.includes('tor')) return 'Tor Exit / Anonymising Relay';
  if (tags.includes('scanner')) return 'Known Hostile Scanner';
  if (tags.includes('bruteforce')) return 'Known Credential Attacker';
  if (tags.includes('hosting')) return 'Bulletproof / Hosting Provider Address';
  return 'Natively Attributed Network Host';
}

export async function traceAttackerIp(
  ip: string,
  options: TraceOptions = {},
): Promise<ThreatNode | null> {
  if (!isValidIpv4(ip)) return null;

  const [geo, asn, ptr] = await Promise.all([lookupGeo(ip), lookupAsn(ip), lookupPtr(ip)]);
  if (!geo && !asn && !ptr) return null;

  const whois = options.includeWhois ? await lookupWhoisIp(ip, asn?.registry) : null;
  const tags = tagsFromIoc(ip);
  const hosting = isHostingAsn(asn?.holder) || tags.includes('hosting');
  const severity = severityFromTags(tags, hosting);

  return {
    id: `trace-${ip}`,
    ip,
    threatType: tags.length > 0 ? threatTypeFromTags(tags) : 'Natively Attributed Network Host',
    sourceFeed: 'Live Attribution',
    severity,
    country: geo?.country || whois?.orgName || 'Unknown',
    countryCode: geo?.countryCode || asn?.countryCode || 'XX',
    city: geo?.city || 'Unknown',
    region: geo?.region,
    physicalAddress:
      [geo?.city, geo?.region, geo?.country].filter(Boolean).join(', ') || undefined,
    timezone: geo?.timezone,
    lat: geo?.lat ?? 0,
    lon: geo?.lon ?? 0,
    asn: asn?.asn ?? 'Unknown ASN',
    isp: asn?.holder ?? whois?.orgName ?? 'Unknown ISP',
    org: whois?.orgName ?? asn?.holder ?? 'Unknown Organization',
    reverse: ptr,
    isProxy: tags.includes('vpn') || tags.includes('tor'),
    isHosting: hosting,
    isTorExit: tags.includes('tor'),
    abuseEmails: whois?.abuseEmails ?? [],
    cidr: asn?.prefix ?? whois?.cidr,
    localTags: tags,
  };
}
