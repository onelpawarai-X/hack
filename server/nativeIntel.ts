import { resolvePtr, resolveTxt } from 'node:dns/promises';
import net from 'node:net';
import geoip from 'geoip-lite';
import { isValidIpv4 } from './threatRules.ts';

export interface GeoIntel {
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  timezone?: string;
  lat?: number;
  lon?: number;
}

export interface AsnIntel {
  asn?: string;
  prefix?: string;
  registry?: string;
  allocated?: string;
  holder?: string;
  countryCode?: string;
}

export interface WhoisIntel {
  server?: string;
  handle?: string;
  cidr?: string;
  orgName?: string;
  abuseEmails: string[];
  raw?: string;
}

export interface DomainWhoisIntel {
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastChangedDate?: string;
  dnssecSigned?: boolean;
  statuses: string[];
  abuseEmails: string[];
  nameServers: string[];
}

const countryNames = new Intl.DisplayNames(['en'], { type: 'region' });
const asnCache = new Map<string, AsnIntel>();
const whoisCache = new Map<string, WhoisIntel>();
const domainWhoisCache = new Map<string, DomainWhoisIntel>();

const REGISTRY_WHOIS: Record<string, string> = {
  arin: 'whois.arin.net',
  ripencc: 'whois.ripe.net',
  apnic: 'whois.apnic.net',
  lacnic: 'whois.lacnic.net',
  afrinic: 'whois.afrinic.net',
};

const HOSTING_TOKENS =
  /(amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|cloudflare|ovh|hetzner|leaseweb|vultr|contabo|oracle|alibaba|tencent|hosting|datacenter|data center|server|vpn|proxy|bulletproof)/i;

export function lookupGeo(ip: string): GeoIntel | null {
  if (!isValidIpv4(ip)) return null;
  const record = geoip.lookup(ip);
  if (!record) return null;
  const countryCode = record.country || undefined;
  return {
    country: countryCode ? countryNames.of(countryCode) ?? countryCode : undefined,
    countryCode,
    region: record.region || undefined,
    city: record.city || undefined,
    timezone: record.timezone || undefined,
    lat: Array.isArray(record.ll) ? record.ll[0] : undefined,
    lon: Array.isArray(record.ll) ? record.ll[1] : undefined,
  };
}

async function resolveTxtValue(name: string): Promise<string | null> {
  try {
    const rows = await resolveTxt(name);
    return rows.map((parts) => parts.join('')).join(' ').trim() || null;
  } catch {
    return null;
  }
}

export async function lookupAsn(ip: string): Promise<AsnIntel | null> {
  if (!isValidIpv4(ip)) return null;
  const cached = asnCache.get(ip);
  if (cached) return cached;
  const reversed = ip.split('.').reverse().join('.');
  const origin = await resolveTxtValue(`${reversed}.origin.asn.cymru.com`);
  if (!origin) return null;
  const fields = origin.split('|').map((field) => field.trim());
  const asnRaw = fields[0]?.split(/\s+/)[0];
  if (!asnRaw || !/^\d+$/.test(asnRaw)) return null;
  const asn = `AS${asnRaw}`;
  const nameRecord = await resolveTxtValue(`AS${asnRaw}.asn.cymru.com`);
  const nameFields = nameRecord ? nameRecord.split('|').map((field) => field.trim()) : [];
  const result: AsnIntel = {
    asn,
    prefix: fields[1] || undefined,
    countryCode: fields[2] || nameFields[1] || undefined,
    registry: fields[3] || nameFields[2] || undefined,
    allocated: fields[4] || nameFields[3] || undefined,
    holder: nameFields[4] || undefined,
  };
  asnCache.set(ip, result);
  return result;
}

export async function lookupPtr(ip: string): Promise<string | undefined> {
  if (!isValidIpv4(ip)) return undefined;
  try {
    const names = await resolvePtr(`${ip.split('.').reverse().join('.')}.in-addr.arpa`);
    return names[0];
  } catch {
    return undefined;
  }
}

function whoisQuery(server: string, query: string, timeoutMs = 7000): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const finish = (value: string) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = net.createConnection(43, server);
    socket.setEncoding('utf8');
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => socket.write(`${query}\r\n`));
    socket.on('data', (chunk) => {
      data += chunk;
      if (data.length > 256 * 1024) socket.destroy();
    });
    socket.on('end', () => finish(data));
    socket.on('timeout', () => {
      socket.destroy();
      finish(data);
    });
    socket.on('error', () => finish(data));
  });
}

function extractEmails(raw: string): string[] {
  const matches = raw.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
  return Array.from(new Set(matches.map((email) => email.toLowerCase()))).sort((a, b) => {
    const aAbuse = /abuse|security|noc|csirt|cert/.test(a) ? 0 : 1;
    const bAbuse = /abuse|security|noc|csirt|cert/.test(b) ? 0 : 1;
    return aAbuse - bAbuse;
  });
}

function referralServer(raw: string): string | undefined {
  const match = raw.match(/(?:ReferralServer|refer|whois):\s*(?:whois:\/\/)?([a-z0-9.-]+\.[a-z]{2,})/i);
  return match?.[1]?.toLowerCase();
}

function parseCidr(raw: string): string | undefined {
  const match = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/);
  return match?.[0];
}

export async function lookupWhoisIp(ip: string, registry?: string): Promise<WhoisIntel> {
  const cacheKey = `${ip}:${registry ?? ''}`;
  const cached = whoisCache.get(cacheKey);
  if (cached) return cached;
  const server = (registry && REGISTRY_WHOIS[registry.toLowerCase()]) || 'whois.arin.net';
  let raw = await whoisQuery(server, ip);
  const referral = referralServer(raw);
  if (referral && referral !== server) {
    const referred = await whoisQuery(referral, ip);
    if (referred.trim().length > 0) raw = `${raw}\n${referred}`;
  }
  const orgMatch = raw.match(/^(?:OrgName|org-name|owner|descr|netname):\s*(.+)$/im);
  const handleMatch = raw.match(/^(?:NetHandle|nic-hdl|handle):\s*(.+)$/im);
  const result: WhoisIntel = {
    server: referral ?? server,
    handle: handleMatch?.[1]?.trim(),
    cidr: parseCidr(raw),
    orgName: orgMatch?.[1]?.trim(),
    abuseEmails: extractEmails(raw).slice(0, 5),
    raw,
  };
  whoisCache.set(cacheKey, result);
  return result;
}

export async function lookupWhoisDomain(domain: string): Promise<DomainWhoisIntel | null> {
  const clean = domain.toLowerCase().replace(/^www\./, '');
  const cached = domainWhoisCache.get(clean);
  if (cached) return cached;
  const tld = clean.split('.').pop();
  if (!tld) return null;
  const iana = await whoisQuery('whois.iana.org', tld);
  const server = referralServer(iana) ?? (tld === 'com' || tld === 'net' ? 'whois.verisign-grs.com' : undefined);
  if (!server) return null;
  const raw = await whoisQuery(server, clean);
  const statuses = Array.from(
    new Set(
      Array.from(raw.matchAll(/^(?:Domain Status|status):\s*(.+)$/gim))
        .map((match) => match[1].trim())
        .filter(Boolean),
    ),
  ).slice(0, 8);
  const result: DomainWhoisIntel = {
    registrar: raw.match(/^(?:Registrar|registrar):\s*(.+)$/im)?.[1]?.trim(),
    registrationDate: raw.match(/^(?:Creation Date|created|registered):\s*(.+)$/im)?.[1]?.trim(),
    expirationDate: raw.match(/^(?:Registry Expiry Date|Expiration Date|expires):\s*(.+)$/im)?.[1]?.trim(),
    lastChangedDate: raw.match(/^(?:Updated Date|last-modified|changed):\s*(.+)$/im)?.[1]?.trim(),
    dnssecSigned: /dnssec:\s*signed/i.test(raw) || /DNSSEC:\s*signed/i.test(raw) || undefined,
    statuses,
    abuseEmails: extractEmails(raw).slice(0, 5),
    nameServers: Array.from(new Set(Array.from(raw.matchAll(/^(?:Name Server|nserver):\s*(.+)$/gim)).map((match) => match[1].trim().toLowerCase()))).slice(0, 8),
  };
  domainWhoisCache.set(clean, result);
  return result;
}

export function isHostingAsn(holder?: string): boolean {
  return Boolean(holder && HOSTING_TOKENS.test(holder));
}

export function describeAsn(intel: AsnIntel | null): string {
  if (!intel) return 'Unknown ASN';
  return intel.holder ? `${intel.asn} · ${intel.holder}` : intel.asn ?? 'Unknown ASN';
}
