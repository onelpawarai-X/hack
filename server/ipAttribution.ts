import type { ThreatNode } from '../src/types/cyber.ts';
import { reverseGeocodeAddress } from './imageForensics.ts';
import { fetchJsonWithTimeout, resolveDnsRecord } from './modules/types.ts';
import { threatMonitor } from './threatMonitor.ts';
import { isValidIpv4 } from './threatRules.ts';

async function fetchShodanInternetDb(ip: string): Promise<{
  ports: number[];
  vulns: string[];
  cpes: string[];
  tags: string[];
  hostnames: string[];
} | null> {
  const json = await fetchJsonWithTimeout<{
    ports?: number[];
    vulns?: string[];
    cpes?: string[];
    tags?: string[];
    hostnames?: string[];
  }>(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, 4500);
  if (!json) return null;
  return {
    ports: Array.isArray(json.ports) ? json.ports : [],
    vulns: Array.isArray(json.vulns) ? json.vulns : [],
    cpes: Array.isArray(json.cpes) ? json.cpes : [],
    tags: Array.isArray(json.tags) ? json.tags : [],
    hostnames: Array.isArray(json.hostnames) ? json.hostnames : [],
  };
}

export async function traceAttackerIp(ip: string): Promise<ThreatNode | null> {
  if (!isValidIpv4(ip)) return null;

  const feedMatches = threatMonitor.lookupIpMatches(ip);
  const isTorExit = threatMonitor.isTorExitIp(ip);
  const reverseOctets = ip.split('.').reverse().join('.');

  const [ptr, shodan] = await Promise.all([
    resolveDnsRecord(`${reverseOctets}.in-addr.arpa`, 'PTR'),
    fetchShodanInternetDb(ip),
  ]);

  let geo: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    postal?: string;
    timezone?: string;
    lat?: number;
    lon?: number;
    asn?: string;
    isp?: string;
    org?: string;
    reverse?: string;
    proxy?: boolean;
    hosting?: boolean;
  } | null = null;

  const ipWho = await fetchJsonWithTimeout<{
    success?: boolean;
    country?: string;
    country_code?: string;
    region?: string;
    city?: string;
    postal?: string;
    timezone?: { id?: string };
    latitude?: number;
    longitude?: number;
    connection?: { asn?: number; org?: string; isp?: string };
  }>(`https://ipwho.is/${encodeURIComponent(ip)}`, 6000);

  if (ipWho?.success && typeof ipWho.latitude === 'number' && typeof ipWho.longitude === 'number') {
    geo = {
      country: ipWho.country,
      countryCode: ipWho.country_code,
      region: ipWho.region,
      city: ipWho.city,
      postal: ipWho.postal,
      timezone: ipWho.timezone?.id,
      lat: ipWho.latitude,
      lon: ipWho.longitude,
      asn: ipWho.connection?.asn ? `AS${ipWho.connection.asn}` : undefined,
      isp: ipWho.connection?.isp,
      org: ipWho.connection?.org,
    };
  }

  if (!geo) {
    const ipApi = await fetchJsonWithTimeout<{
      status?: string;
      country?: string;
      countryCode?: string;
      regionName?: string;
      city?: string;
      zip?: string;
      timezone?: string;
      lat?: number;
      lon?: number;
      isp?: string;
      org?: string;
      as?: string;
      reverse?: string;
      proxy?: boolean;
      hosting?: boolean;
    }>(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,zip,timezone,lat,lon,isp,org,as,reverse,proxy,hosting`,
      6000,
    );
    if (ipApi?.status === 'success' && typeof ipApi.lat === 'number' && typeof ipApi.lon === 'number') {
      geo = {
        country: ipApi.country,
        countryCode: ipApi.countryCode,
        region: ipApi.regionName,
        city: ipApi.city,
        postal: ipApi.zip,
        timezone: ipApi.timezone,
        lat: ipApi.lat,
        lon: ipApi.lon,
        asn: ipApi.as,
        isp: ipApi.isp,
        org: ipApi.org,
        reverse: ipApi.reverse,
        proxy: ipApi.proxy,
        hosting: ipApi.hosting,
      };
    }
  }

  if (!geo) return null;

  const revAddr =
    typeof geo.lat === 'number' && typeof geo.lon === 'number'
      ? await reverseGeocodeAddress(geo.lat, geo.lon)
      : null;

  const hasFeedDanger = feedMatches.length > 0;
  const hasKnownVulns = (shodan?.vulns.length ?? 0) > 0;
  const severity = hasFeedDanger
    ? 'CRITICAL'
    : isTorExit || hasKnownVulns
      ? 'ELEVATED'
      : 'CLEAN';

  return {
    id: `trace-${ip}`,
    ip,
    threatType: hasFeedDanger
      ? feedMatches.map((m) => m.feed).join(' + ')
      : isTorExit
        ? 'Tor Network Exit Node'
        : hasKnownVulns
          ? `Host Exposes ${shodan!.vulns.length} Known CVEs`
          : 'Attributed Network Host',
    sourceFeed: 'Live Attribution',
    severity,
    country: geo.country || revAddr?.country || 'Unknown',
    countryCode: geo.countryCode || revAddr?.countryCode || 'XX',
    city: geo.city || revAddr?.city || 'Unknown',
    region: geo.region,
    postal: geo.postal || revAddr?.postal,
    physicalAddress:
      revAddr?.displayAddress ||
      [geo.city, geo.region, geo.postal, geo.country].filter(Boolean).join(', '),
    timezone: geo.timezone,
    lat: geo.lat ?? 0,
    lon: geo.lon ?? 0,
    asn: geo.asn || 'Unknown ASN',
    isp: geo.isp || 'Unknown ISP',
    org: geo.org || geo.isp || 'Unknown Organization',
    reverse: geo.reverse || ptr[0] || shodan?.hostnames[0] || undefined,
    isProxy: geo.proxy || shodan?.tags.includes('vpn'),
    isHosting: geo.hosting || shodan?.tags.includes('cloud'),
    isTorExit,
    openPorts: shodan?.ports,
    knownVulns: shodan?.vulns,
    cpes: shodan?.cpes,
    shodanTags: shodan?.tags,
  };
}
