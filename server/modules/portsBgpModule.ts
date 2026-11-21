import type { BgpRouteProfile, CveDetailRecord, ThreatNode } from '../../src/types/cyber.ts';
import { traceAttackerIp } from '../ipAttribution.ts';
import { parseMitreCveRecord, parseRipeStatPrefix } from '../osintParsers.ts';
import { isValidIpv4 } from '../threatRules.ts';
import { fetchJsonWithTimeout, resolveDnsRecord, type ScanModulePlugin } from './types.ts';

export async function fetchBgpRouteProfile(ip: string): Promise<BgpRouteProfile | null> {
  if (!isValidIpv4(ip)) return null;
  const json = await fetchJsonWithTimeout<unknown>(
    `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`,
    5500,
  );
  return json ? parseRipeStatPrefix(json) : null;
}

export async function fetchMitreCveDetail(cveId: string): Promise<CveDetailRecord | null> {
  const cleanId = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cleanId)) return null;
  const json = await fetchJsonWithTimeout<unknown>(
    `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cleanId)}`,
    6000,
  );
  return json ? parseMitreCveRecord(json) : null;
}

export const portsBgpModule: ScanModulePlugin = {
  id: 'portsBgp',
  label: 'IP Attribution, BGP Routing & Exposed Ports',
  isActive: false,
  supportsTargetType: (t) => t === 'ip' || t === 'domain' || t === 'url',
  async run(ctx) {
    let targetIps: string[] = [];
    if (ctx.targetType === 'ip') {
      targetIps = [ctx.host];
    } else {
      const candidateA =
        ctx.dns.a.length > 0 ? ctx.dns.a : await resolveDnsRecord(ctx.host, 'A');
      targetIps = candidateA.filter((ip) => isValidIpv4(ip)).slice(0, 3);
    }

    if (targetIps.length === 0) {
      ctx.log('No public IPv4 address available for BGP attribution', 'warn', 'portsBgp');
      return;
    }

    ctx.log(`Attributing ${targetIps.join(', ')} via Shodan InternetDB, RDAP and RIPE Stat`, 'info', 'portsBgp');
    const [attributionResults, bgpProfile] = await Promise.all([
      Promise.all(targetIps.map((ip) => traceAttackerIp(ip))),
      fetchBgpRouteProfile(targetIps[0]),
    ]);

    ctx.attribution = attributionResults.filter((n): n is ThreatNode => n !== null);
    ctx.bgpProfile = bgpProfile;

    for (const node of ctx.attribution) {
      ctx.log(
        `${node.ip} · ${node.city || 'Unknown'}, ${node.country || 'Unknown'} · ${node.asn} · ${node.isp}`,
        'success',
        'portsBgp',
      );
      if ((node.openPorts?.length ?? 0) > 0) {
        ctx.log(
          `Passive port telemetry for ${node.ip}: ${node.openPorts!.join(', ')}`,
          'info',
          'portsBgp',
        );
      }
    }
    if (ctx.bgpProfile) {
      ctx.log(
        `BGP prefix ${ctx.bgpProfile.prefix} announced by ${ctx.bgpProfile.asns.map((a) => `AS${a.asn}`).join(', ') || 'unknown ASN'}`,
        'info',
        'portsBgp',
      );
    }

    const allVulns = Array.from(
      new Set(ctx.attribution.flatMap((a) => a.knownVulns ?? [])),
    );
    if (ctx.targetType === 'ip' && allVulns.length > 0) {
      ctx.heuristicWarnings.push(`Host exposes ${allVulns.length} known CVEs`);
    }

    if (allVulns.length > 0) {
      const cveDetailsRaw = await Promise.all(
        allVulns.slice(0, 3).map((cve) => fetchMitreCveDetail(cve)),
      );
      ctx.cveDetails = cveDetailsRaw.filter((c): c is CveDetailRecord => c !== null);
    }
  },
};
