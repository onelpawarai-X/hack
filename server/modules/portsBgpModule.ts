import type { BgpRouteProfile, CveDetailRecord, ThreatNode } from '../../src/types/cyber.ts';
import { traceAttackerIp } from '../ipAttribution.ts';
import { localCve } from '../localCve.ts';
import { lookupWhoisIp } from '../nativeIntel.ts';
import { isValidIpv4 } from '../threatRules.ts';
import { resolveDnsRecord, type ScanModulePlugin } from './types.ts';

export async function fetchBgpRouteProfile(ip: string): Promise<BgpRouteProfile | null> {
  if (!isValidIpv4(ip)) return null;
  const { lookupAsn } = await import('../nativeIntel.ts');
  const asn = await lookupAsn(ip);
  if (!asn?.prefix) return null;
  return {
    prefix: asn.prefix,
    announced: true,
    asns: asn.asn
      ? [{ asn: Number(asn.asn.replace(/^AS/i, '')), holder: asn.holder ?? 'Unknown holder' }]
      : [],
    rirBlock: asn.registry,
  };
}

export async function fetchMitreCveDetail(cveId: string): Promise<CveDetailRecord | null> {
  return localCve.lookupCve(cveId);
}

export const portsBgpModule: ScanModulePlugin = {
  id: 'portsBgp',
  label: 'IP Attribution, ASN Routing & WHOIS',
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
      ctx.log('No public IPv4 address available for ASN attribution', 'warn', 'portsBgp');
      return;
    }

    ctx.log(
      `Attributing ${targetIps.join(', ')} via offline GeoIP, Team Cymru DNS and native WHOIS`,
      'info',
      'portsBgp',
    );
    const [attributionResults, bgpProfile] = await Promise.all([
      Promise.all(targetIps.map((ip) => traceAttackerIp(ip))),
      fetchBgpRouteProfile(targetIps[0]),
    ]);

    const nodes = attributionResults.filter((n): n is ThreatNode => n !== null);
    if (nodes[0]) {
      const whois = await lookupWhoisIp(nodes[0].ip).catch(() => null);
      if (whois) {
        nodes[0].abuseEmails = whois.abuseEmails;
        nodes[0].cidr = nodes[0].cidr ?? whois.cidr;
        nodes[0].org = whois.orgName ?? nodes[0].org;
      }
    }
    ctx.attribution = nodes;
    ctx.bgpProfile = bgpProfile;

    for (const node of ctx.attribution) {
      ctx.log(
        `${node.ip} · ${node.city || 'Unknown'}, ${node.country || 'Unknown'} · ${node.asn} · ${node.isp}`,
        'success',
        'portsBgp',
      );
      if (node.abuseEmails?.length) {
        ctx.log(`WHOIS abuse contact: ${node.abuseEmails.join(', ')}`, 'info', 'portsBgp');
      }
    }
    if (ctx.bgpProfile) {
      ctx.log(
        `BGP prefix ${ctx.bgpProfile.prefix} announced by ${ctx.bgpProfile.asns.map((a) => `AS${a.asn}`).join(', ') || 'unknown ASN'}`,
        'info',
        'portsBgp',
      );
    }

    const allVulns = Array.from(new Set(ctx.attribution.flatMap((a) => a.knownVulns ?? [])));
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
