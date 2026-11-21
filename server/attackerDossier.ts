import { createHash } from 'node:crypto';
import type { AttackEvent } from '../src/types/defenseGrid.ts';
import type { ThreatActorExternalIntel, ThreatNode } from '../src/types/cyber.ts';
import { listAttackEvents } from './db.ts';
import { traceAttackerIp } from './ipAttribution.ts';
import { localIoc } from './localIoc.ts';
import { collectExternalIntel } from './externalIntel.ts';
import { lookupAsn, lookupGeo, lookupPtr, lookupWhoisIp } from './nativeIntel.ts';
import { isValidIpv4 } from './threatRules.ts';

export interface DossierEvidence {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: 'High' | 'Medium' | 'Low';
  detail: string;
}

export interface AttackerDossier {
  ip: string;
  generatedAt: string;
  attribution: ThreatNode;
  whois: {
    orgName?: string;
    handle?: string;
    cidr?: string;
    abuseEmails: string[];
    server?: string;
  };
  asn: {
    asn?: string;
    prefix?: string;
    registry?: string;
    holder?: string;
  };
  geo: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
  };
  reverseDns?: string;
  externalIntel: ThreatActorExternalIntel;
  localIoc: Array<{ value: string; tags: string[]; source: string }>;
  observedAttacks: {
    count: number;
    firstSeen?: string;
    lastSeen?: string;
    categories: Record<string, number>;
    severities: Record<string, number>;
    events: Array<{
      ts: string;
      method: string;
      path: string;
      category: string;
      severity: string;
      action: string;
      detail: string;
      userAgent?: string;
      ja3?: string;
      tlsh?: string;
    }>;
  };
  risk: {
    score: number;
    severity: 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'CLEAN';
    factors: string[];
  };
  evidence: DossierEvidence[];
  forensic: {
    sha256: string;
    sources: string[];
    limitations: string[];
    chainOfCustody: string;
  };
  reportText: string;
  reportHtml: string;
}

function countBy<T extends string>(values: T[]): Record<string, number> {
  return values.reduce<Record<string, number>>((acc, value) => {
    acc[value] = (acc[value] ?? 0) + 1;
    return acc;
  }, {});
}

function riskScore(
  node: ThreatNode,
  events: AttackEvent[],
  tags: string[],
  external?: ThreatActorExternalIntel,
): { score: number; factors: string[] } {
  const factors: string[] = [];
  let score = 10;
  if (node.severity === 'CRITICAL') {
    score += 45;
    factors.push('Attribution severity is CRITICAL');
  } else if (node.severity === 'HIGH') {
    score += 30;
    factors.push('Attribution severity is HIGH');
  } else if (node.severity === 'ELEVATED') {
    score += 15;
    factors.push('Attribution severity is ELEVATED');
  }
  if (events.length > 0) {
    const bump = Math.min(25, 5 + Math.floor(events.length / 5) * 5);
    score += bump;
    factors.push(`${events.length} observed sensor event(s)`);
  }
  if (tags.includes('c2') || tags.includes('botnet')) {
    score += 20;
    factors.push('Local IOC tags include command-and-control / botnet');
  }
  if (tags.includes('tor')) {
    score += 10;
    factors.push('Tor exit node');
  }
  if (node.isHosting) {
    score += 5;
    factors.push('Hosting / data-centre ASN');
  }
  if (node.abuseEmails?.length) {
    factors.push('Published WHOIS abuse contact available');
  }
  const shodanVulns = external?.shodan?.vulns.length ?? 0;
  if (shodanVulns > 0) {
    score += Math.min(20, 5 + shodanVulns * 2);
    factors.push(`${shodanVulns} exposed CVE(s) on public Shodan InternetDB`);
  }
  const pulseCount = external?.otx.pulseCount ?? 0;
  if (pulseCount > 0) {
    score += Math.min(25, 8 + pulseCount);
    factors.push(`${pulseCount} AlienVault OTX threat pulse(s)`);
  }
  const families = external?.otx.malwareFamilies ?? [];
  if (families.length > 0) {
    score += 10;
    factors.push(`Malware family correlation: ${families.slice(0, 4).join(', ')}`);
  }
  if ((external?.otx.passiveDns.length ?? 0) > 5) {
    score += 5;
    factors.push('Large passive-DNS history');
  }
  return { score: Math.min(100, score), factors };
}

function severityForScore(score: number): AttackerDossier['risk']['severity'] {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'ELEVATED';
  return 'CLEAN';
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderText(input: Omit<AttackerDossier, 'reportText' | 'reportHtml'>): string {
  const node = input.attribution;
  const lines = [
    'SentinelGlobe — Forensic Attacker Dossier',
    '='.repeat(52),
    `Generated: ${input.generatedAt}`,
    `Subject IP: ${input.ip}`,
    `Risk score: ${input.risk.score}/100 (${input.risk.severity})`,
    '',
    '1. NETWORK ATTRIBUTION',
    `ASN: ${input.asn.asn ?? node.asn ?? 'unknown'}`,
    `AS holder: ${input.asn.holder ?? node.isp ?? 'unknown'}`,
    `Announced prefix: ${input.asn.prefix ?? input.whois.cidr ?? node.cidr ?? 'unknown'}`,
    `RIR: ${input.asn.registry ?? 'unknown'}`,
    `Reverse DNS: ${input.reverseDns ?? 'none'}`,
    `Country: ${input.geo.country ?? node.country ?? 'unknown'} (${input.geo.countryCode ?? node.countryCode ?? 'XX'})`,
    `City / region: ${[input.geo.city ?? node.city, input.geo.region ?? node.region].filter(Boolean).join(', ') || 'unknown'}`,
    `Coordinates: ${input.geo.lat ?? node.lat ?? 0}, ${input.geo.lon ?? node.lon ?? 0} (approximate network geolocation)`,
    `Timezone: ${input.geo.timezone ?? node.timezone ?? 'unknown'}`,
    '',
    '2. WHOIS / ABUSE CONTACT',
    `Organisation: ${input.whois.orgName ?? node.org ?? 'unknown'}`,
    `Handle: ${input.whois.handle ?? 'unknown'}`,
    `CIDR: ${input.whois.cidr ?? 'unknown'}`,
    `Abuse contacts: ${input.whois.abuseEmails.join(', ') || 'not published'}`,
    '',
    '3. LOCAL IOC / SENSOR EVIDENCE',
    `Local IOC tags: ${input.localIoc.flatMap((entry) => entry.tags).join(', ') || 'none'}`,
    `Observed attacks: ${input.observedAttacks.count}`,
    `First seen: ${input.observedAttacks.firstSeen ?? 'n/a'}`,
    `Last seen: ${input.observedAttacks.lastSeen ?? 'n/a'}`,
    `Categories: ${Object.entries(input.observedAttacks.categories).map(([key, value]) => `${key}=${value}`).join(', ') || 'none'}`,
    '',
    '4. RECENT EVENTS (MAX 20)',
    ...input.observedAttacks.events.slice(0, 20).map(
      (event) =>
        `- ${event.ts} | ${event.severity} | ${event.category} | ${event.method} ${event.path} | ${event.action} | ${event.detail}`,
    ),
    '',
    '5. RISK FACTORS',
    ...(input.risk.factors.length ? input.risk.factors.map((factor) => `- ${factor}`) : ['- No elevated factor']),
    '',
    '6. EVIDENCE INTEGRITY',
    `SHA-256: ${input.forensic.sha256}`,
    `Sources: ${input.forensic.sources.join('; ')}`,
    `Chain of custody: ${input.forensic.chainOfCustody}`,
    '',
    '7. LIMITATIONS',
    ...input.forensic.limitations.map((line) => `- ${line}`),
    '',
    'LEGAL NOTICE',
    'This dossier is technical incident evidence. IP geolocation is approximate and does not identify a natural person. Do not use it for vigilante action, doxxing, or unauthorized access. Send it only to the affected organisation and the responsible network abuse contact.',
  ];
  return lines.join('\n');
}

function renderHtml(input: Omit<AttackerDossier, 'reportText' | 'reportHtml'>): string {
  const node = input.attribution;
  const rows = [
    ['Subject IP', input.ip],
    ['Risk', `${input.risk.score}/100 (${input.risk.severity})`],
    ['ASN', input.asn.asn ?? node.asn],
    ['AS holder', input.asn.holder ?? node.isp],
    ['Prefix', input.asn.prefix ?? input.whois.cidr ?? node.cidr],
    ['Reverse DNS', input.reverseDns],
    ['Country', `${input.geo.country ?? node.country} (${input.geo.countryCode ?? node.countryCode})`],
    ['City / region', [input.geo.city ?? node.city, input.geo.region ?? node.region].filter(Boolean).join(', ')],
    ['Coordinates', `${input.geo.lat ?? node.lat}, ${input.geo.lon ?? node.lon}`],
    ['WHOIS organisation', input.whois.orgName ?? node.org],
    ['Abuse contacts', input.whois.abuseEmails.join(', ')],
  ]
    .map(([label, value]) => `<tr><th>${escapeHtml(String(label))}</th><td>${escapeHtml(String(value ?? 'unknown'))}</td></tr>`)
    .join('');
  const events = input.observedAttacks.events
    .slice(0, 20)
    .map(
      (event) =>
        `<tr><td>${escapeHtml(event.ts)}</td><td>${escapeHtml(event.severity)}</td><td>${escapeHtml(event.category)}</td><td>${escapeHtml(`${event.method} ${event.path}`)}</td><td>${escapeHtml(event.detail)}</td></tr>`,
    )
    .join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Attacker dossier ${escapeHtml(input.ip)}</title>
<style>body{font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0;padding:28px}h1{font-size:20px}h2{font-size:14px;margin-top:24px;color:#67e8f9}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #1e293b;padding:6px 8px;text-align:left;vertical-align:top}th{width:180px;color:#94a3b8}code{color:#fbbf24}.note{border-left:3px solid #f59e0b;padding:10px;background:#1c1917;font-size:11px}</style></head><body>
<h1>SentinelGlobe — Forensic Attacker Dossier</h1>
<p>Generated ${escapeHtml(input.generatedAt)} · SHA-256 <code>${escapeHtml(input.forensic.sha256)}</code></p>
<h2>Network attribution</h2><table>${rows}</table>
<h2>Observed sensor events</h2><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Request</th><th>Detail</th></tr></thead><tbody>${events || '<tr><td colspan="5">No local sensor events for this IP.</td></tr>'}</tbody></table>
<h2>Risk factors</h2><ul>${input.risk.factors.map((factor) => `<li>${escapeHtml(factor)}</li>`).join('') || '<li>No elevated factor</li>'}</ul>
<h2>Sources</h2><p>${input.forensic.sources.map(escapeHtml).join('; ')}</p>
<div class="note"><b>Limitations:</b> ${input.forensic.limitations.map(escapeHtml).join(' ')}</div>
</body></html>`;
}

export async function buildAttackerDossier(ip: string): Promise<AttackerDossier> {
  if (!isValidIpv4(ip)) throw new Error('Valid IPv4 address required.');
  const [attribution, geo, asn, reverseDns, whois, events, externalIntel] = await Promise.all([
    traceAttackerIp(ip, { includeWhois: true }),
    lookupGeo(ip),
    lookupAsn(ip),
    lookupPtr(ip),
    lookupWhoisIp(ip).catch(() => null),
    Promise.resolve(listAttackEvents({ ip, limit: 200 })),
    collectExternalIntel(ip).catch(() => ({
      generatedAt: new Date().toISOString(),
      sources: [],
      shodan: undefined,
      otx: {
        pulseCount: 0,
        pulses: [],
        validation: [],
        passiveDns: [],
        malware: [],
        urls: [],
        tags: [],
        malwareFamilies: [],
      },
    })),
  ]);
  if (!attribution) throw new Error('No native attribution data is available for this IP.');

  const tags = localIoc.lookupIp(ip);
  const localTags = Array.from(new Set(tags.flatMap((entry) => entry.tags)));
  const risk = riskScore(attribution, events, localTags, externalIntel);
  const evidence: DossierEvidence[] = [
    {
      id: 'geo-offline',
      type: 'network-geolocation',
      value: `${geo?.country ?? 'unknown'} / ${geo?.city ?? 'unknown'} / ${geo?.lat ?? 0},${geo?.lon ?? 0}`,
      source: 'Offline GeoIP database (geoip-lite)',
      confidence: 'Medium',
      detail: 'City-level network location, not a physical address of a person.',
    },
    {
      id: 'asn-cymru',
      type: 'asn-and-prefix',
      value: `${asn?.asn ?? 'unknown'} ${asn?.prefix ?? ''} ${asn?.holder ?? ''}`.trim(),
      source: 'Team Cymru DNS (origin.asn.cymru.com)',
      confidence: 'High',
      detail: 'BGP origin ASN and announced prefix resolved over DNS.',
    },
    {
      id: 'whois',
      type: 'whois-abuse-contact',
      value: whois?.abuseEmails.join(', ') || 'not published',
      source: `Native WHOIS (${whois?.server ?? 'RIR'})`,
      confidence: 'High',
      detail: 'Abuse contact published by the responsible RIR.',
    },
    {
      id: 'shodan-internetdb',
      type: 'public-exposure',
      value: `${externalIntel.shodan?.ports.length ?? 0} port(s), ${externalIntel.shodan?.vulns.length ?? 0} CVE(s)`,
      source: 'Shodan InternetDB (public, no key)',
      confidence: 'Medium',
      detail: 'Publicly indexed services and vulnerabilities; not an intrusive scan.',
    },
    {
      id: 'otx-pulses',
      type: 'threat-intelligence',
      value: `${externalIntel.otx.pulseCount} pulse(s), ${externalIntel.otx.malwareFamilies.length} malware family tag(s)`,
      source: 'AlienVault OTX public API',
      confidence: 'Medium',
      detail: 'Community threat pulses, passive DNS and historical URL observations.',
    },
    {
      id: 'sensor-events',
      type: 'local-sensor-evidence',
      value: `${events.length} event(s)`,
      source: 'SentinelGlobe local attack sensor / SQLite',
      confidence: 'High',
      detail: 'Requests observed by this deployment. Evidence is local and timestamped.',
    },
  ];

  const base = {
    ip,
    generatedAt: new Date().toISOString(),
    attribution,
    whois: {
      orgName: whois?.orgName ?? attribution.org,
      handle: whois?.handle,
      cidr: whois?.cidr ?? asn?.prefix ?? attribution.cidr,
      abuseEmails: whois?.abuseEmails ?? attribution.abuseEmails ?? [],
      server: whois?.server,
    },
    asn: {
      asn: asn?.asn,
      prefix: asn?.prefix,
      registry: asn?.registry,
      holder: asn?.holder,
    },
    geo: {
      country: geo?.country ?? attribution.country,
      countryCode: geo?.countryCode ?? attribution.countryCode,
      region: geo?.region ?? attribution.region,
      city: geo?.city ?? attribution.city,
      lat: geo?.lat ?? attribution.lat,
      lon: geo?.lon ?? attribution.lon,
      timezone: geo?.timezone ?? attribution.timezone,
    },
    reverseDns,
    externalIntel,
    localIoc: tags.map((entry) => ({ value: entry.value, tags: entry.tags, source: entry.source })),
    observedAttacks: {
      count: events.length,
      firstSeen: events.length ? events[events.length - 1].ts : undefined,
      lastSeen: events.length ? events[0].ts : undefined,
      categories: countBy(events.map((event) => event.category)),
      severities: countBy(events.map((event) => event.severity)),
      events: events.map((event) => ({
        ts: event.ts,
        method: event.method,
        path: event.path,
        category: event.category,
        severity: event.severity,
        action: event.action,
        detail: event.detail,
        userAgent: event.userAgent,
        ja3: event.ja3,
        tlsh: event.tlsh,
      })),
    },
    risk: { ...risk, severity: severityForScore(risk.score) },
    evidence,
  } satisfies Omit<AttackerDossier, 'forensic' | 'reportText' | 'reportHtml'>;

  const hashInput = JSON.stringify(base);
  const sha256 = createHash('sha256').update(hashInput).digest('hex');
  const forensic: AttackerDossier['forensic'] = {
    sha256,
    sources: [
      'Offline GeoIP database',
      'Team Cymru DNS ASN/prefix',
      'Native RIR WHOIS over TCP/43',
      'SentinelGlobe local attack sensor',
      'SentinelGlobe local IOC store',
      'Shodan InternetDB public exposure index',
      'AlienVault OTX public threat intelligence',
    ],
    limitations: [
      'IP geolocation is approximate and cannot identify a natural person.',
      'NAT, VPN, Tor, proxy and cloud hosting can hide the real device or operator.',
      'WHOIS abuse contacts are for network abuse reporting, not personal identification.',
      'Do not take vigilante action or access third-party systems without written authorization.',
    ],
    chainOfCustody: `Generated locally at ${base.generatedAt}; evidence hash computed over the JSON dossier before rendering.`,
  };

  const withForensic = { ...base, forensic } satisfies Omit<AttackerDossier, 'reportText' | 'reportHtml'>;
  return {
    ...withForensic,
    reportText: renderText(withForensic),
    reportHtml: renderHtml(withForensic),
  };
}
