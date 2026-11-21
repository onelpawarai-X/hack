import type {
  BgpRouteProfile,
  CveDetailRecord,
  RdapDomainProfile,
  WaybackArchiveProfile,
} from '../src/types/cyber.ts';

const MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'com.bd',
  'org.bd',
  'gov.bd',
  'edu.bd',
  'net.bd',
  'co.in',
  'co.jp',
  'co.kr',
  'com.br',
  'com.sg',
]);

export function extractRootDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '').trim();
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

export function extractCertSpotterSubdomains(rawJson: unknown, rootDomain: string): string[] {
  if (!Array.isArray(rawJson)) return [];
  const target = rootDomain.toLowerCase();
  const set = new Set<string>();

  for (const row of rawJson) {
    const names = (row as { dns_names?: unknown })?.dns_names;
    if (!Array.isArray(names)) continue;
    for (const rawName of names) {
      if (typeof rawName !== 'string') continue;
      const cleaned = rawName.toLowerCase().replace(/^\*\./, '').trim();
      if (!cleaned) continue;
      if (cleaned === target || cleaned.endsWith(`.${target}`)) {
        set.add(cleaned);
      }
      if (set.size >= 80) break;
    }
    if (set.size >= 80) break;
  }

  return Array.from(set).sort((a, b) => a.localeCompare(b)).slice(0, 60);
}

export function parseMitreCveRecord(rawJson: unknown): CveDetailRecord | null {
  const root = rawJson as {
    cveMetadata?: { cveId?: string; datePublished?: string };
    containers?: {
      cna?: {
        title?: string;
        descriptions?: Array<{ lang?: string; value?: string }>;
        metrics?: Array<Record<string, unknown>>;
        problemTypes?: Array<{
          descriptions?: Array<{ cweId?: string; description?: string }>;
        }>;
        affected?: Array<{
          vendor?: string;
          product?: string;
          packageName?: string;
        }>;
        references?: Array<{ url?: string }>;
      };
    };
  };

  const cveId = root?.cveMetadata?.cveId;
  const cna = root?.containers?.cna;
  if (!cveId || !cna) return null;

  const enDesc =
    cna.descriptions?.find((d) => String(d.lang ?? '').toLowerCase().startsWith('en'))?.value ||
    cna.descriptions?.[0]?.value ||
    '';

  let cvssScore: number | undefined;
  let cvssSeverity: string | undefined;
  let cvssVector: string | undefined;

  for (const m of cna.metrics ?? []) {
    const v4 = m.cvssV4_0 as { baseScore?: number; baseSeverity?: string; vectorString?: string } | undefined;
    const v31 = m.cvssV3_1 as { baseScore?: number; baseSeverity?: string; vectorString?: string } | undefined;
    const v30 = m.cvssV3_0 as { baseScore?: number; baseSeverity?: string; vectorString?: string } | undefined;
    const v2 = m.cvssV2_0 as { baseScore?: number; vectorString?: string } | undefined;

    const chosen = v4 ?? v31 ?? v30;
    if (chosen && typeof chosen.baseScore === 'number') {
      cvssScore = chosen.baseScore;
      cvssSeverity = chosen.baseSeverity;
      cvssVector = chosen.vectorString;
      break;
    }
    if (v2 && typeof v2.baseScore === 'number' && cvssScore === undefined) {
      cvssScore = v2.baseScore;
      cvssVector = v2.vectorString;
      cvssSeverity = v2.baseScore >= 7 ? 'HIGH' : v2.baseScore >= 4 ? 'MEDIUM' : 'LOW';
    }
  }

  const cwes: string[] = [];
  for (const pt of cna.problemTypes ?? []) {
    for (const d of pt.descriptions ?? []) {
      const label = [d.cweId, d.description].filter(Boolean).join(': ');
      if (label && !cwes.includes(label)) cwes.push(label);
    }
  }

  const affectedProducts: string[] = [];
  for (const aff of cna.affected ?? []) {
    const label = [aff.vendor, aff.product || aff.packageName].filter(Boolean).join(' / ');
    if (label && !affectedProducts.includes(label)) affectedProducts.push(label);
  }

  const references = (cna.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === 'string' && /^https?:\/\//i.test(u))
    .slice(0, 6);

  return {
    cveId,
    title: cna.title?.trim() || `${cveId} Security Advisory`,
    description: enDesc.trim(),
    cvssScore,
    cvssSeverity,
    cvssVector,
    cwes: cwes.slice(0, 4),
    affectedProducts: affectedProducts.slice(0, 6),
    publishedDate: root.cveMetadata?.datePublished,
    references,
  };
}

export function parseRdapDomainProfile(rawJson: unknown): RdapDomainProfile | null {
  const doc = rawJson as {
    status?: string[];
    events?: Array<{ eventAction?: string; eventDate?: string }>;
    secureDNS?: { delegationSigned?: boolean };
    entities?: Array<{
      roles?: string[];
      vcardArray?: unknown[];
      entities?: Array<{ vcardArray?: unknown[] }>;
    }>;
  };
  if (!doc || typeof doc !== 'object') return null;

  const findEventDate = (action: string): string | undefined => {
    const ev = (doc.events ?? []).find(
      (e) => String(e.eventAction ?? '').toLowerCase() === action.toLowerCase(),
    );
    return ev?.eventDate;
  };

  let registrar: string | undefined;
  const registrarEntity = (doc.entities ?? []).find((e) =>
    Array.isArray(e.roles) && e.roles.includes('registrar'),
  );
  if (registrarEntity && Array.isArray(registrarEntity.vcardArray?.[1])) {
    const vcardRows = registrarEntity.vcardArray[1] as Array<unknown[]>;
    const fnRow = vcardRows.find((r) => Array.isArray(r) && r[0] === 'fn');
    if (fnRow && typeof fnRow[3] === 'string' && fnRow[3].trim()) {
      registrar = fnRow[3].trim();
    }
  }

  const rawText = JSON.stringify(doc);
  const emails = Array.from(
    new Set((rawText.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []).map((e) => e.toLowerCase())),
  ).slice(0, 4);

  return {
    registrar,
    registrationDate: findEventDate('registration'),
    expirationDate: findEventDate('expiration'),
    lastChangedDate: findEventDate('last changed'),
    dnssecSigned:
      typeof doc.secureDNS?.delegationSigned === 'boolean'
        ? doc.secureDNS.delegationSigned
        : undefined,
    statuses: Array.isArray(doc.status) ? doc.status.slice(0, 6) : [],
    abuseEmails: emails,
  };
}

export function parseRipeStatPrefix(rawJson: unknown): BgpRouteProfile | null {
  const doc = rawJson as {
    status?: string;
    data?: {
      resource?: string;
      announced?: boolean;
      asns?: Array<{ asn?: number; holder?: string }>;
      block?: { desc?: string };
    };
  };
  const data = doc?.data;
  if (!data?.resource) return null;

  return {
    prefix: data.resource,
    announced: Boolean(data.announced),
    asns: Array.isArray(data.asns)
      ? data.asns
          .filter((a) => typeof a.asn === 'number')
          .map((a) => ({
            asn: a.asn!,
            holder: String(a.holder ?? 'Unknown Holder'),
          }))
      : [],
    rirBlock: data.block?.desc,
  };
}

function formatWaybackTs(ts: string): string | undefined {
  if (!/^\d{8,14}$/.test(ts)) return undefined;
  return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
}

export function parseWaybackCdx(
  oldestRows: unknown,
  latestRows: unknown,
  domain: string,
): WaybackArchiveProfile | null {
  const extractTs = (rows: unknown): string | undefined => {
    if (!Array.isArray(rows) || rows.length < 2) return undefined;
    const row = rows[1] as unknown[];
    return typeof row?.[0] === 'string' ? formatWaybackTs(row[0]) : undefined;
  };

  const firstSnapshot = extractTs(oldestRows);
  const latestSnapshot = extractTs(latestRows) ?? firstSnapshot;
  if (!firstSnapshot && !latestSnapshot) return null;

  return {
    firstSnapshot,
    latestSnapshot,
    archiveUrl: `https://web.archive.org/web/*/${encodeURIComponent(domain)}`,
  };
}
