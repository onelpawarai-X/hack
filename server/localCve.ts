import fs from 'node:fs';
import path from 'node:path';
import type { CveDetailRecord, TechFingerprint } from '../src/types/cyber.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data', 'cve');

interface CustomCve {
  id?: string;
  cveId?: string;
  description?: string;
  title?: string;
  cvss?: number;
  cvssScore?: number;
  severity?: string;
  cvssSeverity?: string;
  vector?: string;
  cvssVector?: string;
  cwes?: string[];
  cpes?: string[];
  affectedProducts?: string[];
  published?: string;
  publishedDate?: string;
  references?: string[];
}

function normalizeCpe(value: string): string | null {
  const raw = value.trim();
  if (raw.startsWith('cpe:2.3:')) {
    const parts = raw.split(':');
    return parts.length >= 5 ? `${parts[3].toLowerCase()}:${parts[4].toLowerCase()}` : null;
  }
  if (raw.startsWith('cpe:/')) {
    const parts = raw.slice(5).split(':');
    return parts.length >= 3 ? `${parts[1].toLowerCase()}:${parts[2].toLowerCase()}` : null;
  }
  return null;
}

function fromCustom(row: CustomCve): CveDetailRecord | null {
  const cveId = (row.cveId ?? row.id ?? '').trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null;
  return {
    cveId,
    title: row.title ?? cveId,
    description: row.description ?? '',
    cvssScore: row.cvssScore ?? row.cvss,
    cvssSeverity: (row.cvssSeverity ?? row.severity)?.toUpperCase(),
    cvssVector: row.cvssVector ?? row.vector,
    cwes: row.cwes ?? [],
    affectedProducts: row.affectedProducts ?? row.cpes ?? [],
    publishedDate: row.publishedDate ?? row.published,
    references: row.references ?? [],
  };
}

function fromNvd(row: any): CveDetailRecord | null {
  const cve = row?.cve;
  const cveId = String(cve?.id ?? '').toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null;
  const descriptions = Array.isArray(cve?.descriptions) ? cve.descriptions : [];
  const description =
    descriptions.find((entry: any) => entry?.lang === 'en')?.value ?? descriptions[0]?.value ?? '';
  const metrics = cve?.metrics ?? {};
  const metric =
    metrics.cvssMetricV31?.[0] ??
    metrics.cvssMetricV30?.[0] ??
    metrics.cvssMetricV2?.[0] ??
    null;
  const cvssData = metric?.cvssData ?? {};
  const weaknesses = Array.isArray(cve?.weaknesses) ? cve.weaknesses : [];
  const cwes: string[] = Array.from(
    new Set<string>(
      weaknesses.flatMap((entry: any) =>
        (entry?.description ?? [])
          .map((desc: any) => String(desc?.value ?? ''))
          .filter((value: string) => value.startsWith('CWE-')),
      ),
    ),
  );
  const configurations = Array.isArray(cve?.configurations) ? cve.configurations : [];
  const cpes: string[] = [];
  const walk = (nodes: any[]) => {
    for (const node of nodes) {
      for (const match of node?.cpeMatch ?? []) {
        if (match?.criteria) cpes.push(String(match.criteria));
      }
      if (Array.isArray(node?.children)) walk(node.children);
    }
  };
  walk(configurations.flatMap((entry: any) => entry?.nodes ?? []));
  return {
    cveId,
    title: cveId,
    description,
    cvssScore: typeof cvssData.baseScore === 'number' ? cvssData.baseScore : undefined,
    cvssSeverity: cvssData.baseSeverity ? String(cvssData.baseSeverity).toUpperCase() : undefined,
    cvssVector: cvssData.vectorString ? String(cvssData.vectorString) : undefined,
    cwes,
    affectedProducts: Array.from(new Set(cpes)),
    publishedDate: cve?.published ? String(cve.published) : undefined,
    references: (cve?.references ?? []).map((ref: any) => String(ref?.url ?? '')).filter(Boolean),
  };
}

class LocalCveStore {
  private records: CveDetailRecord[] = [];
  private byId = new Map<string, CveDetailRecord>();
  private loadedAt = 0;

  constructor() {
    this.reload();
  }

  reload(): void {
    this.records = [];
    this.byId.clear();
    let files: string[] = [];
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      files = fs.readdirSync(DATA_DIR).filter((name) => name.endsWith('.json')).sort();
    } catch {
      files = [];
    }
    for (const file of files) {
      try {
        const parsed = JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf8'));
        const rows = Array.isArray(parsed)
          ? parsed
          : Array.isArray(parsed?.vulnerabilities)
            ? parsed.vulnerabilities
            : [];
        for (const row of rows) {
          const record = row?.cve ? fromNvd(row) : fromCustom(row);
          if (record) this.records.push(record);
        }
      } catch {
        // A malformed local CVE feed must not stop the scanner.
      }
    }
    this.records = Array.from(new Map(this.records.map((record) => [record.cveId, record])).values());
    this.byId = new Map(this.records.map((record) => [record.cveId, record]));
    this.loadedAt = Date.now();
  }

  lookupCve(cveId: string): CveDetailRecord | null {
    return this.byId.get(cveId.trim().toUpperCase()) ?? null;
  }

  lookupForStack(stack: TechFingerprint[]): CveDetailRecord[] {
    if (this.records.length === 0 || stack.length === 0) return [];
    const wanted = new Set(
      stack.flatMap((item) => [item.cpe, item.name.toLowerCase()]).filter(Boolean) as string[],
    );
    const wantedCpes = new Set(
      stack.map((item) => item.cpe).filter(Boolean).map((cpe) => normalizeCpe(String(cpe))).filter(Boolean) as string[],
    );
    return this.records.filter((record) => {
      for (const product of record.affectedProducts) {
        const cpe = normalizeCpe(product);
        if (cpe && wantedCpes.has(cpe)) return true;
        const lower = product.toLowerCase();
        for (const token of wanted) {
          if (lower.includes(token) || token.includes(lower)) return true;
        }
      }
      return false;
    });
  }

  stats(): { files: number; cves: number; loadedAt: string } {
    let files = 0;
    try {
      files = fs.readdirSync(DATA_DIR).filter((name) => name.endsWith('.json')).length;
    } catch {
      files = 0;
    }
    return { files, cves: this.records.length, loadedAt: new Date(this.loadedAt).toISOString() };
  }
}

export const localCve = new LocalCveStore();
