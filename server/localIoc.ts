import fs from 'node:fs';
import path from 'node:path';
import { isValidIpv4 } from './threatRules.ts';

export type IocType = 'ip' | 'cidr' | 'domain';

export interface IocEntry {
  value: string;
  type: IocType;
  tags: string[];
  source: string;
  addedAt?: string;
}

const DATA_DIR = path.resolve(process.cwd(), 'data', 'intel');
const MANUAL_FILE = path.join(DATA_DIR, 'manual.txt');
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function ensureDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function classify(value: string): IocType | null {
  if (value.includes('/')) {
    const [ip, bits] = value.split('/');
    const prefix = Number(bits);
    return isValidIpv4(ip) && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32
      ? 'cidr'
      : null;
  }
  if (isValidIpv4(value)) return 'ip';
  if (DOMAIN_RE.test(value)) return 'domain';
  return null;
}

function ipToInt(ip: string): number {
  return ip.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [network, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!isValidIpv4(ip) || !isValidIpv4(network) || !Number.isInteger(bits)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(network) & mask);
}

function parseLine(line: string, source: string): IocEntry | null {
  const clean = line.split('#')[0].trim();
  if (!clean) return null;
  const parts = clean.split(/[\s,;\t]+/).filter(Boolean);
  const value = parts[0].toLowerCase();
  const type = classify(value);
  if (!type) return null;
  return {
    value,
    type,
    tags: parts.slice(1).map((tag) => tag.toLowerCase()),
    source,
  };
}

class LocalIocStore {
  private entries: IocEntry[] = [];
  private ipIndex = new Map<string, IocEntry>();
  private cidrEntries: IocEntry[] = [];
  private domainIndex = new Map<string, IocEntry>();
  private loadedAt = 0;

  constructor() {
    this.reload();
  }

  reload(): void {
    ensureDir();
    const entries: IocEntry[] = [];
    let files: string[] = [];
    try {
      files = fs
        .readdirSync(DATA_DIR)
        .filter((name) => /\.(txt|csv)$/i.test(name))
        .sort();
    } catch {
      files = [];
    }
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(DATA_DIR, file), 'utf8');
        for (const line of raw.split(/\r?\n/)) {
          const entry = parseLine(line, file);
          if (entry) entries.push(entry);
        }
      } catch {
        // A broken local feed must never stop the sensor.
      }
    }
    this.entries = entries;
    this.ipIndex.clear();
    this.domainIndex.clear();
    this.cidrEntries = [];
    for (const entry of entries) {
      if (entry.type === 'ip') this.ipIndex.set(entry.value, entry);
      else if (entry.type === 'cidr') this.cidrEntries.push(entry);
      else this.domainIndex.set(entry.value, entry);
    }
    this.loadedAt = Date.now();
  }

  lookupIp(ip: string): IocEntry[] {
    if (!isValidIpv4(ip)) return [];
    const matches: IocEntry[] = [];
    const exact = this.ipIndex.get(ip);
    if (exact) matches.push(exact);
    for (const entry of this.cidrEntries) {
      if (ipInCidr(ip, entry.value)) matches.push(entry);
    }
    return matches;
  }

  lookupDomain(host: string): IocEntry[] {
    const clean = host.toLowerCase().replace(/^www\./, '');
    const matches: IocEntry[] = [];
    const exact = this.domainIndex.get(clean);
    if (exact) matches.push(exact);
    for (const [domain, entry] of this.domainIndex) {
      if (clean.endsWith(`.${domain}`)) matches.push(entry);
    }
    return matches;
  }

  all(): IocEntry[] {
    return [...this.entries];
  }

  stats(): { files: number; entries: number; ips: number; cidrs: number; domains: number; loadedAt: string } {
    let files = 0;
    try {
      files = fs.readdirSync(DATA_DIR).filter((name) => /\.(txt|csv)$/i.test(name)).length;
    } catch {
      files = 0;
    }
    return {
      files,
      entries: this.entries.length,
      ips: this.ipIndex.size,
      cidrs: this.cidrEntries.length,
      domains: this.domainIndex.size,
      loadedAt: new Date(this.loadedAt).toISOString(),
    };
  }

  add(value: string, tags: string[] = []): { ok: boolean; error?: string; entry?: IocEntry } {
    const normalized = value.trim().toLowerCase();
    const type = classify(normalized);
    if (!type) return { ok: false, error: 'Expected a public IPv4, CIDR or domain.' };
    if (this.entries.some((entry) => entry.value === normalized)) {
      return { ok: false, error: 'Indicator already exists.' };
    }
    ensureDir();
    const line = [normalized, ...tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean)].join(',');
    fs.appendFileSync(MANUAL_FILE, `${line}\n`, 'utf8');
    const entry: IocEntry = {
      value: normalized,
      type,
      tags,
      source: 'manual.txt',
      addedAt: new Date().toISOString(),
    };
    this.reload();
    return { ok: true, entry };
  }

  remove(value: string): boolean {
    const normalized = value.trim().toLowerCase();
    if (!fs.existsSync(MANUAL_FILE)) return false;
    const lines = fs.readFileSync(MANUAL_FILE, 'utf8').split(/\r?\n/);
    const next = lines.filter((line) => parseLine(line, 'manual.txt')?.value !== normalized);
    if (next.length === lines.length) return false;
    fs.writeFileSync(MANUAL_FILE, next.join('\n'), 'utf8');
    this.reload();
    return true;
  }
}

export const localIoc = new LocalIocStore();
