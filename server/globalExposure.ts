import { promises as dns } from 'node:dns';
import { defenseEngine } from './defenseEngine.ts';
import { threatMonitor } from './threatMonitor.ts';

export interface GlobalExposureSite {
  domain: string;
  source: 'urlscan' | 'phishing-feed' | 'protected-site';
  url: string;
  status?: number;
  ip?: string;
  country?: string;
  asn?: string;
  asnName?: string;
  title?: string;
  tlsIssuer?: string;
  tlsValidDays?: number;
  domainAgeDays?: number;
  redirect?: string;
  labels: string[];
  securityHeaders: {
    hsts: boolean;
    csp: boolean;
    xFrameOptions: boolean;
    xContentTypeOptions: boolean;
    referrerPolicy: boolean;
    permissionsPolicy: boolean;
  };
  emailSecurity: {
    spf: boolean;
    dmarc: boolean;
  };
  issues: string[];
  risk: number;
  verdict: 'critical' | 'high' | 'medium' | 'low';
  checkedAt: string;
  error?: string;
}

export interface GlobalExposureSnapshot {
  generatedAt: string;
  lastRunAt: string | null;
  running: boolean;
  sources: Array<{ name: string; status: 'online' | 'degraded'; detail: string }>;
  coverage: {
    discovered: number;
    probed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  sites: GlobalExposureSite[];
}

const UA = 'SentinelGlobe/1.0 (public web-exposure audit; respectful single request per site)';
const MAX_SITES = Number(process.env.SENTINEL_EXPOSURE_BATCH) || 40;
const REFRESH_MS = Number(process.env.SENTINEL_EXPOSURE_REFRESH_MS) || 15 * 60 * 1000;
type DiscoveredSite = { domain: string; meta: Record<string, unknown> };

let snapshot: GlobalExposureSnapshot = {
  generatedAt: new Date().toISOString(),
  lastRunAt: null,
  running: false,
  sources: [],
  coverage: { discovered: 0, probed: 0, critical: 0, high: 0, medium: 0, low: 0 },
  sites: [],
};
let timer: NodeJS.Timeout | null = null;

function domainOf(value: string): string | null {
  try {
    const withScheme = /^https?:\/\//i.test(value) ? value : `https://${value}`;
    const host = new URL(withScheme).hostname.toLowerCase().replace(/^www\./, '');
    if (!host.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;
    return host;
  } catch {
    return null;
  }
}

function verdictFor(risk: number): GlobalExposureSite['verdict'] {
  if (risk >= 70) return 'critical';
  if (risk >= 45) return 'high';
  if (risk >= 20) return 'medium';
  return 'low';
}

async function dnsTxt(name: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((parts) => parts.join(''));
  } catch {
    return [];
  }
}

async function probeSite(domain: string, base: Omit<GlobalExposureSite, 'checkedAt' | 'issues' | 'risk' | 'verdict' | 'securityHeaders' | 'emailSecurity'>): Promise<GlobalExposureSite> {
  const issues: string[] = [];
  let risk = 0;
  const securityHeaders = {
    hsts: false,
    csp: false,
    xFrameOptions: false,
    xContentTypeOptions: false,
    referrerPolicy: false,
    permissionsPolicy: false,
  };
  const emailSecurity = { spf: false, dmarc: false };

  try {
    const response = await fetch(`https://${domain}/`, {
      redirect: 'follow',
      headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml' },
      signal: AbortSignal.timeout(10_000),
    });
    const headers = response.headers;
    securityHeaders.hsts = Boolean(headers.get('strict-transport-security'));
    securityHeaders.csp = Boolean(headers.get('content-security-policy'));
    securityHeaders.xFrameOptions = Boolean(headers.get('x-frame-options'));
    securityHeaders.xContentTypeOptions = Boolean(headers.get('x-content-type-options'));
    securityHeaders.referrerPolicy = Boolean(headers.get('referrer-policy'));
    securityHeaders.permissionsPolicy = Boolean(headers.get('permissions-policy'));

    if (!securityHeaders.hsts) { risk += 6; issues.push('No HSTS header'); }
    if (!securityHeaders.csp) { risk += 8; issues.push('No Content-Security-Policy'); }
    if (!securityHeaders.xFrameOptions) { risk += 5; issues.push('No X-Frame-Options (clickjacking risk)'); }
    if (!securityHeaders.xContentTypeOptions) { risk += 3; issues.push('No X-Content-Type-Options'); }
    if (!securityHeaders.referrerPolicy) { risk += 2; issues.push('No Referrer-Policy'); }
    if (!securityHeaders.permissionsPolicy) { risk += 2; issues.push('No Permissions-Policy'); }
    if (response.status >= 500) { risk += 15; issues.push(`Server error HTTP ${response.status}`); }
    else if (response.status >= 400) { risk += 5; issues.push(`HTTP ${response.status}`); }

    await response.body?.cancel().catch(() => undefined);
    base.status = response.status;
    base.url = response.url || base.url;
  } catch (error) {
    risk += 20;
    issues.push(`HTTPS probe failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  }

  const [spfRecords, dmarcRecords] = await Promise.all([dnsTxt(domain), dnsTxt(`_dmarc.${domain}`)]);
  emailSecurity.spf = spfRecords.some((record) => /^v=spf1/i.test(record));
  emailSecurity.dmarc = dmarcRecords.some((record) => /^v=DMARC1/i.test(record));
  if (!emailSecurity.spf) { risk += 6; issues.push('No SPF record'); }
  if (!emailSecurity.dmarc) { risk += 8; issues.push('No DMARC record'); }

  if ((base.domainAgeDays ?? 9999) < 30) {
    risk += 15;
    issues.push(`Very new domain (${base.domainAgeDays} days)`);
  }
  const badLabels = base.labels.filter((label) => /malicious|phish|malware|scam|spam/i.test(label));
  if (badLabels.length > 0) {
    risk += 30;
    issues.push(`Threat labels: ${badLabels.join(', ')}`);
  }
  if (base.source === 'phishing-feed') {
    risk += 35;
    issues.push('Listed in a live phishing feed');
  }
  if (base.title && /login|verify|wallet|seed|password|account suspended/i.test(base.title)) {
    risk += 8;
    issues.push(`Sensitive page title: ${base.title}`);
  }

  const bounded = Math.min(100, risk);
  return {
    ...base,
    securityHeaders,
    emailSecurity,
    issues,
    risk: bounded,
    verdict: verdictFor(bounded),
    checkedAt: new Date().toISOString(),
  };
}

async function discoverFromUrlscan(): Promise<{ sites: DiscoveredSite[]; status: 'online' | 'degraded'; detail: string }> {
  try {
    const response = await fetch('https://urlscan.io/api/v1/search/?q=date%3A%5Bnow-6h%20TO%20now%5D&size=100', {
      headers: { 'User-Agent': UA, Accept: 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = (await response.json()) as { results?: Array<Record<string, unknown>> };
    const rows = Array.isArray(payload.results) ? payload.results : [];
    const sites = rows
      .map((row) => {
        const page = (row.page ?? {}) as Record<string, unknown>;
        const task = (row.task ?? {}) as Record<string, unknown>;
        const domain = domainOf(String(page.domain ?? task.domain ?? ''));
        return domain ? ({ domain, meta: { ...page, labels: row.labels } } as DiscoveredSite) : null;
      })
      .filter((row): row is DiscoveredSite => Boolean(row));
    return { sites, status: 'online', detail: `${rows.length} recent public scans` };
  } catch (error) {
    return { sites: [], status: 'degraded', detail: error instanceof Error ? error.message : 'urlscan unavailable' };
  }
}

async function discoverFromThreatMonitor(): Promise<DiscoveredSite[]> {
  const radar = await threatMonitor.getSnapshot().catch(() => null);
  if (!radar) return [];
  return radar.phishingTraps
    .map((trap) => {
      const domain = domainOf(trap.url);
      return domain
        ? ({
            domain,
            meta: {
              source: 'phishing-feed',
              title: trap.host,
              labels: trap.riskReasons,
            },
          } as DiscoveredSite)
        : null;
    })
    .filter((row): row is DiscoveredSite => Boolean(row));
}

function discoverFromShields(): DiscoveredSite[] {
  return defenseEngine
    .getState()
    .protectedShields.map((shield) => {
      const domain = domainOf(shield.host);
      return domain
        ? ({ domain, meta: { source: 'protected-site', title: shield.host, labels: [] } } as DiscoveredSite)
        : null;
    })
    .filter((row): row is DiscoveredSite => Boolean(row));
}

export async function refreshGlobalExposure(): Promise<GlobalExposureSnapshot> {
  if (snapshot.running) return snapshot;
  snapshot = { ...snapshot, running: true, generatedAt: new Date().toISOString() };
  try {
    const [urlscan, phishing, shields] = await Promise.all([
      discoverFromUrlscan(),
      Promise.resolve(discoverFromThreatMonitor()),
      Promise.resolve(discoverFromShields()),
    ]);

    const unique = new Map<string, DiscoveredSite>();
    for (const row of [...phishing, ...shields, ...urlscan.sites]) {
      if (!unique.has(row.domain)) unique.set(row.domain, row);
    }
    const candidates = Array.from(unique.values()).slice(0, MAX_SITES);

    const sites: GlobalExposureSite[] = [];
    const concurrency = 6;
    for (let index = 0; index < candidates.length; index += concurrency) {
      const batch = candidates.slice(index, index + concurrency);
      const probed = await Promise.all(
        batch.map((candidate) => {
          const meta = candidate.meta;
          const source = meta.source === 'phishing-feed'
            ? 'phishing-feed'
            : meta.source === 'protected-site'
              ? 'protected-site'
              : 'urlscan';
          return probeSite(candidate.domain, {
            domain: candidate.domain,
            source,
            url: `https://${candidate.domain}/`,
            ip: typeof meta.ip === 'string' ? meta.ip : undefined,
            country: typeof meta.country === 'string' ? meta.country : undefined,
            asn: typeof meta.asn === 'string' ? meta.asn : undefined,
            asnName: typeof meta.asnname === 'string' ? meta.asnname : undefined,
            title: typeof meta.title === 'string' ? meta.title.slice(0, 160) : undefined,
            tlsIssuer: typeof meta.tlsIssuer === 'string' ? meta.tlsIssuer : undefined,
            tlsValidDays: typeof meta.tlsValidDays === 'number' ? meta.tlsValidDays : undefined,
            domainAgeDays: typeof meta.domainAgeDays === 'number' ? meta.domainAgeDays : undefined,
            redirect: typeof meta.redirected === 'string' ? meta.redirected : undefined,
            labels: Array.isArray(meta.labels) ? meta.labels.filter((label): label is string => typeof label === 'string') : [],
          });
        }),
      );
      sites.push(...probed);
    }

    sites.sort((a, b) => b.risk - a.risk);
    snapshot = {
      generatedAt: new Date().toISOString(),
      lastRunAt: new Date().toISOString(),
      running: false,
      sources: [
        { name: 'urlscan.io public scans', status: urlscan.status, detail: urlscan.detail },
        { name: 'Live phishing feeds', status: phishing.length > 0 ? 'online' : 'degraded', detail: `${phishing.length} domain(s)` },
        { name: 'Protected customer sites', status: 'online', detail: `${shields.length} domain(s)` },
      ],
      coverage: {
        discovered: unique.size,
        probed: sites.length,
        critical: sites.filter((site) => site.verdict === 'critical').length,
        high: sites.filter((site) => site.verdict === 'high').length,
        medium: sites.filter((site) => site.verdict === 'medium').length,
        low: sites.filter((site) => site.verdict === 'low').length,
      },
      sites,
    };
    return snapshot;
  } finally {
    snapshot = { ...snapshot, running: false, generatedAt: new Date().toISOString() };
  }
}

export function getGlobalExposureSnapshot(): GlobalExposureSnapshot {
  return snapshot;
}

export function startGlobalExposureMonitor(): void {
  if (timer || process.env.SENTINEL_EXPOSURE_ENABLED === 'false') return;
  setTimeout(() => void refreshGlobalExposure().catch(() => undefined), 25_000);
  timer = setInterval(() => void refreshGlobalExposure().catch(() => undefined), REFRESH_MS);
}
