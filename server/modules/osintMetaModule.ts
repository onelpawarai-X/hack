import { resolve4 } from 'node:dns/promises';
import type {
  CyberIncident,
  RdapDomainProfile,
  WaybackArchiveProfile,
} from '../../src/types/cyber.ts';
import { localIoc } from '../localIoc.ts';
import { lookupWhoisDomain } from '../nativeIntel.ts';
import type { ScanModulePlugin } from './types.ts';

const DEFAULT_WORDLIST = [
  'www', 'api', 'app', 'admin', 'portal', 'mail', 'smtp', 'imap', 'pop', 'webmail',
  'vpn', 'remote', 'gateway', 'gw', 'dns', 'ns1', 'ns2', 'mx', 'ftp', 'sftp',
  'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'prod', 'production', 'demo',
  'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'media', 'img', 'images',
  'docs', 'help', 'support', 'status', 'monitor', 'metrics', 'grafana', 'kibana',
  'jenkins', 'git', 'gitlab', 'github', 'ci', 'build', 'registry', 'docker',
  'db', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kafka', 'rabbitmq',
  'auth', 'sso', 'login', 'id', 'oauth', 'accounts', 'billing', 'pay', 'payments',
  'crm', 'erp', 'hr', 'intranet', 'internal', 'office', 'meet', 'chat', 'wiki',
];

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T | null> {
  return Promise.race([
    promise,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
  ]).catch(() => null);
}

async function enumerateSubdomains(rootDomain: string): Promise<string[]> {
  const probe = `sg-${Date.now().toString(36)}.${rootDomain}`;
  const wildcard = await withTimeout(resolve4(probe), 1200);
  if (wildcard && wildcard.length > 0) return [];

  const found = new Set<string>();
  for (let index = 0; index < DEFAULT_WORDLIST.length; index += 12) {
    const batch = DEFAULT_WORDLIST.slice(index, index + 12);
    const results = await Promise.all(
      batch.map(async (label) => {
        const host = `${label}.${rootDomain}`;
        const addresses = await withTimeout(resolve4(host), 1500);
        return addresses && addresses.length > 0 ? host : null;
      }),
    );
    for (const host of results) if (host) found.add(host);
  }
  return Array.from(found).sort();
}

function localSignals(term: string): CyberIncident[] {
  const clean = term.toLowerCase().replace(/^www\./, '');
  return localIoc
    .all()
    .filter(
      (entry) =>
        entry.value.includes(clean) ||
        clean.includes(entry.value) ||
        entry.tags.some((tag) => clean.includes(tag)),
    )
    .slice(0, 20)
    .map((entry, index) => ({
      id: `local-signal-${index}-${entry.value}`,
      title: `Local IOC match: ${entry.value}`,
      summary: `Indicator tagged ${entry.tags.join(', ') || 'unclassified'} in ${entry.source}.`,
      source: 'Local IOC Store',
      url: entry.type === 'domain' ? `https://${entry.value}` : `ip:${entry.value}`,
      publishedAt: entry.addedAt ?? new Date().toISOString(),
      severity: entry.tags.includes('c2') || entry.tags.includes('phishing') ? 'CRITICAL' : 'HIGH',
      extractedTargets: [entry.value],
    }));
}

export async function searchWebBreachSignals(term: string): Promise<CyberIncident[]> {
  return localSignals(term);
}

async function fetchRdapDomainProfile(rootDomain: string): Promise<RdapDomainProfile | null> {
  const whois = await lookupWhoisDomain(rootDomain);
  if (!whois) return null;
  return {
    registrar: whois.registrar,
    registrationDate: whois.registrationDate,
    expirationDate: whois.expirationDate,
    lastChangedDate: whois.lastChangedDate,
    dnssecSigned: whois.dnssecSigned,
    statuses: whois.statuses,
    abuseEmails: whois.abuseEmails,
  };
}

export const osintMetaModule: ScanModulePlugin = {
  id: 'osintMeta',
  label: 'WHOIS, DNS Enumeration & Local Intel',
  isActive: false,
  supportsTargetType: (t) => t === 'ip' || t === 'domain' || t === 'url',
  async run(ctx) {
    if (ctx.targetType === 'ip') {
      ctx.log(`Searching local IOC store for ${ctx.host}`, 'info', 'osintMeta');
      ctx.webBreachSignals = localSignals(ctx.host);
      ctx.log(
        `Found ${ctx.webBreachSignals.length} local IOC match(es)`,
        ctx.webBreachSignals.length > 0 ? 'warn' : 'info',
        'osintMeta',
      );
      return;
    }

    ctx.log(`Enumerating DNS labels and querying WHOIS for ${ctx.rootDomain}`, 'info', 'osintMeta');
    const [subdomains, rdapProfile, webSignals] = await Promise.all([
      enumerateSubdomains(ctx.rootDomain),
      fetchRdapDomainProfile(ctx.rootDomain),
      Promise.resolve(localSignals(ctx.host)),
    ]);

    ctx.discoveredSubdomains = subdomains;
    ctx.rdapProfile = rdapProfile;
    ctx.waybackProfile = null as WaybackArchiveProfile | null;
    ctx.webBreachSignals = webSignals;

    ctx.log(`DNS enumeration returned ${subdomains.length} subdomain(s)`, 'info', 'osintMeta');
    if (rdapProfile?.registrar) ctx.log(`WHOIS registrar: ${rdapProfile.registrar}`, 'info', 'osintMeta');
    ctx.log(
      `Found ${webSignals.length} local IOC match(es)`,
      webSignals.length > 0 ? 'warn' : 'info',
      'osintMeta',
    );
  },
};
