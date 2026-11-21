import type {
  CyberIncident,
  ExploitedCve,
  FeedHealthItem,
  PhishingTrap,
} from '../src/types/cyber.ts';
import { classifyIncidentSeverity } from './threatRules.ts';

const CACHE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 12_000;

export interface PublicIpIndicator {
  ip: string;
  tags: string[];
  source: string;
}

export interface PublicThreatFeedSnapshot {
  fetchedAt: string;
  cves: ExploitedCve[];
  phishingTraps: PhishingTrap[];
  incidents: CyberIncident[];
  ipIndicators: PublicIpIndicator[];
  health: FeedHealthItem[];
}

const EMPTY_SNAPSHOT: PublicThreatFeedSnapshot = {
  fetchedAt: new Date(0).toISOString(),
  cves: [],
  phishingTraps: [],
  incidents: [],
  ipIndicators: [],
  health: [],
};

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: {
      'User-Agent': 'SentinelGlobe/1.0 (+https://github.com/onelpawarai-X/hack)',
      Accept: 'text/plain, application/json, application/xml, text/xml, */*',
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function fetchJson<T>(url: string): Promise<T> {
  return JSON.parse(await fetchText(url)) as T;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function cleanText(value: string): string {
  return decodeEntities(
    value
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim(),
  );
}

function xmlTag(block: string, tag: string): string {
  const match = block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
  return match ? cleanText(match[1]) : '';
}

function hostOf(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function validIp(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    const number = Number(part);
    return Number.isInteger(number) && number >= 0 && number <= 255;
  });
}

function parsePlainIpFeed(
  text: string,
  tags: string[],
  source: string,
  limit: number,
): PublicIpIndicator[] {
  const out: PublicIpIndicator[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const clean = line.split('#')[0].trim();
    if (!clean) continue;
    const candidate = clean.split(/[\s,;\t]+/)[0];
    if (!validIp(candidate) || seen.has(candidate)) continue;
    seen.add(candidate);
    out.push({ ip: candidate, tags, source });
    if (out.length >= limit) break;
  }
  return out;
}

function parsePlainUrlFeed(
  text: string,
  source: PhishingTrap['sourceFeed'],
  limit: number,
): PhishingTrap[] {
  const out: PhishingTrap[] = [];
  const seen = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const url = line.trim();
    if (!/^https?:\/\//i.test(url) || seen.has(url)) continue;
    seen.add(url);
    out.push({
      id: `public-phish-${hostOf(url)}-${out.length}`,
      url,
      host: hostOf(url),
      sourceFeed: source,
      severity: 'HIGH',
      riskReasons: [`Listed by ${source} public threat feed`],
      detectedAt: new Date().toISOString(),
    });
    if (out.length >= limit) break;
  }
  return out;
}

async function fetchCisaKev(): Promise<ExploitedCve[]> {
  const payload = await fetchJson<{
    vulnerabilities?: Array<{
      cveID?: string;
      vendorProject?: string;
      product?: string;
      vulnerabilityName?: string;
      dateAdded?: string;
      dueDate?: string;
      knownRansomwareCampaignUse?: string;
      shortDescription?: string;
    }>;
  }>('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  return (payload.vulnerabilities ?? [])
    .filter((item) => item.cveID)
    .slice(0, 40)
    .map((item) => ({
      cveID: String(item.cveID),
      vendorProject: item.vendorProject || 'Unknown vendor',
      product: item.product || 'Unknown product',
      vulnerabilityName: item.vulnerabilityName || String(item.cveID),
      dateAdded: item.dateAdded || '',
      dueDate: item.dueDate || '',
      knownRansomware: /known/i.test(item.knownRansomwareCampaignUse || ''),
      shortDescription: item.shortDescription || '',
    }));
}

async function fetchRssIncidents(
  url: string,
  source: string,
): Promise<CyberIncident[]> {
  const xml = await fetchText(url);
  const items = Array.from(xml.matchAll(/<item\b[\s\S]*?<\/item>/gi)).slice(0, 12);
  return items.map((match, index) => {
    const block = match[0];
    const title = xmlTag(block, 'title') || `${source} security update`;
    const link = xmlTag(block, 'link');
    const description = xmlTag(block, 'description');
    const publishedAt = xmlTag(block, 'pubDate');
    const published = publishedAt ? new Date(publishedAt) : new Date();
    return {
      id: `rss-${source}-${index}-${Buffer.from(link || title).toString('hex').slice(0, 12)}`,
      title,
      summary: description.slice(0, 320),
      source,
      url: link,
      publishedAt: Number.isNaN(published.getTime()) ? new Date().toISOString() : published.toISOString(),
      severity: classifyIncidentSeverity(title, description),
      extractedTargets: [],
    };
  });
}

class PublicThreatFeedService {
  private snapshot: PublicThreatFeedSnapshot | null = null;
  private inflight: Promise<PublicThreatFeedSnapshot> | null = null;

  public async get(): Promise<PublicThreatFeedSnapshot> {
    if (
      this.snapshot &&
      Date.now() - new Date(this.snapshot.fetchedAt).getTime() < CACHE_TTL_MS
    ) {
      return this.snapshot;
    }
    if (this.inflight) return this.inflight;
    this.inflight = this.refresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async refresh(): Promise<PublicThreatFeedSnapshot> {
    const health: FeedHealthItem[] = [];
    const cves: ExploitedCve[] = [];
    const phishingTraps: PhishingTrap[] = [];
    const incidents: CyberIncident[] = [];
    const ipIndicators: PublicIpIndicator[] = [];

    const tasks: Array<Promise<void>> = [];

    tasks.push(
      fetchCisaKev()
        .then((items) => {
          cves.push(...items);
          health.push({ name: 'CISA KEV', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'CISA KEV', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchText('https://openphish.com/feed.txt')
        .then((text) => {
          const items = parsePlainUrlFeed(text, 'OpenPhish', 20);
          phishingTraps.push(...items);
          health.push({ name: 'OpenPhish', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'OpenPhish', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchText('https://feodotracker.abuse.ch/downloads/ipblocklist.txt')
        .then((text) => {
          const items = parsePlainIpFeed(text, ['c2', 'botnet'], 'Feodo Tracker', 25);
          ipIndicators.push(...items);
          health.push({ name: 'Feodo Tracker', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'Feodo Tracker', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchText('https://check.torproject.org/torbulkexitlist')
        .then((text) => {
          const items = parsePlainIpFeed(text, ['tor'], 'Tor Project', 20);
          ipIndicators.push(...items);
          health.push({ name: 'Tor exit list', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'Tor exit list', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchText('https://cinsscore.com/list/ci-badguys.txt')
        .then((text) => {
          const items = parsePlainIpFeed(text, ['scanner'], 'CINS Army', 20);
          ipIndicators.push(...items);
          health.push({ name: 'CINS Army', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'CINS Army', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchText('https://lists.blocklist.de/lists/all.txt')
        .then((text) => {
          const items = parsePlainIpFeed(text, ['bruteforce'], 'Blocklist.de', 20);
          ipIndicators.push(...items);
          health.push({ name: 'Blocklist.de', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'Blocklist.de', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchRssIncidents('https://feeds.feedburner.com/TheHackersNews', 'The Hacker News')
        .then((items) => {
          incidents.push(...items);
          health.push({ name: 'The Hacker News', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'The Hacker News', status: 'degraded', recordCount: 0 }); }),
    );

    tasks.push(
      fetchRssIncidents('https://www.bleepingcomputer.com/feed/', 'BleepingComputer')
        .then((items) => {
          incidents.push(...items);
          health.push({ name: 'BleepingComputer', status: 'online', recordCount: items.length });
        })
        .catch(() => { health.push({ name: 'BleepingComputer', status: 'degraded', recordCount: 0 }); }),
    );

    await Promise.allSettled(tasks);

    const seenPhish = new Set<string>();
    const uniquePhish = phishingTraps.filter((item) => {
      if (!item.url || seenPhish.has(item.url)) return false;
      seenPhish.add(item.url);
      return true;
    });

    const seenIp = new Set<string>();
    const uniqueIps = ipIndicators.filter((item) => {
      if (seenIp.has(item.ip)) return false;
      seenIp.add(item.ip);
      return true;
    });

    const seenIncident = new Set<string>();
    const uniqueIncidents = incidents
      .filter((item) => {
        const key = item.url || item.title;
        if (!key || seenIncident.has(key)) return false;
        seenIncident.add(key);
        return true;
      })
      .sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt))
      .slice(0, 20);

    this.snapshot = {
      fetchedAt: new Date().toISOString(),
      cves,
      phishingTraps: uniquePhish,
      incidents: uniqueIncidents,
      ipIndicators: uniqueIps,
      health,
    };
    return this.snapshot;
  }
}

export const publicThreatFeeds = new PublicThreatFeedService();

export function emptyPublicThreatFeedSnapshot(): PublicThreatFeedSnapshot {
  return { ...EMPTY_SNAPSHOT };
}
