import type {
  CyberIncident,
  ExploitedCve,
  FeedHealthItem,
  PhishingTrap,
  RadarSnapshot,
  ThreatNode,
} from '../src/types/cyber.ts';
import { extractDomain, parseRssFeed, stripHtml } from './parsers.ts';
import {
  classifyIncidentSeverity,
  extractTargetIdentifiers,
  isPrivateOrReservedIp,
  parseCisaKevCatalog,
  parseIpBlocklistText,
  parseOpenPhishFeed,
  type FeodoRawRecord,
} from './threatRules.ts';

const REFRESH_INTERVAL_MS = 120_000; // 2-minute continuous live monitoring cycle

interface IpApiBatchItem {
  status?: string;
  query?: string;
  country?: string;
  countryCode?: string;
  city?: string;
  lat?: number;
  lon?: number;
  isp?: string;
  org?: string;
  as?: string;
  reverse?: string;
  proxy?: boolean;
  hosting?: boolean;
}

class ThreatMonitorService {
  private snapshot: RadarSnapshot | null = null;
  private inflight: Promise<RadarSnapshot> | null = null;
  private cycleCount = 0;
  private timer: NodeJS.Timeout | null = null;

  private blocklistIps = new Set<string>();
  private cinsIps = new Set<string>();
  private torExitIps = new Set<string>();
  private feodoByIp = new Map<string, FeodoRawRecord>();
  private openPhishUrls = new Set<string>();
  private openPhishHosts = new Set<string>();

  public isTorExitIp(ip: string): boolean {
    return this.torExitIps.has(ip);
  }

  public start(): void {
    if (this.timer) return;
    // Warm up immediately without blocking server startup
    void this.refreshNow().catch(() => {});
    this.timer = setInterval(() => {
      void this.refreshNow().catch(() => {});
    }, REFRESH_INTERVAL_MS);
  }

  public async getSnapshot(forceRefresh = false): Promise<RadarSnapshot> {
    if (!forceRefresh && this.snapshot) {
      const age = Date.now() - new Date(this.snapshot.scannedAt).getTime();
      if (age < REFRESH_INTERVAL_MS) {
        return this.snapshot;
      }
    }
    return this.refreshNow();
  }

  public lookupIpMatches(ip: string): Array<{ feed: string; detail: string }> {
    const matches: Array<{ feed: string; detail: string }> = [];
    const feodo = this.feodoByIp.get(ip);
    if (feodo) {
      matches.push({
        feed: 'Abuse.ch Feodo C2',
        detail: `Active Botnet C2 (${feodo.malware || 'Malware'}, port ${feodo.port || '?'})`,
      });
    }
    if (this.blocklistIps.has(ip)) {
      matches.push({
        feed: 'Blocklist.de Live Attackers',
        detail: 'Reported active SSH/Web/Bruteforce attacker IP in the last 48h',
      });
    }
    if (this.cinsIps.has(ip)) {
      matches.push({
        feed: 'CINS Army Threat List',
        detail: 'Confirmed hostile network scanner / automated attack source',
      });
    }
    return matches;
  }

  public lookupUrlMatches(rawUrl: string, host: string): Array<{ feed: string; detail: string }> {
    const matches: Array<{ feed: string; detail: string }> = [];
    const cleanUrl = rawUrl.trim().toLowerCase();
    const cleanHost = host.trim().toLowerCase();
    if (this.openPhishUrls.has(cleanUrl)) {
      matches.push({
        feed: 'OpenPhish Live Feed',
        detail: 'Exact URL flagged as an active credential-stealing phishing trap',
      });
    } else if (cleanHost && this.openPhishHosts.has(cleanHost)) {
      matches.push({
        feed: 'OpenPhish Live Feed',
        detail: `Hostname "${cleanHost}" actively hosts live phishing trap URLs`,
      });
    }
    return matches;
  }

  public async refreshNow(): Promise<RadarSnapshot> {
    if (this.inflight) return this.inflight;
    this.inflight = this.executeScanCycle().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async fetchText(url: string, timeoutMs = 9500): Promise<string> {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'SentinelGlobe-ThreatMonitor/1.0',
          Accept: 'application/json, application/xml, text/plain, */*',
        },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } finally {
      clearTimeout(t);
    }
  }

  private async batchGeolocateIps(ips: string[]): Promise<Map<string, IpApiBatchItem>> {
    const geoMap = new Map<string, IpApiBatchItem>();
    if (ips.length === 0) return geoMap;

    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 9000);
      try {
        const res = await fetch(
          'http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,isp,org,as,reverse,proxy,hosting',
          {
            method: 'POST',
            signal: controller.signal,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ips.slice(0, 60)),
          },
        );
        if (res.ok) {
          const rows = (await res.json()) as IpApiBatchItem[];
          if (Array.isArray(rows)) {
            for (const row of rows) {
              if (row.status === 'success' && row.query && typeof row.lat === 'number' && typeof row.lon === 'number') {
                geoMap.set(row.query, row);
              }
            }
          }
        }
      } finally {
        clearTimeout(t);
      }
    } catch {
      // Fallback gracefully if geo batch is slow
    }

    return geoMap;
  }

  private async fetchBingCyberWebScan(): Promise<CyberIncident[]> {
    try {
      const query = encodeURIComponent('cyber attack data breach ransomware hackers');
      const xml = await this.fetchText(
        `https://www.bing.com/news/search?q=${query}&format=rss`,
        8500,
      );
      const parsed = parseRssFeed(xml, 'Global Web Scan', 'bing').slice(0, 12);
      return parsed.map((item, idx) => {
        const domain = extractDomain(item.url);
        const extractedTargets = extractTargetIdentifiers(`${item.title} ${item.summary}`);
        return {
          id: `web-${idx + 1}-${domain}`,
          title: item.title,
          summary: item.summary,
          source: domain !== 'bing.com' ? domain : 'Web Monitor',
          url: item.url,
          publishedAt: item.publishedAt,
          severity: classifyIncidentSeverity(item.title, item.summary),
          extractedTargets,
        };
      });
    } catch {
      return [];
    }
  }

  private async fetchHackerNewsIncidents(): Promise<CyberIncident[]> {
    try {
      const xml = await this.fetchText('https://feeds.feedburner.com/TheHackersNews', 9000);
      const parsed = parseRssFeed(xml, 'The Hacker News', 'bing').slice(0, 10);
      return parsed.map((item, idx) => ({
        id: `thn-${idx + 1}`,
        title: item.title,
        summary: stripHtml(item.summary),
        source: 'The Hacker News',
        url: item.url,
        publishedAt: item.publishedAt,
        severity: classifyIncidentSeverity(item.title, item.summary),
        extractedTargets: extractTargetIdentifiers(`${item.title} ${item.summary}`),
      }));
    } catch {
      return [];
    }
  }

  private async executeScanCycle(): Promise<RadarSnapshot> {
    const nowIso = new Date().toISOString();
    const nextIso = new Date(Date.now() + REFRESH_INTERVAL_MS).toISOString();
    this.cycleCount += 1;

    const [
      feodoRecRes,
      feodoFullRes,
      blocklistRes,
      cinsRes,
      openPhishRes,
      cisaRes,
      torExitRes,
      thnIncidents,
      webHighlights,
    ] = await Promise.allSettled([
      this.fetchText('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', 8000),
      this.fetchText('https://feodotracker.abuse.ch/downloads/ipblocklist.json', 8000),
      this.fetchText('https://lists.blocklist.de/lists/all.txt', 10000),
      this.fetchText('https://cinsscore.com/list/ci-badguys.txt', 10000),
      this.fetchText('https://openphish.com/feed.txt', 9000),
      this.fetchText(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        10000,
      ),
      this.fetchText('https://check.torproject.org/torbulkexitlist', 8500),
      this.fetchHackerNewsIncidents(),
      this.fetchBingCyberWebScan(),
    ]);

    const feedHealth: FeedHealthItem[] = [];

    // 1. Feodo Tracker C2s
    const feodoRecords: FeodoRawRecord[] = [];
    const seenFeodo = new Set<string>();
    for (const res of [feodoRecRes, feodoFullRes]) {
      if (res.status === 'fulfilled') {
        try {
          const arr = JSON.parse(res.value) as FeodoRawRecord[];
          if (Array.isArray(arr)) {
            for (const rec of arr) {
              if (rec.ip_address && !seenFeodo.has(rec.ip_address)) {
                seenFeodo.add(rec.ip_address);
                feodoRecords.push(rec);
              }
            }
          }
        } catch {
          // ignore malformed chunk
        }
      }
    }
    if (feodoRecords.length > 0) {
      this.feodoByIp = new Map(feodoRecords.map((r) => [r.ip_address!, r]));
    }
    feedHealth.push({
      name: 'Abuse.ch Feodo C2',
      status: feodoRecords.length > 0 ? 'online' : 'degraded',
      recordCount: this.feodoByIp.size,
    });

    // 2. Blocklist.de live attackers
    if (blocklistRes.status === 'fulfilled') {
      const parsed = parseIpBlocklistText(blocklistRes.value);
      if (parsed.size > 0) this.blocklistIps = parsed;
    }
    feedHealth.push({
      name: 'Blocklist.de Attackers',
      status: blocklistRes.status === 'fulfilled' && this.blocklistIps.size > 0 ? 'online' : 'degraded',
      recordCount: this.blocklistIps.size,
    });

    // 3. CINS Army hostile scanners
    if (cinsRes.status === 'fulfilled') {
      const parsed = parseIpBlocklistText(cinsRes.value);
      if (parsed.size > 0) this.cinsIps = parsed;
    }
    feedHealth.push({
      name: 'CINS Army Scanners',
      status: cinsRes.status === 'fulfilled' && this.cinsIps.size > 0 ? 'online' : 'degraded',
      recordCount: this.cinsIps.size,
    });

    // 4. OpenPhish Live Phishing Traps
    let phishingTraps: PhishingTrap[] = this.snapshot?.phishingTraps ?? [];
    if (openPhishRes.status === 'fulfilled') {
      const parsedPhish = parseOpenPhishFeed(openPhishRes.value, nowIso);
      if (parsedPhish.urlSet.size > 0) {
        this.openPhishUrls = parsedPhish.urlSet;
        this.openPhishHosts = parsedPhish.hostSet;
        phishingTraps = parsedPhish.traps;
      }
    }
    feedHealth.push({
      name: 'OpenPhish Traps',
      status: openPhishRes.status === 'fulfilled' && this.openPhishUrls.size > 0 ? 'online' : 'degraded',
      recordCount: this.openPhishUrls.size,
    });

    // 5. CISA KEV Exploited CVEs
    let cves: ExploitedCve[] = this.snapshot?.cves ?? [];
    if (cisaRes.status === 'fulfilled') {
      try {
        const parsedCves = parseCisaKevCatalog(JSON.parse(cisaRes.value));
        if (parsedCves.length > 0) cves = parsedCves;
      } catch {
        // retain prior
      }
    }
    feedHealth.push({
      name: 'CISA Exploited CVEs',
      status: cisaRes.status === 'fulfilled' && cves.length > 0 ? 'online' : 'degraded',
      recordCount: cves.length,
    });

    // 5b. Tor Project Exit Node List
    if (torExitRes.status === 'fulfilled') {
      const parsedTor = parseIpBlocklistText(torExitRes.value);
      if (parsedTor.size > 0) this.torExitIps = parsedTor;
    }
    feedHealth.push({
      name: 'Tor Exit Nodes',
      status: torExitRes.status === 'fulfilled' && this.torExitIps.size > 0 ? 'online' : 'degraded',
      recordCount: this.torExitIps.size,
    });

    // 6. Select real representative attacker IPs deterministically (zero Math.random!)
    // Spread stride rotates each cycle so continuous radar sweeps surface fresh regions from the live feeds.
    const blocklistArr = Array.from(this.blocklistIps);
    const cinsArr = Array.from(this.cinsIps);
    const candidateIps: Array<{
      ip: string;
      sourceFeed: ThreatNode['sourceFeed'];
      threatType: string;
      severity: ThreatNode['severity'];
      feodo?: FeodoRawRecord;
    }> = [];

    for (const rec of feodoRecords.slice(0, 12)) {
      if (rec.ip_address && !isPrivateOrReservedIp(rec.ip_address)) {
        candidateIps.push({
          ip: rec.ip_address,
          sourceFeed: 'Feodo C2',
          threatType: `${rec.malware || 'Botnet'} C2 Server`,
          severity: 'CRITICAL',
          feodo: rec,
        });
      }
    }

    const offset = (this.cycleCount - 1) * 7;
    if (blocklistArr.length > 0) {
      const step = Math.max(1, Math.floor(blocklistArr.length / 26));
      for (let i = 0; i < 24 && candidateIps.length < 36; i++) {
        const idx = (offset + i * step) % blocklistArr.length;
        const ip = blocklistArr[idx];
        if (!isPrivateOrReservedIp(ip) && !candidateIps.some((c) => c.ip === ip)) {
          candidateIps.push({
            ip,
            sourceFeed: 'Blocklist.de',
            threatType: this.cinsIps.has(ip)
              ? 'Multi-Feed Bruteforce / Web Attack'
              : 'Active Web / SSH Attacker',
            severity: this.cinsIps.has(ip) ? 'CRITICAL' : 'HIGH',
          });
        }
      }
    }

    if (cinsArr.length > 0) {
      const step = Math.max(1, Math.floor(cinsArr.length / 20));
      for (let i = 0; i < 16 && candidateIps.length < 48; i++) {
        const idx = (offset + i * step) % cinsArr.length;
        const ip = cinsArr[idx];
        if (!isPrivateOrReservedIp(ip) && !candidateIps.some((c) => c.ip === ip)) {
          candidateIps.push({
            ip,
            sourceFeed: 'CINS Army',
            threatType: 'Hostile Vulnerability Scanner',
            severity: 'HIGH',
          });
        }
      }
    }

    const geoMap = await this.batchGeolocateIps(candidateIps.map((c) => c.ip));
    const threatNodes: ThreatNode[] = [];
    for (const item of candidateIps) {
      const geo = geoMap.get(item.ip);
      if (!geo || typeof geo.lat !== 'number' || typeof geo.lon !== 'number') continue;
      threatNodes.push({
        id: `${item.sourceFeed}-${item.ip}`,
        ip: item.ip,
        port: item.feodo?.port,
        threatType: item.threatType,
        malware: item.feodo?.malware,
        sourceFeed: item.sourceFeed,
        severity: item.severity,
        country: geo.country || item.feodo?.country || 'Unknown',
        countryCode: geo.countryCode || item.feodo?.country || 'XX',
        city: geo.city || 'Unknown',
        lat: geo.lat,
        lon: geo.lon,
        asn: geo.as || (item.feodo?.as_number ? `AS${item.feodo.as_number}` : 'Unknown ASN'),
        isp: geo.isp || item.feodo?.as_name || 'Unknown ISP',
        org: geo.org || geo.isp || 'Unknown Organization',
        reverse: geo.reverse || item.feodo?.hostname || undefined,
        isProxy: Boolean(geo.proxy),
        isHosting: Boolean(geo.hosting),
        firstSeen: item.feodo?.first_seen,
        lastSeen: item.feodo?.last_online,
      });
    }

    const incidents =
      thnIncidents.status === 'fulfilled' && thnIncidents.value.length > 0
        ? thnIncidents.value
        : this.snapshot?.incidents ?? [];
    const webScanHighlights =
      webHighlights.status === 'fulfilled' && webHighlights.value.length > 0
        ? webHighlights.value
        : this.snapshot?.webScanHighlights ?? [];

    feedHealth.push({
      name: 'Global Web Cyber Scan',
      status: webScanHighlights.length > 0 || incidents.length > 0 ? 'online' : 'degraded',
      recordCount: webScanHighlights.length + incidents.length,
    });

    const nextSnapshot: RadarSnapshot = {
      scannedAt: nowIso,
      nextScanAt: nextIso,
      scanCycleCount: this.cycleCount,
      feedHealth,
      summary: {
        activeAttackers: this.blocklistIps.size + this.cinsIps.size,
        c2Botnets: this.feodoByIp.size,
        phishingTraps: this.openPhishUrls.size,
        exploitedCves: cves.length,
        globalIncidents: incidents.length + webScanHighlights.length,
        torExitNodes: this.torExitIps.size,
      },
      threatNodes,
      phishingTraps,
      cves,
      incidents,
      webScanHighlights,
    };

    this.snapshot = nextSnapshot;
    return nextSnapshot;
  }
}

export const threatMonitor = new ThreatMonitorService();
