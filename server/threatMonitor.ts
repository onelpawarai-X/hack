import { resolve4 } from 'node:dns/promises';
import type {
  CyberIncident,
  ExploitedCve,
  FeedHealthItem,
  PhishingTrap,
  RadarSnapshot,
  ThreatNode,
} from '../src/types/cyber.ts';
import { listAttackEvents } from './db.ts';
import { traceAttackerIp } from './ipAttribution.ts';
import { localCve } from './localCve.ts';
import { localIoc } from './localIoc.ts';
import { isPrivateOrReservedIp } from './threatRules.ts';

const REFRESH_INTERVAL_MS = 60_000;

class ThreatMonitorService {
  private snapshot: RadarSnapshot | null = null;
  private inflight: Promise<RadarSnapshot> | null = null;
  private cycleCount = 0;
  private timer: NodeJS.Timeout | null = null;

  public start(): void {
    if (this.timer) return;
    void this.refreshNow().catch(() => {});
    this.timer = setInterval(() => {
      void this.refreshNow().catch(() => {});
    }, REFRESH_INTERVAL_MS);
  }

  public getCachedSnapshot(): RadarSnapshot | null {
    return this.snapshot;
  }

  public async getSnapshot(forceRefresh = false): Promise<RadarSnapshot> {
    if (!forceRefresh && this.snapshot) {
      const age = Date.now() - new Date(this.snapshot.scannedAt).getTime();
      if (age < REFRESH_INTERVAL_MS) return this.snapshot;
    }
    return this.refreshNow();
  }

  public lookupIpMatches(ip: string): Array<{ feed: string; detail: string }> {
    return localIoc.lookupIp(ip).map((entry) => ({
      feed: 'Local IOC',
      detail: `${entry.value}${entry.tags.length ? ` (${entry.tags.join(', ')})` : ''} from ${entry.source}`,
    }));
  }

  public isTorExitIp(ip: string): boolean {
    return localIoc.lookupIp(ip).some((entry) => entry.tags.includes('tor'));
  }

  public lookupUrlMatches(rawUrl: string, host: string): Array<{ feed: string; detail: string }> {
    const cleanHost = host.trim().toLowerCase().replace(/^www\./, '');
    const matches = localIoc.lookupDomain(cleanHost);
    return matches.map((entry) => ({
      feed: 'Local IOC',
      detail: `${rawUrl} matches ${entry.value}${entry.tags.length ? ` (${entry.tags.join(', ')})` : ''}`,
    }));
  }

  public async refreshNow(): Promise<RadarSnapshot> {
    if (this.inflight) return this.inflight;
    this.inflight = this.executeScanCycle().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async executeScanCycle(): Promise<RadarSnapshot> {
    const nowIso = new Date().toISOString();
    this.cycleCount += 1;

    const iocEntries = localIoc.all();
    const eventRows = listAttackEvents({ limit: 250 });
    const candidateIps = new Map<string, { ip: string; tags: string[]; firstSeen?: string; lastSeen?: string }>();

    for (const entry of iocEntries) {
      if (entry.type === 'ip' && !isPrivateOrReservedIp(entry.value)) {
        const existing = candidateIps.get(entry.value);
        candidateIps.set(entry.value, {
          ip: entry.value,
          tags: Array.from(new Set([...(existing?.tags ?? []), ...entry.tags])),
          firstSeen: existing?.firstSeen ?? entry.addedAt,
        });
      } else if (entry.type === 'domain') {
        try {
          const addresses = await resolve4(entry.value);
          for (const ip of addresses.slice(0, 2)) {
            if (isPrivateOrReservedIp(ip)) continue;
            const existing = candidateIps.get(ip);
            candidateIps.set(ip, {
              ip,
              tags: Array.from(new Set([...(existing?.tags ?? []), ...entry.tags])),
              firstSeen: existing?.firstSeen ?? entry.addedAt,
            });
          }
        } catch {
          // Domain IOC without a current A record stays in the local store only.
        }
      }
    }

    for (const event of eventRows) {
      if (!event.ip || isPrivateOrReservedIp(event.ip)) continue;
      const existing = candidateIps.get(event.ip);
      candidateIps.set(event.ip, {
        ip: event.ip,
        tags: Array.from(new Set([...(existing?.tags ?? []), event.category])),
        firstSeen: existing?.firstSeen ?? event.ts,
        lastSeen: event.ts,
      });
    }

    const candidates = Array.from(candidateIps.values()).slice(0, 60);
    const nodes: ThreatNode[] = [];
    for (let index = 0; index < candidates.length; index += 8) {
      const batch = candidates.slice(index, index + 8);
      const traced = await Promise.all(
        batch.map(async (candidate) => {
          const node = await traceAttackerIp(candidate.ip);
          if (!node) return null;
          return {
            ...node,
            id: `local-${candidate.ip}`,
            threatType:
              candidate.tags.length > 0
                ? `Local IOC / Sensor: ${candidate.tags.join(', ')}`
                : node.threatType,
            severity:
              candidate.tags.includes('c2') ||
              candidate.tags.includes('botnet') ||
              candidate.tags.includes('phishing') ||
              candidate.tags.includes('sqli') ||
              candidate.tags.includes('rce')
                ? 'CRITICAL'
                : candidate.tags.includes('tor') ||
                    candidate.tags.includes('scanner') ||
                    candidate.tags.includes('bruteforce') ||
                    candidate.tags.includes('xss')
                  ? 'HIGH'
                  : node.severity,
            sourceFeed: 'Live Attribution',
            firstSeen: candidate.firstSeen,
            lastSeen: candidate.lastSeen,
            localTags: candidate.tags,
          } satisfies ThreatNode;
        }),
      );
      for (const node of traced) if (node) nodes.push(node);
    }

    const phishingTraps: PhishingTrap[] = iocEntries
      .filter((entry) => entry.type === 'domain' && entry.tags.includes('phishing'))
      .slice(0, 40)
      .map((entry) => ({
        id: `local-phish-${entry.value}`,
        url: `https://${entry.value}`,
        host: entry.value,
        sourceFeed: 'OpenPhish',
        severity: 'CRITICAL',
        riskReasons: ['Listed in the local phishing IOC store'],
        detectedAt: entry.addedAt ?? nowIso,
      }));

    const cves: ExploitedCve[] = [];
    const incidents: CyberIncident[] = [];
    const feedHealth: FeedHealthItem[] = [
      {
        name: 'Local IOC store',
        status: iocEntries.length > 0 ? 'online' : 'degraded',
        recordCount: iocEntries.length,
      },
      {
        name: 'Local attack sensor',
        status: eventRows.length > 0 ? 'online' : 'degraded',
        recordCount: eventRows.length,
      },
      {
        name: 'Offline geo / ASN / CVE',
        status: 'online',
        recordCount: localCve.stats().cves,
      },
    ];

    const uniqueAttackers = new Set(eventRows.map((event) => event.ip).filter(Boolean)).size;
    const snapshot: RadarSnapshot = {
      scannedAt: nowIso,
      nextScanAt: new Date(Date.now() + REFRESH_INTERVAL_MS).toISOString(),
      scanCycleCount: this.cycleCount,
      feedHealth,
      summary: {
        activeAttackers: uniqueAttackers + iocEntries.filter((entry) => entry.type === 'ip').length,
        c2Botnets: iocEntries.filter((entry) => entry.tags.includes('c2')).length,
        phishingTraps: phishingTraps.length,
        exploitedCves: cves.length,
        globalIncidents: incidents.length,
        torExitNodes: iocEntries.filter((entry) => entry.tags.includes('tor')).length,
      },
      threatNodes: nodes,
      phishingTraps,
      cves,
      incidents,
      webScanHighlights: [],
    };

    this.snapshot = snapshot;
    return snapshot;
  }
}

export const threatMonitor = new ThreatMonitorService();
