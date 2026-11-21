import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  ProtectedSystemShield,
  RadarSnapshot,
  ThreatNode,
  ThreatSeverity,
} from '../src/types/cyber.ts';
import type {
  AttackCategory,
  AttackEvent,
  DefenseGridAttacker,
  DefenseGridSnapshot,
} from '../src/types/defenseGrid.ts';
import {
  defenseEngine,
  generateFirewallRulesForIp,
  lookupRdapIpAbuse,
} from './defenseEngine.ts';
import { traceAttackerIp } from './scanner.ts';
import { threatMonitor } from './threatMonitor.ts';
import { isPrivateOrReservedIp, isValidIpv4 } from './threatRules.ts';

const MAX_EVENTS = 400;
const SENSOR_STATE_PATH = path.resolve(process.cwd(), '.sentinel-sensor-state.json');
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT_PER_MINUTE = Number(process.env.SENTINEL_RATE_LIMIT_PER_MINUTE) || 240;
const AUTO_BLOCK_AFTER = Number(process.env.SENTINEL_AUTO_BLOCK_AFTER) || 3;
const TARPIT_MS = Number(process.env.SENTINEL_TARPIT_MS) || 1200;

const HONEYPOT_PATHS = [
  '/.env',
  '/.git/config',
  '/.git/HEAD',
  '/wp-config.php',
  '/wp-login.php',
  '/xmlrpc.php',
  '/phpmyadmin',
  '/pma',
  '/admin',
  '/admin.php',
  '/administrator',
  '/wp-admin',
  '/login',
  '/server-status',
  '/server-info',
  '/actuator/env',
  '/actuator/health',
  '/console',
  '/manager/html',
  '/solr/admin',
  '/jenkins',
  '/config.json',
  '/backup.zip',
  '/.DS_Store',
  '/cgi-bin/',
  '/vendor/phpunit',
  '/trap',
];

interface Classification {
  category: AttackCategory;
  severity: ThreatSeverity;
  detail: string;
  honeypot: boolean;
}

interface PatternRule {
  category: AttackCategory;
  severity: ThreatSeverity;
  pattern: RegExp;
  detail: string;
}

const PATTERN_RULES: PatternRule[] = [
  {
    category: 'sqli',
    severity: 'CRITICAL',
    pattern: /(union[\s+]+select|information_schema|sleep\s*\(|benchmark\s*\(|['"]\s*or\s*['"]?1['"]?\s*=\s*['"]?1|;\s*drop\s+table)/i,
    detail: 'SQL injection payload in request path or query',
  },
  {
    category: 'xss',
    severity: 'HIGH',
    pattern: /(<script\b|javascript\s*:|onerror\s*=|onload\s*=|document\.cookie)/i,
    detail: 'Cross-site scripting payload in request',
  },
  {
    category: 'rce',
    severity: 'CRITICAL',
    pattern: /(;\s*(cat|whoami|id|uname|wget|curl)\b|\|\s*(whoami|id|uname)\b|\$\(|`[^`]+`|cmd\.exe|\/bin\/sh)/i,
    detail: 'Remote command execution payload',
  },
  {
    category: 'path-traversal',
    severity: 'CRITICAL',
    pattern: /(\.\.\/|\.\.%2f|%2e%2e%2f|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini)/i,
    detail: 'Path traversal / local file inclusion attempt',
  },
  {
    category: 'scanner',
    severity: 'ELEVATED',
    pattern: /(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|acunetix|nessus|openvas|qualys|netsparker|burp\s*collaborator)/i,
    detail: 'Automated vulnerability scanner user-agent',
  },
];

const FEED_CATEGORY: Record<string, AttackCategory> = {
  'Feodo C2': 'botnet-c2',
  'Blocklist.de': 'bruteforce',
  'CINS Army': 'scanner',
};

function severityRank(severity: ThreatSeverity): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'ELEVATED':
      return 2;
    default:
      return 1;
  }
}

function categoryForThreatNode(node: ThreatNode): AttackCategory {
  const type = node.threatType.toLowerCase();
  if (type.includes('phishing')) return 'phishing';
  if (type.includes('c2') || type.includes('botnet') || type.includes('malware')) return 'botnet-c2';
  if (type.includes('scanner')) return 'scanner';
  if (type.includes('brute') || type.includes('ssh')) return 'bruteforce';
  return FEED_CATEGORY[node.sourceFeed] ?? 'other';
}

function decodeTarget(req: Request): string {
  const raw = `${req.path}${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export function classifyAttack(input: {
  path: string;
  query?: string;
  userAgent?: string;
  method?: string;
}): Classification {
  const path = input.path.toLowerCase();
  const rawInput = `${path}${input.query ?? ''}`;
  let raw = rawInput;
  try {
    raw = decodeURIComponent(rawInput);
  } catch {
    raw = rawInput;
  }
  const ua = input.userAgent ?? '';

  const honeypotMatch = HONEYPOT_PATHS.find(
    (candidate) => path === candidate || path.startsWith(`${candidate}/`) || path.startsWith(candidate),
  );
  if (honeypotMatch) {
    const isLogin = honeypotMatch.includes('login') || honeypotMatch.includes('admin');
    return {
      category: isLogin ? 'credential-stuffing' : 'honeypot',
      severity: honeypotMatch === '/.env' || honeypotMatch === '/.git/config' ? 'CRITICAL' : 'HIGH',
      detail: `Decoy asset probe: ${honeypotMatch}`,
      honeypot: true,
    };
  }

  for (const rule of PATTERN_RULES) {
    if (rule.pattern.test(raw) || rule.pattern.test(ua)) {
      return {
        category: rule.category,
        severity: rule.severity,
        detail: rule.detail,
        honeypot: false,
      };
    }
  }

  if (/\b(?:nikto|nmap|masscan|zgrab|nuclei|sqlmap)\b/i.test(ua)) {
    return {
      category: 'scanner',
      severity: 'ELEVATED',
      detail: 'Known offensive scanner signature',
      honeypot: false,
    };
  }

  return { category: 'other', severity: 'CLEAN', detail: '', honeypot: false };
}

export function isBlockablePublicIp(
  ip: string,
  safeIps: ReadonlySet<string> = new Set(),
): boolean {
  return Boolean(ip) && isValidIpv4(ip) && !isPrivateOrReservedIp(ip) && !safeIps.has(ip);
}

export function isStaticAssetPath(path: string): boolean {
  return (
    path.startsWith('/assets/') ||
    path.startsWith('/@') ||
    path.startsWith('/src/') ||
    path.startsWith('/node_modules/') ||
    path.startsWith('/socket.io/') ||
    /\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot)$/i.test(path)
  );
}

export function clientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  const raw =
    typeof forwarded === 'string'
      ? forwarded.split(',')[0]?.trim()
      : (req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  return raw && isValidIpv4(raw) ? raw : '';
}

class AttackSensor {
  private events: AttackEvent[] = [];
  private rates = new Map<string, { count: number; startedAt: number }>();
  private malicious = new Map<string, { count: number; firstAt: number }>();
  private safeIps = new Set<string>(
    (process.env.SENTINEL_SAFE_IPS ?? '')
      .split(',')
      .map((ip) => ip.trim())
      .filter((ip) => isValidIpv4(ip)),
  );
  private autoDefenseEnabled = true;
  private sensorRequests = 0;
  private lastPrune = 0;
  private broadcast: ((event: AttackEvent, alert?: boolean) => void) | null = null;

  constructor() {
    this.loadState();
  }

  private loadState() {
    try {
      if (!fs.existsSync(SENSOR_STATE_PATH)) return;
      const parsed = JSON.parse(fs.readFileSync(SENSOR_STATE_PATH, 'utf8')) as {
        autoDefenseEnabled?: boolean;
        safeIps?: string[];
      };
      if (typeof parsed.autoDefenseEnabled === 'boolean') {
        this.autoDefenseEnabled = parsed.autoDefenseEnabled;
      }
      for (const ip of parsed.safeIps ?? []) {
        if (isValidIpv4(ip)) this.safeIps.add(ip);
      }
    } catch {
      // Ignore corrupt local sensor state
    }
  }

  private saveState() {
    try {
      fs.writeFileSync(
        SENSOR_STATE_PATH,
        JSON.stringify(
          {
            autoDefenseEnabled: this.autoDefenseEnabled,
            safeIps: Array.from(this.safeIps),
          },
          null,
          2,
        ),
        'utf8',
      );
    } catch {
      // Best-effort persistence
    }
  }

  setBroadcast(fn: (event: AttackEvent, alert?: boolean) => void) {
    this.broadcast = fn;
  }

  setAutoDefense(enabled: boolean) {
    this.autoDefenseEnabled = enabled;
    this.saveState();
  }

  addSafeIp(ip: string): boolean {
    if (!isValidIpv4(ip)) return false;
    this.safeIps.add(ip);
    this.saveState();
    return true;
  }

  removeSafeIp(ip: string): boolean {
    const deleted = this.safeIps.delete(ip);
    if (deleted) this.saveState();
    return deleted;
  }

  getSnapshotSafeIps(): string[] {
    return Array.from(this.safeIps);
  }

  clearEvents(): void {
    this.events = [];
  }

  private isBlockable(ip: string): boolean {
    return isBlockablePublicIp(ip, this.safeIps);
  }

  private prune(now: number) {
    if (
      now - this.lastPrune < 5 * 60_000 &&
      this.rates.size < 5000 &&
      this.malicious.size < 5000
    ) {
      return;
    }
    this.lastPrune = now;
    for (const [ip, entry] of this.rates) {
      if (now - entry.startedAt > 10 * 60_000) this.rates.delete(ip);
    }
    for (const [ip, entry] of this.malicious) {
      if (now - entry.firstAt > 10 * 60_000) this.malicious.delete(ip);
    }
  }

  private record(event: AttackEvent): AttackEvent {
    this.events.unshift(event);
    if (this.events.length > MAX_EVENTS) this.events.length = MAX_EVENTS;
    this.broadcast?.(event, event.action === 'blocked');
    return event;
  }

  private buildSensorEvent(
    req: Request,
    ip: string,
    classification: Classification,
    action: AttackEvent['action'],
    requestCount?: number,
  ): AttackEvent {
    return {
      id: randomUUID(),
      ts: new Date().toISOString(),
      ip: ip || 'unknown',
      method: req.method,
      path: decodeTarget(req).slice(0, 300),
      host: typeof req.headers.host === 'string' ? req.headers.host : undefined,
      userAgent: typeof req.headers['user-agent'] === 'string'
        ? req.headers['user-agent'].slice(0, 240)
        : undefined,
      category: classification.category,
      severity: classification.severity,
      detail: classification.detail,
      action,
      source: 'sensor',
      requestCount,
    };
  }

  private async autoBlock(req: Request, event: AttackEvent): Promise<AttackEvent> {
    if (!this.autoDefenseEnabled) return event;
    if (!this.isBlockable(event.ip)) return event;

    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded !== 'string' || forwarded.trim().length === 0) {
      // Direct proxy/local peer: never auto-block it or the dashboard would lock itself out.
      return event;
    }

    const peer = (req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
    if (peer && event.ip === peer) {
      // Some proxies forward their own address; blocking it would take the site down.
      return event;
    }

    const now = Date.now();
    this.prune(now);
    const entry = this.malicious.get(event.ip);
    const nextCount = entry && now - entry.firstAt < 10 * 60_000 ? entry.count + 1 : 1;
    this.malicious.set(event.ip, {
      count: nextCount,
      firstAt: entry && now - entry.firstAt < 10 * 60_000 ? entry.firstAt : now,
    });

    const immediate =
      event.category === 'honeypot' ||
      event.category === 'rce' ||
      event.category === 'sqli' ||
      event.category === 'ddos';
    if (!immediate && nextCount < AUTO_BLOCK_AFTER) return event;

    const blocked: AttackEvent = { ...event, action: 'blocked' };
    void defenseEngine
      .defendAttackerIp(event.ip, `${event.category}: ${event.detail}`)
      .catch(() => null);
    return blocked;
  }

  private rateExceeded(ip: string): { exceeded: boolean; count: number } {
    if (!ip) return { exceeded: false, count: 0 };
    const now = Date.now();
    this.prune(now);
    const entry = this.rates.get(ip);
    if (!entry || now - entry.startedAt > RATE_WINDOW_MS) {
      this.rates.set(ip, { count: 1, startedAt: now });
      return { exceeded: false, count: 1 };
    }
    entry.count += 1;
    return { exceeded: entry.count > RATE_LIMIT_PER_MINUTE, count: entry.count };
  }

  middleware = async (req: Request, res: Response, next: NextFunction) => {
    if (isStaticAssetPath(req.path)) {
      next();
      return;
    }
    this.sensorRequests += 1;
    const ip = clientIp(req);
    const rate = this.rateExceeded(ip);

    if (rate.exceeded) {
      const event = this.buildSensorEvent(
        req,
        ip,
        {
          category: 'ddos',
          severity: 'CRITICAL',
          detail: `Request flood: ${rate.count} requests in 60s from one source`,
          honeypot: false,
        },
        'blocked',
        rate.count,
      );
      const blocked = await this.autoBlock(req, event);
      this.record(blocked);
      res.status(429).json({
        blocked: true,
        shield: 'SentinelGlobe Rate Shield',
        message: 'Request rate exceeded. This source has been added to the active defense queue.',
      });
      return;
    }

    const classification = classifyAttack({
      path: req.path,
      query: req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '',
      userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '',
      method: req.method,
    });

    if (classification.category === 'other') {
      next();
      return;
    }

    const isApi = req.path.startsWith('/api/') || req.path.startsWith('/socket.io/');
    const event = this.buildSensorEvent(req, ip, classification, 'observed');

    if (classification.honeypot) {
      const blocked = await this.autoBlock(req, event);
      const tarpitted: AttackEvent = {
        ...blocked,
        action: blocked.action === 'blocked' ? 'blocked' : 'tarpitted',
      };
      this.record(tarpitted);
      this.tarpitResponse(req, res, classification);
      return;
    }

    // Dashboard/API traffic is observed, never blocked here: a search for an XSS
    // payload must not lock the operator out of the console.
    if (isApi) {
      this.record(event);
      next();
      return;
    }

    const blocked = await this.autoBlock(req, event);
    if (blocked.action === 'blocked') {
      this.record(blocked);
      res.status(403).json({
        blocked: true,
        shield: 'SentinelGlobe Active Defense Grid',
        message: 'Malicious request signature matched. Source added to the defense blocklist.',
      });
      return;
    }

    this.record(event);
    next();
  };

  private tarpitResponse(req: Request, res: Response, classification: Classification) {
    const path = req.path.toLowerCase();
    const send = () => {
      if (res.headersSent) return;
      if (path.includes('.env')) {
        res
          .status(200)
          .type('text/plain')
          .send(
            [
              'APP_ENV=production',
              'APP_DEBUG=false',
              'DB_HOST=127.0.0.1',
              'DB_USER=sentinel_decoy',
              'DB_PASSWORD=DECOY_VALUE_NOT_A_REAL_SECRET',
              'REDIS_HOST=127.0.0.1',
            ].join('\n'),
          );
        return;
      }
      if (path.includes('.git')) {
        res
          .status(200)
          .type('text/plain')
          .send('[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n');
        return;
      }
      if (path.includes('login') || path.includes('admin')) {
        res
          .status(200)
          .type('html')
          .send(
            '<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1><form method="post"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form></body></html>',
          );
        return;
      }
      if (path.includes('actuator') || path.includes('config.json')) {
        res.status(200).json({ status: 'UP', sentinel: 'decoy', trace: classification.category });
        return;
      }
      res
        .status(404)
        .type('html')
        .send('<!doctype html><html><body><h1>Not Found</h1></body></html>');
    };

    setTimeout(send, TARPIT_MS);
  }

  private buildFeedEvents(): AttackEvent[] {
    const events: AttackEvent[] = [];
    const snapshot: RadarSnapshot | null = threatMonitor.getCachedSnapshot();
    if (!snapshot) return events;

    for (const node of snapshot.threatNodes.slice(0, 40)) {
      events.push({
        id: `feed-${node.id}`,
        ts: snapshot.scannedAt,
        ip: node.ip,
        method: 'FEED',
        path: node.threatType,
        category: categoryForThreatNode(node),
        severity: node.severity,
        detail: `${node.threatType} · ${node.sourceFeed}`,
        action: defenseEngine.isIpBlocked(node.ip) ? 'blocked' : 'observed',
        source: 'feed',
        country: node.country,
        city: node.city,
        asn: node.asn,
        isp: node.isp,
        abuseEmails: node.abuseEmails,
      });
    }

    for (const trap of snapshot.phishingTraps.slice(0, 15)) {
      events.push({
        id: `feed-${trap.url}`,
        ts: trap.detectedAt,
        ip: trap.host,
        method: 'FEED',
        path: trap.url.slice(0, 300),
        category: 'phishing',
        severity: trap.severity,
        detail: `Live phishing trap · OpenPhish${trap.riskReasons[0] ? ` · ${trap.riskReasons[0]}` : ''}`,
        action: 'observed',
        source: 'feed',
        country: '—',
        city: '—',
      });
    }

    return events;
  }

  async getSnapshot(): Promise<DefenseGridSnapshot> {
    const sensorEvents = [...this.events];
    const feedEvents = this.buildFeedEvents();
    const all = [...sensorEvents, ...feedEvents]
      .sort((a, b) => b.ts.localeCompare(a.ts))
      .slice(0, 250);

    const attackers = new Map<string, DefenseGridAttacker>();
    const categoryCounts = new Map<AttackCategory, number>();
    for (const event of all) {
      categoryCounts.set(event.category, (categoryCounts.get(event.category) ?? 0) + 1);
      const existing = attackers.get(event.ip);
      if (!existing) {
        attackers.set(event.ip, {
          ip: event.ip,
          count: 1,
          category: event.category,
          severity: event.severity,
          country: event.country,
          city: event.city,
          blocked: event.action === 'blocked',
        });
      } else {
        existing.count += 1;
        if (severityRank(event.severity) > severityRank(existing.severity)) {
          existing.severity = event.severity;
          existing.category = event.category;
        }
        existing.blocked = existing.blocked || event.action === 'blocked';
      }
    }

    const lastMinute = Date.now() - 60_000;
    const stats = {
      totalEvents: all.length,
      blocked: all.filter((e) => e.action === 'blocked').length,
      tarpitted: all.filter((e) => e.action === 'tarpitted').length,
      uniqueAttackers: attackers.size,
      eventsLastMinute: all.filter((e) => new Date(e.ts).getTime() >= lastMinute).length,
      sensorRequests: this.sensorRequests,
      autoDefenseEnabled: this.autoDefenseEnabled,
      safeIps: Array.from(this.safeIps),
    };

    return {
      events: all,
      stats,
      topAttackers: Array.from(attackers.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      categoryCounts: Array.from(categoryCounts.entries())
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count),
      protectedSites: defenseEngine.getState().protectedShields,
      generatedAt: new Date().toISOString(),
    };
  }

  getProtectedSites(): ProtectedSystemShield[] {
    return defenseEngine.getState().protectedShields;
  }

  async buildAbuseReport(ip: string): Promise<{ report: string; abuseEmails: string[] }> {
    const clean = ip.trim();
    if (!isValidIpv4(clean)) {
      return { report: 'Valid IPv4 address required.', abuseEmails: [] };
    }
    const [trace, rdap, snapshot] = await Promise.all([
      traceAttackerIp(clean).catch(() => null),
      lookupRdapIpAbuse(clean),
      this.getSnapshot().catch(() => null),
    ]);
    const events = snapshot?.events.filter((e) => e.ip === clean) ?? [];
    const categories = Array.from(new Set(events.map((e) => e.category))).join(', ') || 'unknown';
    const lines = [
      'SentinelGlobe — Automated Abuse Report',
      `Generated: ${new Date().toISOString()}`,
      `Attacker IP: ${clean}`,
      `ASN / ISP: ${trace?.asn ?? rdap.handle ?? 'unknown'} / ${trace?.isp ?? 'unknown'}`,
      `Location: ${[trace?.city, trace?.country].filter(Boolean).join(', ') || 'unknown'}`,
      `Abuse contacts: ${rdap.abuseEmails.join(', ') || 'not published'}`,
      `Observed events: ${events.length}`,
      `Categories: ${categories}`,
      `Firewall rules:`,
      generateFirewallRulesForIp(clean).iptables,
      '',
      'Requested action: investigate the source and suspend abusive traffic.',
      'Evidence: request paths, timestamps and signatures are retained by SentinelGlobe.',
    ];
    return { report: lines.join('\n'), abuseEmails: rdap.abuseEmails };
  }
}

export const attackSensor = new AttackSensor();
