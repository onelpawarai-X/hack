import type { NextFunction, Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import type {
  BlockedDomainEntry,
  BlockedIpEntry,
  DefenseStateSnapshot,
  ProtectedSystemShield,
  TargetScanResult,
} from '../src/types/cyber.ts';
import { scanTargetOrWeb, traceAttackerIp } from './scanner.ts';
import { isValidIpv4 } from './threatRules.ts';

const STATE_FILE_PATH = path.resolve(process.cwd(), '.sentinel-defense-state.json');

interface PersistedDefenseData {
  blockedIps: BlockedIpEntry[];
  blockedDomains: BlockedDomainEntry[];
  protectedShields: ProtectedSystemShield[];
}

export function generateFirewallRulesForIp(ip: string): BlockedIpEntry['firewallRules'] {
  return {
    nginx: `deny ${ip};`,
    iptables: `iptables -I INPUT -s ${ip} -j DROP && iptables -I FORWARD -s ${ip} -j DROP`,
    ufw: `ufw insert 1 deny from ${ip} to any`,
    cloudflare: `(ip.src eq ${ip})`,
  };
}

export function generateGlobalFirewallBundle(
  blockedIps: BlockedIpEntry[],
  blockedDomains: BlockedDomainEntry[],
): DefenseStateSnapshot['globalFirewallBundle'] {
  const ips = blockedIps.map((b) => b.ip);
  const domains = blockedDomains.map((d) => d.domain);

  const nginxDenyList =
    ips.length > 0
      ? [
          '# SentinelGlobe Active Threat Blocklist (Nginx)',
          ...ips.map((ip) => `deny ${ip};`),
        ].join('\n')
      : '# No blocked attacker IPs yet';

  const iptablesScript =
    ips.length > 0
      ? [
          '#!/usr/bin/env bash',
          '# SentinelGlobe Linux Netfilter Defense Rules',
          ...ips.map((ip) => `iptables -I INPUT -s ${ip} -j DROP`),
        ].join('\n')
      : '#!/usr/bin/env bash\n# No blocked attacker IPs yet';

  const dnsSinkholeHosts =
    domains.length > 0
      ? [
          '# SentinelGlobe DNS Sinkhole (/etc/hosts & Pi-hole)',
          ...domains.map((d) => `0.0.0.0 ${d}`),
        ].join('\n')
      : '# No sinkholed phishing domains yet';

  const cloudflareWafExpr =
    ips.length > 0
      ? `(ip.src in {${ips.join(' ')}})`
      : '(false)';

  return {
    nginxDenyList,
    iptablesScript,
    dnsSinkholeHosts,
    cloudflareWafExpr,
  };
}

export function generateNginxHardeningConfig(scan: TargetScanResult): string {
  const missing = new Set(scan.httpAudit?.missingSecurityHeaders ?? []);
  const lines = [
    `# SentinelGlobe Defense Shield Hardening for ${scan.normalizedTarget}`,
    'server_tokens off;',
  ];

  if (missing.has('strict-transport-security') || scan.httpAudit === null) {
    lines.push(
      'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    );
  }
  if (missing.has('content-security-policy') || scan.httpAudit === null) {
    lines.push(
      'add_header Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\'; object-src \'none\'; base-uri \'self\';" always;',
    );
  }
  if (missing.has('x-frame-options') || scan.httpAudit === null) {
    lines.push('add_header X-Frame-Options "DENY" always;');
  }
  if (missing.has('x-content-type-options') || scan.httpAudit === null) {
    lines.push('add_header X-Content-Type-Options "nosniff" always;');
  }
  if (missing.has('referrer-policy') || scan.httpAudit === null) {
    lines.push('add_header Referrer-Policy "strict-origin-when-cross-origin" always;');
  }
  if (missing.has('permissions-policy') || scan.httpAudit === null) {
    lines.push(
      'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    );
  }

  lines.push('limit_req_zone $binary_remote_addr zone=sentinel_shield:10m rate=20r/s;');
  return lines.join('\n');
}

export function generateRecommendedDnsRecords(scan: TargetScanResult, host: string): string[] {
  const records: string[] = [];
  if (scan.dns.emailSecurityStatus !== 'protected') {
    if (!scan.dns.spfRecord) {
      records.push(`${host}.  TXT  "v=spf1 -all"`);
    } else if (scan.dns.spfRecord.includes('~all') || scan.dns.spfRecord.includes('+all')) {
      records.push(
        `${host}.  TXT  "${scan.dns.spfRecord.replace(/\+all|~all/i, '-all')}"`,
      );
    }
    if (!scan.dns.dmarcRecord) {
      records.push(
        `_dmarc.${host}.  TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"`,
      );
    } else if (/p=none/i.test(scan.dns.dmarcRecord)) {
      records.push(
        `_dmarc.${host}.  TXT  "${scan.dns.dmarcRecord.replace(/p=none/i, 'p=quarantine')}"`,
      );
    }
  }
  if (scan.dns.caa.length === 0) {
    records.push(`${host}.  CAA  0 issue "letsencrypt.org"`);
  }
  return records;
}

export async function lookupRdapIpAbuse(ip: string): Promise<{
  cidr?: string;
  handle?: string;
  abuseEmails: string[];
}> {
  if (!isValidIpv4(ip)) return { abuseEmails: [] };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6500);
    try {
      const res = await fetch(`https://rdap-bootstrap.arin.net/bootstrap/ip/${encodeURIComponent(ip)}`, {
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'SentinelGlobe-DefenseEngine/1.0',
        },
      });
      if (!res.ok) return { abuseEmails: [] };
      const json = (await res.json()) as {
        handle?: string;
        startAddress?: string;
        endAddress?: string;
        cidr0_cidrs?: Array<{ v4prefix?: string; length?: number }>;
      };
      const rawStr = JSON.stringify(json);
      const emailMatches = rawStr.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
      const sortedEmails = Array.from(new Set(emailMatches.map((e) => e.toLowerCase()))).sort(
        (a, b) => {
          const aAbuse = a.includes('abuse') || a.includes('security') ? 0 : 1;
          const bAbuse = b.includes('abuse') || b.includes('security') ? 0 : 1;
          return aAbuse - bAbuse;
        },
      );
      const cidrObj = json.cidr0_cidrs?.[0];
      const cidr =
        cidrObj?.v4prefix && typeof cidrObj.length === 'number'
          ? `${cidrObj.v4prefix}/${cidrObj.length}`
          : json.startAddress && json.endAddress
            ? `${json.startAddress} - ${json.endAddress}`
            : undefined;

      return {
        cidr,
        handle: json.handle,
        abuseEmails: sortedEmails.slice(0, 5),
      };
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return { abuseEmails: [] };
  }
}

export async function lookupRdapDomainAbuse(domain: string): Promise<string[]> {
  try {
    const clean = domain.toLowerCase().replace(/^www\./, '');
    const tld = clean.split('.').pop() || '';
    const rdapUrl =
      tld === 'com' || tld === 'net'
        ? `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(clean)}`
        : `https://rdap.org/domain/${encodeURIComponent(clean)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5500);
    try {
      const res = await fetch(rdapUrl, {
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          Accept: 'application/rdap+json, application/json',
          'User-Agent': 'SentinelGlobe-DefenseEngine/1.0',
        },
      });
      if (!res.ok) return [];
      const raw = await res.text();
      const emails = raw.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? [];
      return Array.from(new Set(emails.map((e) => e.toLowerCase())))
        .sort((a, b) => {
          const aAbuse = a.includes('abuse') ? 0 : 1;
          const bAbuse = b.includes('abuse') ? 0 : 1;
          return aAbuse - bAbuse;
        })
        .slice(0, 5);
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return [];
  }
}

class DefenseEngine {
  private blockedIps = new Map<string, BlockedIpEntry>();
  private blockedDomains = new Map<string, BlockedDomainEntry>();
  private protectedShields = new Map<string, ProtectedSystemShield>();
  private watchdogTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.loadFromDisk();
  }

  private loadFromDisk() {
    try {
      if (!fs.existsSync(STATE_FILE_PATH)) return;
      const raw = fs.readFileSync(STATE_FILE_PATH, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedDefenseData>;
      for (const ipEntry of parsed.blockedIps ?? []) {
        if (ipEntry?.ip) this.blockedIps.set(ipEntry.ip, ipEntry);
      }
      for (const domEntry of parsed.blockedDomains ?? []) {
        if (domEntry?.domain) this.blockedDomains.set(domEntry.domain, domEntry);
      }
      for (const shield of parsed.protectedShields ?? []) {
        if (shield?.id) this.protectedShields.set(shield.id, shield);
      }
    } catch {
      // Ignore corrupt local defense state file
    }
  }

  private saveToDisk() {
    try {
      const payload: PersistedDefenseData = {
        blockedIps: Array.from(this.blockedIps.values()),
        blockedDomains: Array.from(this.blockedDomains.values()),
        protectedShields: Array.from(this.protectedShields.values()),
      };
      fs.writeFileSync(STATE_FILE_PATH, JSON.stringify(payload, null, 2), 'utf8');
    } catch {
      // Best-effort persistence
    }
  }

  startWatchdog() {
    if (this.watchdogTimer) return;
    this.watchdogTimer = setInterval(() => {
      void this.recheckAllWatchdogs();
    }, 120_000);
  }

  isIpBlocked(ip: string): boolean {
    return this.blockedIps.has(ip);
  }

  middleware = (req: Request, res: Response, next: NextFunction) => {
    const fwd = req.headers['x-forwarded-for'];
    const clientIpRaw =
      typeof fwd === 'string'
        ? fwd.split(',')[0].trim()
        : (req.ip || req.socket.remoteAddress || '').replace(/^::ffff:/, '');

    if (clientIpRaw && this.blockedIps.has(clientIpRaw)) {
      res.status(403).json({
        blocked: true,
        shield: 'SentinelGlobe Active Defense Firewall',
        ip: clientIpRaw,
        reason: this.blockedIps.get(clientIpRaw)?.reason,
      });
      return;
    }
    next();
  };

  getState(): DefenseStateSnapshot {
    const blockedIps = Array.from(this.blockedIps.values()).sort((a, b) =>
      b.blockedAt.localeCompare(a.blockedAt),
    );
    const blockedDomains = Array.from(this.blockedDomains.values()).sort((a, b) =>
      b.sinkholedAt.localeCompare(a.sinkholedAt),
    );
    const protectedShields = Array.from(this.protectedShields.values()).sort((a, b) =>
      b.activatedAt.localeCompare(a.activatedAt),
    );
    return {
      blockedIps,
      blockedDomains,
      protectedShields,
      globalFirewallBundle: generateGlobalFirewallBundle(blockedIps, blockedDomains),
    };
  }

  async defendAttackerIp(ip: string, reason?: string): Promise<BlockedIpEntry> {
    const cleanIp = ip.trim();
    const [trace, rdap] = await Promise.all([
      traceAttackerIp(cleanIp).catch(() => null),
      lookupRdapIpAbuse(cleanIp),
    ]);

    const now = new Date().toISOString();
    const entry: BlockedIpEntry = {
      ip: cleanIp,
      blockedAt: this.blockedIps.get(cleanIp)?.blockedAt ?? now,
      lastCheckedAt: now,
      reason:
        reason?.trim() ||
        trace?.threatType ||
        'Blocked by SentinelGlobe Active Defense Shield',
      severity: trace?.severity ?? 'HIGH',
      country: trace?.country,
      city: trace?.city,
      physicalAddress: trace?.physicalAddress,
      asn: trace?.asn,
      isp: trace?.isp,
      cidr: rdap.cidr,
      abuseEmails: rdap.abuseEmails,
      openPorts: trace?.openPorts ?? [],
      knownVulns: trace?.knownVulns ?? [],
      watchdogStatus: 'blocked-monitoring',
      firewallRules: generateFirewallRulesForIp(cleanIp),
    };

    this.blockedIps.set(cleanIp, entry);
    this.saveToDisk();
    return entry;
  }

  unblockIp(ip: string): boolean {
    const deleted = this.blockedIps.delete(ip.trim());
    if (deleted) this.saveToDisk();
    return deleted;
  }

  async takedownPhishingTarget(target: string, reason?: string): Promise<BlockedDomainEntry> {
    const raw = target.trim();
    let domain = raw.toLowerCase();
    let fullUrl: string | undefined;

    try {
      const parsed = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
      domain = parsed.hostname.toLowerCase();
      if (/^https?:\/\//i.test(raw)) fullUrl = parsed.toString();
    } catch {
      domain = raw.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }

    const [scan, domainAbuseEmails] = await Promise.all([
      scanTargetOrWeb(fullUrl || domain).catch(() => null),
      lookupRdapDomainAbuse(domain),
    ]);

    const resolvedIps = scan?.dns.a.filter((ip) => isValidIpv4(ip)) ?? [];
    const ipAbuseLookups = await Promise.all(
      resolvedIps.slice(0, 2).map((ip) => lookupRdapIpAbuse(ip)),
    );

    const allAbuseEmails = Array.from(
      new Set([
        ...domainAbuseEmails,
        ...ipAbuseLookups.flatMap((r) => r.abuseEmails),
      ]),
    ).slice(0, 6);

    // Also block hosting IPs found if target was flagged in threat feeds
    if (scan && (scan.verdict === 'CRITICAL' || scan.verdict === 'HIGH')) {
      for (const ip of resolvedIps.slice(0, 2)) {
        if (!this.blockedIps.has(ip)) {
          await this.defendAttackerIp(ip, `Hosting infrastructure for malicious domain ${domain}`);
        }
      }
    }

    const entry: BlockedDomainEntry = {
      domain,
      fullUrl,
      sinkholedAt: new Date().toISOString(),
      reason:
        reason?.trim() ||
        scan?.verdictReasons[0] ||
        'Phishing / Threat Infrastructure Sinkholed',
      resolvedIps,
      abuseEmails: allAbuseEmails,
      hostsEntry: `0.0.0.0 ${domain}`,
      piholeRule: `||${domain}^`,
      safeBrowsingUrl: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(
        fullUrl || `https://${domain}`,
      )}`,
      netcraftReportUrl: `https://report.netcraft.com/report?url=${encodeURIComponent(
        fullUrl || `https://${domain}`,
      )}`,
    };

    this.blockedDomains.set(domain, entry);
    this.saveToDisk();
    return entry;
  }

  removeBlockedDomain(domain: string): boolean {
    const deleted = this.blockedDomains.delete(domain.trim().toLowerCase());
    if (deleted) this.saveToDisk();
    return deleted;
  }

  async activateWebsiteShield(target: string): Promise<ProtectedSystemShield> {
    const scan = await scanTargetOrWeb(target.trim());
    let host = scan.normalizedTarget.toLowerCase();
    try {
      const u = new URL(/^https?:\/\//i.test(scan.normalizedTarget) ? scan.normalizedTarget : `https://${scan.normalizedTarget}`);
      host = u.hostname.toLowerCase();
    } catch {
      host = scan.normalizedTarget.split('/')[0].toLowerCase();
    }

    const id = `shield-${host}`;
    const existing = this.protectedShields.get(id);
    const now = new Date().toISOString();

    const baselineA = existing?.baselineA.length ? existing.baselineA : scan.dns.a;
    const dnsChanged =
      existing &&
      existing.baselineA.length > 0 &&
      scan.dns.a.length > 0 &&
      scan.dns.a.some((ip) => !existing.baselineA.includes(ip));

    const hasAlert =
      scan.verdict === 'CRITICAL' ||
      scan.verdict === 'HIGH' ||
      scan.tls?.valid === false ||
      Boolean(dnsChanged);

    let alertReason: string | undefined;
    if (dnsChanged) {
      alertReason = `DNS A-record changed from [${existing!.baselineA.join(', ')}] to [${scan.dns.a.join(', ')}]`;
    } else if (scan.feedMatches.length > 0) {
      alertReason = scan.feedMatches.map((m) => m.feed).join(', ');
    } else if (scan.tls?.valid === false) {
      alertReason = scan.tls.error || 'TLS Certificate Invalid';
    }

    const shield: ProtectedSystemShield = {
      id,
      target: scan.normalizedTarget,
      host,
      activatedAt: existing?.activatedAt ?? now,
      lastCheckedAt: now,
      verdict: scan.verdict,
      tlsValid: scan.tls ? scan.tls.valid : null,
      tlsDaysRemaining: scan.tls?.daysRemaining,
      missingHeadersCount: scan.httpAudit?.missingSecurityHeaders.length ?? 0,
      emailSecurityStatus: scan.dns.emailSecurityStatus,
      baselineA,
      status: hasAlert ? 'alert' : 'shielded',
      alertReason,
      nginxHardeningConfig: generateNginxHardeningConfig(scan),
      recommendedDnsRecords: generateRecommendedDnsRecords(scan, host),
    };

    this.protectedShields.set(id, shield);
    this.saveToDisk();
    return shield;
  }

  async recheckShieldById(id: string): Promise<ProtectedSystemShield | null> {
    const existing = this.protectedShields.get(id);
    if (!existing) return null;
    return this.activateWebsiteShield(existing.target);
  }

  removeShield(id: string): boolean {
    const deleted = this.protectedShields.delete(id);
    if (deleted) this.saveToDisk();
    return deleted;
  }

  async recheckAllWatchdogs(): Promise<void> {
    const shields = Array.from(this.protectedShields.values()).slice(0, 5);
    for (const s of shields) {
      await this.recheckShieldById(s.id).catch(() => null);
    }
  }
}

export const defenseEngine = new DefenseEngine();
