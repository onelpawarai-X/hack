import type {
  CyberIncident,
  ExploitedCve,
  HardeningRecommendation,
  PhishingTrap,
  ThreatSeverity,
} from '../src/types/cyber.ts';

const IPV4_REGEX =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

const DOMAIN_REGEX =
  /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,})+)\b/gi;

export interface FeodoRawRecord {
  ip_address?: string;
  port?: number;
  status?: string;
  hostname?: string | null;
  as_number?: number;
  as_name?: string;
  country?: string;
  first_seen?: string;
  last_online?: string;
  malware?: string;
}

export function parseIpBlocklistText(raw: string): Set<string> {
  const result = new Set<string>();
  if (!raw) return result;
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
    const match = trimmed.match(/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/);
    if (match) {
      result.add(trimmed);
    }
  }
  return result;
}

export function isValidIpv4(value: string): boolean {
  return /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(
    value.trim(),
  );
}

export function isPrivateOrReservedIp(ip: string): boolean {
  if (!isValidIpv4(ip)) return true;
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

const BRAND_LURES = [
  'paypal',
  'microsoft',
  'office365',
  'google',
  'apple',
  'icloud',
  'metamask',
  'coinbase',
  'binance',
  'amazon',
  'facebook',
  'instagram',
  'whatsapp',
  'netflix',
  'chase',
  'bankofamerica',
  'dhl',
  'fedex',
  'steam',
  'telegram',
];

const FREE_HOST_ABUSE_DOMAINS = [
  'weeblysite.com',
  'weebly.com',
  'gitbook.io',
  'blogspot.com',
  'pages.dev',
  'workers.dev',
  'netlify.app',
  'vercel.app',
  'firebaseapp.com',
  'web.app',
  'duckdns.org',
  'ngrok-free.app',
  'trycloudflare.com',
];

export function analyzeUrlTrapHeuristics(rawUrl: string): string[] {
  const reasons: string[] = [];
  let parsed: URL | null = null;
  try {
    parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return reasons;
  }

  const host = parsed.hostname.toLowerCase();
  const full = parsed.href.toLowerCase();

  if (parsed.protocol === 'http:') {
    reasons.push('Unencrypted HTTP transport');
  }
  if (isValidIpv4(host)) {
    reasons.push('Raw IP host instead of verified domain');
  }
  if (host.includes('xn--')) {
    reasons.push('Punycode / IDN homograph pattern');
  }
  if (parsed.username || parsed.password || full.includes('@')) {
    reasons.push('Credential-masking @ URI pattern');
  }
  if (host.split('.').length >= 5) {
    reasons.push('Excessive subdomain nesting');
  }
  for (const brand of BRAND_LURES) {
    if (host.includes(brand) && !host.endsWith(`${brand}.com`) && !host.endsWith(`${brand}.io`) && !host.endsWith(`${brand}.org`)) {
      reasons.push(`Potential "${brand}" brand impersonation`);
      break;
    }
  }
  for (const abuseHost of FREE_HOST_ABUSE_DOMAINS) {
    if (host.endsWith(abuseHost) && (full.includes('login') || full.includes('verify') || full.includes('wallet') || full.includes('auth') || reasons.length > 0)) {
      reasons.push(`Abused free hosting (${abuseHost})`);
      break;
    }
  }
  if (/\.(exe|apk|scr|bat|ps1|vbs|zip|iso)$/i.test(parsed.pathname)) {
    reasons.push('Direct executable/archive payload path');
  }

  return reasons;
}

export function parseOpenPhishFeed(raw: string, timestamp: string): {
  traps: PhishingTrap[];
  urlSet: Set<string>;
  hostSet: Set<string>;
} {
  const traps: PhishingTrap[] = [];
  const urlSet = new Set<string>();
  const hostSet = new Set<string>();

  if (!raw) return { traps, urlSet, hostSet };

  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const url = line.trim();
    if (!url || !/^https?:\/\//i.test(url)) continue;
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      urlSet.add(url.toLowerCase());
      hostSet.add(host);

      if (traps.length < 40) {
        const heuristicReasons = analyzeUrlTrapHeuristics(url);
        const riskReasons = [
          'Active OpenPhish Credential Trap',
          ...heuristicReasons.slice(0, 2),
        ];
        traps.push({
          id: `phish-${traps.length + 1}-${host}`,
          url,
          host,
          sourceFeed: 'OpenPhish',
          severity: 'CRITICAL',
          riskReasons,
          detectedAt: timestamp,
        });
      }
    } catch {
      // skip malformed line
    }
  }

  return { traps, urlSet, hostSet };
}

export function parseCisaKevCatalog(rawJson: unknown): ExploitedCve[] {
  const data = rawJson as {
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
  };
  const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  // Sort newest dateAdded first
  const sorted = [...list].sort((a, b) =>
    String(b.dateAdded ?? '').localeCompare(String(a.dateAdded ?? '')),
  );
  return sorted.slice(0, 20).map((item) => ({
    cveID: String(item.cveID ?? ''),
    vendorProject: String(item.vendorProject ?? 'Unknown'),
    product: String(item.product ?? 'Unknown'),
    vulnerabilityName: String(item.vulnerabilityName ?? ''),
    dateAdded: String(item.dateAdded ?? ''),
    dueDate: String(item.dueDate ?? ''),
    knownRansomware: String(item.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known',
    shortDescription: String(item.shortDescription ?? ''),
  }));
}

export function extractTargetIdentifiers(text: string): string[] {
  const found = new Set<string>();
  if (!text) return [];
  const ips = text.match(IPV4_REGEX) ?? [];
  for (const ip of ips) {
    if (!isPrivateOrReservedIp(ip)) found.add(ip);
  }
  const domains = text.match(DOMAIN_REGEX) ?? [];
  for (const d of domains) {
    const clean = d.toLowerCase();
    if (
      clean.length >= 4 &&
      !/\.(png|jpg|jpeg|gif|svg|css|js|xml|json|pdf)$/i.test(clean)
    ) {
      found.add(clean);
    }
  }
  return Array.from(found).slice(0, 5);
}

export function classifyIncidentSeverity(title: string, summary: string): CyberIncident['severity'] {
  const text = `${title} ${summary}`.toLowerCase();
  if (
    /\b(ransomware|zero-day|0-day|breach|compromised|botnet|ddos|backdoor|critical|exploited|apt|wiper|stealer)\b/.test(
      text,
    )
  ) {
    return 'CRITICAL';
  }
  if (/\b(phishing|vulnerability|flaw|attack|hack|malware|trojan|c2|cve-)\b/.test(text)) {
    return 'HIGH';
  }
  return 'ELEVATED';
}

export function computeTargetVerdict(params: {
  feedMatches: Array<{ feed: string; detail: string }>;
  heuristicWarnings: string[];
  tlsValid: boolean | null;
  missingSecurityHeadersCount: number;
  webBreachMatchesCount: number;
}): { verdict: ThreatSeverity; reasons: string[] } {
  const reasons: string[] = [];

  if (params.feedMatches.length > 0) {
    for (const match of params.feedMatches) {
      reasons.push(`${match.feed}: ${match.detail}`);
    }
    return { verdict: 'CRITICAL', reasons };
  }

  if (params.heuristicWarnings.length >= 2) {
    reasons.push(...params.heuristicWarnings);
    return { verdict: 'HIGH', reasons };
  }

  if (params.tlsValid === false) {
    reasons.push('TLS certificate invalid, expired, or unavailable on HTTPS');
  }
  if (params.heuristicWarnings.length === 1) {
    reasons.push(params.heuristicWarnings[0]);
  }
  if (params.missingSecurityHeadersCount >= 3) {
    reasons.push(
      `Missing ${params.missingSecurityHeadersCount} core HTTP security headers (HSTS/CSP/X-Frame-Options)`,
    );
  }
  if (params.webBreachMatchesCount >= 2) {
    reasons.push(
      `Referenced in ${params.webBreachMatchesCount} recent web security/breach dispatches`,
    );
  }

  if (reasons.length >= 2 || params.tlsValid === false) {
    return { verdict: 'ELEVATED', reasons };
  }
  if (reasons.length === 1) {
    return { verdict: 'ELEVATED', reasons };
  }

  return {
    verdict: 'CLEAN',
    reasons: [
      'No matches across Blocklist.de, CINS Army, Feodo Tracker C2, or OpenPhish live feeds',
    ],
  };
}

export function auditEmailDnsSecurity(
  txtRecords: string[],
  dmarcRecords: string[],
): {
  spfRecord: string | null;
  dmarcRecord: string | null;
  emailSecurityStatus: 'protected' | 'weak' | 'missing';
} {
  const spfRecord =
    txtRecords.find((r) => r.toLowerCase().includes('v=spf1')) ?? null;
  const dmarcRecord =
    dmarcRecords.find((r) => r.toLowerCase().includes('v=dmarc1')) ?? null;

  if (!spfRecord && !dmarcRecord) {
    return { spfRecord, dmarcRecord, emailSecurityStatus: 'missing' };
  }
  const spfPermissive = spfRecord ? /\+all\b/i.test(spfRecord) : true;
  const dmarcMonitorOnly = dmarcRecord ? /\bp=none\b/i.test(dmarcRecord) : true;
  if (!spfRecord || !dmarcRecord || spfPermissive || dmarcMonitorOnly) {
    return { spfRecord, dmarcRecord, emailSecurityStatus: 'weak' };
  }
  return { spfRecord, dmarcRecord, emailSecurityStatus: 'protected' };
}

export function generateHardeningRecommendations(params: {
  targetType: 'url' | 'domain' | 'ip' | 'cve' | 'search';
  feedMatches: Array<{ feed: string; detail: string }>;
  tlsValid: boolean | null;
  tlsDaysRemaining?: number;
  missingSecurityHeaders: string[];
  cookieIssues: string[];
  emailSecurityStatus?: 'protected' | 'weak' | 'missing';
  knownVulnsCount: number;
  openPorts: number[];
}): HardeningRecommendation[] {
  const recs: HardeningRecommendation[] = [];

  if (params.feedMatches.length > 0) {
    recs.push({
      id: 'block-ioc',
      severity: 'CRITICAL',
      title: 'Immediate Firewall / DNS Block & Incident Containment',
      remediation:
        'Block this IP/URL across perimeter firewall, WAF, and DNS resolvers immediately; inspect outbound logs for lateral C2 beaconing or credential submission.',
    });
  }

  if (params.knownVulnsCount > 0) {
    recs.push({
      id: 'patch-cves',
      severity: 'CRITICAL',
      title: `Patch ${params.knownVulnsCount} Known Host Vulnerabilities (CVEs)`,
      remediation:
        'Update exposed services and OS packages indexed on this IP immediately, prioritizing CVEs listed in CISA KEV and restricting management ports via VPN/ACL.',
    });
  }

  const riskyPorts = params.openPorts.filter((p) =>
    [21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017].includes(p),
  );
  if (riskyPorts.length > 0) {
    recs.push({
      id: 'close-exposed-ports',
      severity: 'HIGH',
      title: `Restrict Exposed Administrative / Database Ports (${riskyPorts.join(', ')})`,
      remediation:
        'Bind database, SSH, RDP, and SMB ports to private VPC/VPN interfaces or strict source IP allowlists instead of public internet exposure.',
    });
  }

  if (params.tlsValid === false) {
    recs.push({
      id: 'fix-tls',
      severity: 'HIGH',
      title: 'Deploy Valid TLS 1.3 Certificate & Enforce HTTPS Redirect',
      remediation:
        'Issue an automated trusted X.509 certificate (e.g., Let’s Encrypt ACME), disable TLS 1.0/1.1, and enforce 301 HTTP-to-HTTPS redirection.',
    });
  } else if (
    typeof params.tlsDaysRemaining === 'number' &&
    params.tlsDaysRemaining < 14
  ) {
    recs.push({
      id: 'renew-tls',
      severity: 'MEDIUM',
      title: `Renew Expiring TLS Certificate (${params.tlsDaysRemaining} days left)`,
      remediation:
        'Verify ACME auto-renewal daemon or load-balancer certificate rotation before service outage occurs.',
    });
  }

  if (params.missingSecurityHeaders.length > 0) {
    recs.push({
      id: 'harden-headers',
      severity: params.missingSecurityHeaders.length >= 3 ? 'HIGH' : 'MEDIUM',
      title: `Configure Missing HTTP Security Headers (${params.missingSecurityHeaders.join(', ')})`,
      remediation:
        'Add Strict-Transport-Security (max-age=31536000; includeSubDomains), Content-Security-Policy, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff at reverse proxy/CDN.',
    });
  }

  if (params.cookieIssues.length > 0) {
    recs.push({
      id: 'harden-cookies',
      severity: 'MEDIUM',
      title: 'Harden Session Cookies (HttpOnly, Secure, SameSite)',
      remediation:
        'Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all authentication and session cookies to mitigate XSS theft and CSRF.',
    });
  }

  if (
    (params.targetType === 'domain' || params.targetType === 'url') &&
    params.emailSecurityStatus &&
    params.emailSecurityStatus !== 'protected'
  ) {
    recs.push({
      id: 'enforce-dmarc-spf',
      severity: params.emailSecurityStatus === 'missing' ? 'HIGH' : 'MEDIUM',
      title: 'Enforce SPF & DMARC Email Anti-Spoofing Policy',
      remediation:
        'Publish a strict TXT SPF record (-all / ~all) and _dmarc TXT policy with p=quarantine or p=reject to stop attackers spoofing your domain.',
    });
  }

  return recs;
}

