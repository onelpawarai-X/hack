import type {
  ActiveVulnFinding,
  OwaspCategory,
  PortScanReport,
  RemediationSnippets,
  RiskLevel,
  RiskScoreBreakdown,
  SecurityFinding,
  SensitivePathFinding,
  TargetScanResult,
  TechFingerprint,
  WafDetectionResult,
} from '../src/types/cyber.ts';

export const ETHICAL_LEGAL_DISCLAIMER =
  'For authorized security testing only. Misuse is strictly prohibited.';

function detectManagedGoogleEdge(input: {
  httpAudit: TargetScanResult['httpAudit'];
  attribution: TargetScanResult['attribution'];
}): { managed: boolean; reason?: string } {
  const server = String(
    input.httpAudit?.server || input.httpAudit?.headers?.server || '',
  ).toLowerCase();
  if (/(^|[\s/])gws([\s/]|$)/.test(server) || server.includes('google')) {
    return { managed: true, reason: `Server header: ${server || 'gws'}` };
  }
  const googleHost = input.attribution.find(
    (node) =>
      /^AS15169$/i.test(node.asn) ||
      /google/i.test(node.isp || '') ||
      /google/i.test(node.org || ''),
  );
  if (googleHost) {
    return {
      managed: true,
      reason: `${googleHost.asn || 'Google ASN'} · ${googleHost.isp || googleHost.org || 'Google'}`,
    };
  }
  return { managed: false };
}

export function getHeaderFixSnippets(headerName: string): RemediationSnippets {
  const key = headerName.toLowerCase();
  if (key === 'content-security-policy') {
    return {
      nginx: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';" always;`,
      apache: `Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"`,
      cloudflare: `# Cloudflare Transform Rule (Modify Response Header)\nSet static header: Content-Security-Policy = default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`,
    };
  }
  if (key === 'strict-transport-security') {
    return {
      nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
      apache: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
      cloudflare: `# Cloudflare SSL/TLS -> Edge Certificates -> HSTS\nEnable HSTS: max-age=31536000, includeSubDomains=true, preload=true`,
    };
  }
  if (key === 'x-frame-options') {
    return {
      nginx: `add_header X-Frame-Options "DENY" always;`,
      apache: `Header always set X-Frame-Options "DENY"`,
      cloudflare: `# Cloudflare Transform Rule (Modify Response Header)\nSet static header: X-Frame-Options = DENY`,
    };
  }
  if (key === 'x-content-type-options') {
    return {
      nginx: `add_header X-Content-Type-Options "nosniff" always;`,
      apache: `Header always set X-Content-Type-Options "nosniff"`,
      cloudflare: `# Cloudflare Transform Rule (Modify Response Header)\nSet static header: X-Content-Type-Options = nosniff`,
    };
  }
  if (key === 'referrer-policy') {
    return {
      nginx: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
      apache: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
      cloudflare: `# Cloudflare Transform Rule (Modify Response Header)\nSet static header: Referrer-Policy = strict-origin-when-cross-origin`,
    };
  }
  // permissions-policy
  return {
    nginx: `add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;`,
    apache: `Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"`,
    cloudflare: `# Cloudflare Transform Rule (Modify Response Header)\nSet static header: Permissions-Policy = geolocation=(), microphone=(), camera=()`,
  };
}

export function getSensitiveFilesSnippets(): RemediationSnippets {
  return {
    nginx: `location ~* /\\.(env|git|hg|svn|DS_Store) {\n  deny all;\n  return 404;\n}\nlocation ~* \\.(sql|zip|tar\\.gz|bak|old)$ {\n  deny all;\n  return 404;\n}`,
    apache: `<FilesMatch "^(\\.(env|git|DS_Store)|.*\\.(sql|zip|bak|old))$">\n  Require all denied\n</FilesMatch>`,
    cloudflare: `# Cloudflare WAF Custom Rule\n(http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git" or http.request.uri.path matches "\\\\.(zip|sql|bak)$") -> Block`,
  };
}

export function buildCategorizedFindings(input: {
  targetType: TargetScanResult['targetType'];
  feedMatches: Array<{ feed: string; detail: string }>;
  tls: TargetScanResult['tls'];
  httpAudit: TargetScanResult['httpAudit'];
  emailSecurityStatus: 'protected' | 'weak' | 'missing';
  attribution: TargetScanResult['attribution'];
  cveDetails?: TargetScanResult['cveDetails'];
  waf?: WafDetectionResult | null;
  portScan?: PortScanReport | null;
  techStack?: TechFingerprint[];
  sensitivePaths?: SensitivePathFinding[];
  activeVulns?: ActiveVulnFinding[];
  executedModules: string[];
}): {
  findings: SecurityFinding[];
  riskCounts: Record<RiskLevel, number>;
} {
  const findings: SecurityFinding[] = [];

  // 1. Threat Feed Hits -> Critical
  for (let i = 0; i < input.feedMatches.length; i++) {
    const match = input.feedMatches[i];
    findings.push({
      id: `threat-feed-${i}`,
      moduleId: 'threatIntel',
      title: `Active Threat Intelligence Match (${match.feed})`,
      description: match.detail,
      riskLevel: 'Critical',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      owaspId: 'A05:2021',
      cwe: 'CWE-912',
      evidence: match.detail,
      remediation:
        'Immediately block the indicator at perimeter firewall and WAF rulesets, inspect internal egress logs, and verify host integrity.',
      snippets: {
        nginx: `# Block IOC origin IP in Nginx server block\ndeny <MALICIOUS_IP>;`,
        apache: `# Block IOC IP in Apache VirtualHost\nRequire not ip <MALICIOUS_IP>`,
        cloudflare: `# Cloudflare WAF IP Block Expression\n(ip.src in {<MALICIOUS_IP>}) -> Block`,
      },
    });
  }

  // 2. Host CVEs & Exposed Admin Ports
  const knownVulns = Array.from(
    new Set(input.attribution.flatMap((a) => a.knownVulns ?? [])),
  );
  if (knownVulns.length > 0) {
    const topCve = input.cveDetails?.[0];
    const isCrit =
      (topCve?.cvssScore ?? 0) >= 9 || knownVulns.length >= 3;
    findings.push({
      id: 'exposed-host-cves',
      moduleId: 'portsBgp',
      title: `${knownVulns.length} Known Host Vulnerabilities Detected (${knownVulns.slice(0, 4).join(', ')})`,
      description:
        topCve?.description ||
        'Public service fingerprinting reported known unpatched software vulnerabilities.',
      riskLevel: isCrit ? 'Critical' : 'High',
      owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
      owaspId: 'A06:2021',
      cwe: 'CWE-1104',
      evidence: knownVulns.slice(0, 8).join(', '),
      remediation:
        'Upgrade vulnerable packages immediately, apply vendor patches, and restrict administrative services behind VPN or zero-trust access.',
      snippets: {
        nginx: `server_tokens off;\n# Restrict management locations to internal CIDR\nlocation /admin {\n  allow 10.0.0.0/8;\n  deny all;\n}`,
        apache: `ServerTokens Prod\nServerSignature Off`,
        cloudflare: `# Cloudflare Zero Trust Access Policy\nProtect internal endpoints behind Cloudflare Access & disable legacy TLS/version headers.`,
      },
    });
  }

  const activePorts = input.portScan?.openPorts.map((item) => item.port) ?? [];
  const allPorts = Array.from(
    new Set([...input.attribution.flatMap((a) => a.openPorts ?? []), ...activePorts]),
  );
  const riskyPorts = allPorts.filter((p) =>
    [21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017].includes(p),
  );
  if (riskyPorts.length > 0) {
    findings.push({
      id: 'risky-open-ports',
      moduleId: 'portsBgp',
      title: `Sensitive Administrative / Database Ports Exposed (${riskyPorts.join(', ')})`,
      description:
        'Management or data-tier ports are reachable from the public internet according to passive port telemetry.',
      riskLevel: 'High',
      owaspCategory: 'A01:2021 - Broken Access Control',
      owaspId: 'A01:2021',
      cwe: 'CWE-284',
      evidence: `Open ports: ${riskyPorts.join(', ')}`,
      remediation:
        'Restrict remote SSH/RDP/DB ports to private VPC subnets or bastion allowlists; enforce key-based authentication.',
      snippets: {
        nginx: `# Proxy only HTTP(S) services; bind backend DB/admin sockets to 127.0.0.1`,
        apache: `# Restrict sensitive endpoints via Require ip <TRUSTED_VPN_CIDR>`,
        cloudflare: `# Enable Cloudflare Spectrum / Tunnel so origin firewall drops all inbound except Cloudflare IPs`,
      },
    });
  }

  // 2b. Real TCP port scan results
  if (input.portScan && input.portScan.openPorts.length > 0) {
    const services = input.portScan.openPorts
      .map((item) => `${item.port}/${item.service}`)
      .join(', ');
    findings.push({
      id: 'tcp-port-scan',
      moduleId: 'portScan',
      title: `TCP Port Scan Discovered ${input.portScan.openPorts.length} Open Service(s)`,
      description:
        'A live TCP connect scan from the SentinelGlobe scanner reached the following services on the public internet.',
      riskLevel: input.portScan.openPorts.some(
        (item) => item.riskLevel === 'Critical' || item.riskLevel === 'High',
      )
        ? 'High'
        : 'Info',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      owaspId: 'A05:2021',
      cwe: 'CWE-1327',
      evidence: services,
      remediation:
        'Close every service that does not need public exposure and restrict management ports to VPN, bastion or zero-trust access.',
      snippets: {
        nginx: `# Only proxy required HTTP(S) services\nlocation / {\n  proxy_pass http://127.0.0.1:8080;\n}`,
        apache: `# Bind internal services to loopback only\nListen 127.0.0.1:8080`,
        cloudflare: `# Put origin behind Cloudflare Tunnel and deny direct inbound traffic at the firewall.`,
      },
    });
  }

  // 2c. Observed technology stack
  if (input.techStack && input.techStack.length > 0) {
    findings.push({
      id: 'tech-stack-fingerprint',
      moduleId: 'headers',
      title: `Technology Stack Fingerprint (${input.techStack.length} component(s))`,
      description:
        'Observed server, framework, platform and CDN components. CVE matching is scoped to this stack to avoid cross-product false positives.',
      riskLevel: 'Info',
      owaspCategory: 'A05:2021 - Security Misconfiguration',
      owaspId: 'A05:2021',
      evidence: input.techStack
        .map((item) => `${item.name}${item.version ? ` ${item.version}` : ''} [${item.category}, ${item.confidence}${item.cpe ? `, ${item.cpe}` : ''}]`)
        .join('; '),
      remediation:
        'Keep each detected component patched and remove version banners from public responses.',
    });
  }

  // 3. TLS / Cryptographic Audit
  if (input.tls) {
    if (!input.tls.valid) {
      findings.push({
        id: 'tls-invalid',
        moduleId: 'tls',
        title: 'Invalid, Self-Signed, or Expired TLS Certificate',
        description:
          input.tls.error ||
          'HTTPS TLS handshake failed validation checks, exposing users to interception risks.',
        riskLevel: 'High',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
        owaspId: 'A02:2021',
        cwe: 'CWE-295',
        evidence: input.tls.error || 'Certificate trust verification failed',
        remediation:
          'Deploy a valid certificate chain from a trusted CA (e.g., Let’s Encrypt ACME) and restrict protocols to TLSv1.2 / TLSv1.3.',
        snippets: {
          nginx: `ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;`,
          apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLHonorCipherOrder on`,
          cloudflare: `# Cloudflare SSL/TLS -> Overview: Full (Strict)\n# Edge Certificates -> Minimum TLS Version: TLS 1.2`,
        },
      });
    } else {
      if (typeof input.tls.daysRemaining === 'number' && input.tls.daysRemaining < 14) {
        findings.push({
          id: 'tls-expiring-soon',
          moduleId: 'tls',
          title: `TLS Certificate Expiring Soon (${input.tls.daysRemaining} days left)`,
          description: 'Certificate validity window is nearly exhausted.',
          riskLevel: 'Medium',
          owaspCategory: 'A02:2021 - Cryptographic Failures',
          owaspId: 'A02:2021',
          cwe: 'CWE-298',
          evidence: `Valid until: ${input.tls.validTo}`,
          remediation: 'Verify automated ACME certificate renewal and reload configuration.',
        });
      } else {
        findings.push({
          id: 'tls-verified-info',
          moduleId: 'tls',
          title: `Verified TLS Certificate (${input.tls.protocol || 'TLS'})`,
          description: `Valid certificate issued by ${input.tls.issuer || 'Trusted CA'}.`,
          riskLevel: 'Info',
          owaspCategory: 'A02:2021 - Cryptographic Failures',
          owaspId: 'A02:2021',
          evidence: `${input.tls.protocol || 'TLS'} · ${input.tls.cipher || ''}`.trim(),
          remediation: 'Continue monitoring certificate expiration and keep TLS 1.3 enabled.',
        });
      }
    }
  }

  // 4. HTTP Security Headers -> context-aware risk, exact Nginx/Apache/Cloudflare snippets
  if (input.httpAudit && !input.httpAudit.error) {
    const edge = detectManagedGoogleEdge(input);
    for (const h of input.httpAudit.missingSecurityHeaders) {
      const lower = h.toLowerCase();
      const isCore =
        lower === 'content-security-policy' ||
        lower === 'strict-transport-security' ||
        lower === 'x-frame-options';
      // Google-managed frontends (Server: gws / AS15169) often terminate these
      // headers upstream, so a missing header is informational, not HIGH.
      const riskLevel: RiskLevel = edge.managed ? 'Info' : isCore ? 'High' : 'Medium';
      findings.push({
        id: `missing-header-${lower}`,
        moduleId: 'headers',
        title: edge.managed
          ? `Missing Security Header: ${h} (managed Google edge)`
          : `Missing Security Header: ${h}`,
        description: edge.managed
          ? `HTTP response lacks ${h}. This target is fronted by a Google-managed edge (${edge.reason}); the header may be injected upstream or intentionally omitted, so this is informational.`
          : `HTTP response lacks ${h}, weakening browser-side defense-in-depth protections.`,
        riskLevel,
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: lower === 'content-security-policy' ? 'CWE-693' : 'CWE-1021',
        evidence: `Header "${h}" absent in final HTTP ${input.httpAudit.status ?? ''} response${edge.managed ? ` · ${edge.reason}` : ''}`,
        remediation: edge.managed
          ? 'Verify the edge/origin configuration directly before changing anything; do not treat this as an origin vulnerability.'
          : `Configure the reverse proxy or CDN to emit a strict ${h} response header.`,
        snippets: edge.managed ? undefined : getHeaderFixSnippets(lower),
      });
    }

    const cookieAudit = input.httpAudit.cookieAudit ?? [];
    if (cookieAudit.length > 0) {
      const severityOrder: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
      for (const severity of severityOrder) {
        const items = cookieAudit.filter(
          (cookie) => cookie.severity === severity && cookie.missing.length > 0,
        );
        if (items.length === 0) continue;
        const sessionItems = items.filter((cookie) => cookie.category === 'session');
        const trackingItems = items.filter((cookie) => cookie.category === 'tracking');
        const title =
          severity === 'Critical'
            ? `Critical Session Cookie Flags Missing (${items.length})`
            : severity === 'Info'
              ? `Tracking Cookie Flags Missing (${items.length})`
              : `Cookie Flag Issues (${severity}, ${items.length})`;
        findings.push({
          id: `cookie-flags-${severity.toLowerCase()}`,
          moduleId: 'headers',
          title,
          description:
            severity === 'Critical'
              ? `Session/authentication cookies (${sessionItems.map((cookie) => cookie.name).join(', ') || items.map((cookie) => cookie.name).join(', ')}) are missing Secure or HttpOnly. This can expose authenticated sessions to theft or XSS.`
              : severity === 'Info'
                ? `Tracking/analytics cookies (${trackingItems.map((cookie) => cookie.name).join(', ') || items.map((cookie) => cookie.name).join(', ')}) lack hardening flags. This is a privacy/consent observation, not a session takeover risk.`
                : `Cookies lack recommended security attributes. Review the listed names and their purpose.`,
          riskLevel: severity,
          owaspCategory: 'A07:2021 - Identification and Authentication Failures',
          owaspId: 'A07:2021',
          cwe: 'CWE-614',
          evidence: items
            .slice(0, 12)
            .map((cookie) => `${cookie.name} [${cookie.category}] missing ${cookie.missing.join(', ')}`)
            .join(' | '),
          remediation:
            severity === 'Info'
              ? 'Optional: set Secure, HttpOnly and SameSite on tracking cookies where compatible with the analytics vendor.'
              : 'Set Secure; HttpOnly; SameSite=Lax (or Strict) on all sensitive session cookies.',
          snippets:
            severity === 'Info'
              ? undefined
              : {
                  nginx: `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";`,
                  apache: `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"`,
                  cloudflare: `# Set cookie flags at origin application framework or edge response rewrite`,
                },
        });
      }
    } else if (input.httpAudit.cookieIssues.length > 0) {
      findings.push({
        id: 'insecure-cookies',
        moduleId: 'headers',
        title: `Insecure Cookie Attributes (${input.httpAudit.cookieIssues.length})`,
        description: 'Set-Cookie headers omit HttpOnly, Secure, or SameSite flags.',
        riskLevel: 'Medium',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        owaspId: 'A07:2021',
        cwe: 'CWE-614',
        evidence: input.httpAudit.cookieIssues.slice(0, 4).join(' | '),
        remediation: 'Set Secure; HttpOnly; SameSite=Lax (or Strict) on all sensitive session cookies.',
        snippets: {
          nginx: `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";`,
          apache: `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"`,
          cloudflare: `# Set cookie flags at origin application framework or edge response rewrite`,
        },
      });
    }

    if (input.httpAudit.cors?.risky) {
      findings.push({
        id: 'risky-cors-policy',
        moduleId: 'headers',
        title: 'Risky CORS Policy with Credentials',
        description:
          'The origin reflects an arbitrary Origin header or allows * together with credentials, which can expose authenticated responses to hostile sites.',
        riskLevel: 'Medium',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: 'CWE-942',
        evidence: `Allow-Origin: ${input.httpAudit.cors.allowOrigin} | Allow-Credentials: ${input.httpAudit.cors.allowCredentials} | reflective: ${input.httpAudit.cors.reflective}`,
        remediation:
          'Return an explicit allow-list of trusted origins and never combine Access-Control-Allow-Credentials: true with * or reflected origins.',
      });
    }

    const dangerousMethods = (input.httpAudit.httpMethods ?? []).filter(
      (method) => method === 'TRACE' || method === 'TRACK',
    );
    if (dangerousMethods.length > 0) {
      findings.push({
        id: 'dangerous-http-methods',
        moduleId: 'headers',
        title: `Dangerous HTTP Methods Advertised (${dangerousMethods.join(', ')})`,
        description:
          'TRACE/TRACK can enable cross-site tracing and should be disabled on public web servers.',
        riskLevel: 'Low',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: 'CWE-749',
        evidence: `Allow: ${input.httpAudit.httpMethods?.join(', ')}`,
        remediation: 'Disable TRACE/TRACK in the web server configuration (Apache: TraceEnable off).',
        snippets: {
          nginx: `# nginx does not enable TRACE by default`,
          apache: `TraceEnable off`,
        },
      });
    }
  }

  // 5. Email DNS Security (SPF/DMARC)
  if (
    (input.targetType === 'domain' || input.targetType === 'url') &&
    input.executedModules.includes('dns')
  ) {
    if (input.emailSecurityStatus === 'missing') {
      findings.push({
        id: 'dns-spf-dmarc-missing',
        moduleId: 'dns',
        title: 'Missing SPF & DMARC Email Authentication Records',
        description:
          'Without SPF and DMARC records, attackers can spoof emails pretending to originate from this domain.',
        riskLevel: 'High',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: 'CWE-290',
        evidence: 'No v=spf1 or v=DMARC1 TXT records found.',
        remediation:
          'Publish TXT SPF policy (-all) and _dmarc TXT policy (p=quarantine or p=reject).',
        snippets: {
          cloudflare: `# Cloudflare DNS TXT Records\n@       TXT "v=spf1 -all"\n_dmarc  TXT "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"`,
        },
      });
    } else if (input.emailSecurityStatus === 'weak') {
      findings.push({
        id: 'dns-spf-dmarc-weak',
        moduleId: 'dns',
        title: 'Weak or Monitor-Only SPF/DMARC Policy',
        description:
          'Domain uses p=none or permissive +all, allowing spoofed emails to be delivered.',
        riskLevel: 'Low',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: 'CWE-290',
        remediation: 'Transition DMARC from p=none to p=quarantine or p=reject after reviewing aggregate reports.',
      });
    }
  }

  // 6. WAF Detection -> Info or Low
  if (input.waf) {
    if (input.waf.detected) {
      findings.push({
        id: 'waf-detected',
        moduleId: 'waf',
        title: `Web Application Firewall Detected: ${input.waf.provider}`,
        description: `Edge security filtering identified (${input.waf.confidence} confidence).`,
        riskLevel: 'Info',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        evidence: input.waf.signals.join('; '),
        remediation: 'Verify origin IP is firewalled so attackers cannot bypass the WAF directly.',
      });
    } else {
      findings.push({
        id: 'waf-not-detected',
        moduleId: 'waf',
        title: 'No Edge Web Application Firewall (WAF) Signature Detected',
        description:
          'HTTP responses did not reveal common WAF/CDN edge protection headers.',
        riskLevel: 'Low',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        remediation:
          'Consider fronting public endpoints behind Cloudflare WAF, AWS WAF, or ModSecurity rulesets.',
        snippets: {
          nginx: `# Enable ModSecurity WAF in Nginx\nmodsecurity on;\nmodsecurity_rules_file /etc/nginx/modsec/main.conf;`,
          apache: `# Enable ModSecurity in Apache\nSecRuleEngine On`,
          cloudflare: `# Enable Cloudflare Managed WAF Ruleset (OWASP Core Ruleset)`,
        },
      });
    }
  }

  // 7. Sensitive Files Discovery -> Critical / High
  if (input.sensitivePaths) {
    for (const item of input.sensitivePaths.filter((p) => p.exposed)) {
      findings.push({
        id: `sensitive-path-${item.path.replace(/[^a-z0-9]/gi, '-')}`,
        moduleId: 'sensitiveFiles',
        title: `Exposed Sensitive Path: ${item.path} (HTTP ${item.status})`,
        description: item.detail,
        riskLevel: item.riskLevel,
        owaspCategory: 'A01:2021 - Broken Access Control',
        owaspId: 'A01:2021',
        cwe: 'CWE-538',
        evidence: `GET ${item.path} -> HTTP ${item.status}`,
        remediation:
          'Remove sensitive artifacts from webroot immediately, rotate any exposed credentials, and deny access at the reverse proxy.',
        snippets: getSensitiveFilesSnippets(),
      });
    }
  }

  // 8. Active Vulnerability Checks -> High / Medium
  if (input.activeVulns) {
    for (const vuln of input.activeVulns) {
      findings.push({
        id: vuln.id,
        moduleId: 'activeVulns',
        title: `${vuln.category} (${vuln.parameter || vuln.endpoint})`,
        description: vuln.evidence,
        riskLevel: vuln.riskLevel,
        owaspCategory: vuln.owaspCategory,
        owaspId: vuln.owaspCategory.split(' - ')[0] as OwaspCategory,
        cwe:
          vuln.category === 'Reflected XSS'
            ? 'CWE-79'
            : vuln.category === 'SQL Injection Indicator'
              ? 'CWE-89'
              : 'CWE-352',
        evidence: vuln.evidence,
        remediation: vuln.remediation,
        snippets:
          vuln.category === 'Reflected XSS'
            ? getHeaderFixSnippets('content-security-policy')
            : vuln.category === 'Missing CSRF Protection'
              ? {
                  nginx: `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";`,
                  apache: `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"`,
                  cloudflare: `# Require Origin/Referer verification + anti-CSRF synchronizer tokens on all state-changing routes.`,
                }
              : {
                  nginx: `# Disable upstream detailed error leaks\nproxy_intercept_errors on;`,
                  apache: `# Suppress server debug output\nServerSignature Off`,
                  cloudflare: `# Enable Cloudflare OWASP Core Ruleset SQLi Managed Rules & hide stack traces`,
                },
      });
    }
  }

  const order: Record<RiskLevel, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
    Info: 4,
  };
  findings.sort((a, b) => order[a.riskLevel] - order[b.riskLevel]);

  const riskCounts: Record<RiskLevel, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  for (const f of findings) {
    riskCounts[f.riskLevel] += 1;
  }

  return { findings, riskCounts };
}

const RISK_WEIGHTS: Record<RiskLevel, number> = {
  Critical: 40,
  High: 20,
  Medium: 8,
  Low: 3,
  Info: 0,
};

const VERDICT_FLOORS: Record<TargetScanResult['verdict'], number> = {
  CRITICAL: 80,
  HIGH: 55,
  ELEVATED: 30,
  CLEAN: 0,
};

export function computeRiskScore(
  findings: SecurityFinding[],
  verdict: TargetScanResult['verdict'],
): RiskScoreBreakdown {
  const severities: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const components = severities
    .map((severity) => {
      const count = findings.filter((f) => f.riskLevel === severity).length;
      return { severity, count, weight: RISK_WEIGHTS[severity], points: count * RISK_WEIGHTS[severity] };
    })
    .filter((component) => component.count > 0);

  const rawPoints = components.reduce((sum, component) => sum + component.points, 0);
  const verdictFloor = VERDICT_FLOORS[verdict] ?? 0;
  const score = Math.min(100, Math.max(rawPoints, verdictFloor));
  const grade: RiskScoreBreakdown['grade'] =
    score >= 70 ? 'F' : score >= 50 ? 'D' : score >= 30 ? 'C' : score >= 15 ? 'B' : 'A';

  return {
    score,
    grade,
    rawPoints,
    verdictFloor,
    capped: rawPoints > 100,
    components,
  };
}

export function applyRiskScore(result: TargetScanResult): TargetScanResult {
  return {
    ...result,
    riskScore: computeRiskScore(result.findings ?? [], result.verdict),
  };
}
