import type {
  ActiveVulnFinding,
  OwaspCategory,
  RemediationSnippets,
  RiskLevel,
  SecurityFinding,
  SensitivePathFinding,
  TargetScanResult,
  WafDetectionResult,
} from '../src/types/cyber.ts';

export const ETHICAL_LEGAL_DISCLAIMER =
  'For authorized security testing only. Misuse is strictly prohibited.';

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

  const allPorts = Array.from(
    new Set(input.attribution.flatMap((a) => a.openPorts ?? [])),
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

  // 4. HTTP Security Headers -> Exact Nginx/Apache/Cloudflare snippets
  if (input.httpAudit && !input.httpAudit.error) {
    for (const h of input.httpAudit.missingSecurityHeaders) {
      const lower = h.toLowerCase();
      const isMedium =
        lower === 'content-security-policy' ||
        lower === 'strict-transport-security' ||
        lower === 'x-frame-options';
      findings.push({
        id: `missing-header-${lower}`,
        moduleId: 'headers',
        title: `Missing Security Header: ${h}`,
        description: `HTTP response lacks ${h}, weakening browser-side defense-in-depth protections.`,
        riskLevel: isMedium ? 'Medium' : 'Low',
        owaspCategory: 'A05:2021 - Security Misconfiguration',
        owaspId: 'A05:2021',
        cwe: lower === 'content-security-policy' ? 'CWE-693' : 'CWE-1021',
        evidence: `Header "${h}" absent in HTTP ${input.httpAudit.status ?? ''} response`,
        remediation: `Configure the reverse proxy or CDN to emit a strict ${h} response header.`,
        snippets: getHeaderFixSnippets(lower),
      });
    }

    if (input.httpAudit.cookieIssues.length > 0) {
      findings.push({
        id: 'insecure-cookies',
        moduleId: 'headers',
        title: `Insecure Session Cookie Attributes (${input.httpAudit.cookieIssues.length})`,
        description:
          'Set-Cookie headers omit HttpOnly, Secure, or SameSite flags.',
        riskLevel: 'Medium',
        owaspCategory: 'A07:2021 - Identification and Authentication Failures',
        owaspId: 'A07:2021',
        cwe: 'CWE-614',
        evidence: input.httpAudit.cookieIssues.slice(0, 4).join(' | '),
        remediation:
          'Set Secure; HttpOnly; SameSite=Lax (or Strict) on all sensitive session cookies.',
        snippets: {
          nginx: `proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Lax";`,
          apache: `Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"`,
          cloudflare: `# Set cookie flags at origin application framework or Cloudflare Worker response rewrite`,
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
