import assert from 'node:assert/strict';
import test from 'node:test';
import type { TargetScanResult } from '../src/types/cyber.ts';
import {
  generateFirewallRulesForIp,
  generateGlobalFirewallBundle,
  generateNginxHardeningConfig,
  generateRecommendedDnsRecords,
} from './defenseEngine.ts';

test('generateFirewallRulesForIp outputs valid Nginx, iptables, UFW, and Cloudflare WAF rules', () => {
  const rules = generateFirewallRulesForIp('198.51.100.44');
  assert.equal(rules.nginx, 'deny 198.51.100.44;');
  assert.ok(rules.iptables.includes('iptables -I INPUT -s 198.51.100.44 -j DROP'));
  assert.ok(rules.ufw.includes('ufw insert 1 deny from 198.51.100.44'));
  assert.equal(rules.cloudflare, '(ip.src eq 198.51.100.44)');
});

test('generateGlobalFirewallBundle aggregates blocked IPs and sinkholed phishing domains', () => {
  const rules = generateFirewallRulesForIp('203.0.113.9');
  const bundle = generateGlobalFirewallBundle(
    [
      {
        ip: '203.0.113.9',
        blockedAt: '2026-11-20T00:00:00Z',
        lastCheckedAt: '2026-11-20T00:00:00Z',
        reason: 'Feodo C2',
        severity: 'CRITICAL',
        abuseEmails: ['abuse@example.net'],
        openPorts: [443],
        knownVulns: [],
        watchdogStatus: 'blocked-monitoring',
        firewallRules: rules,
      },
    ],
    [
      {
        domain: 'evil-phish-login.example',
        sinkholedAt: '2026-11-20T00:00:00Z',
        reason: 'OpenPhish',
        resolvedIps: ['203.0.113.9'],
        abuseEmails: ['abuse@registrar.example'],
        hostsEntry: '0.0.0.0 evil-phish-login.example',
        piholeRule: '||evil-phish-login.example^',
        safeBrowsingUrl: 'https://safebrowsing.google.com/',
        netcraftReportUrl: 'https://report.netcraft.com/',
      },
    ],
  );

  assert.ok(bundle.nginxDenyList.includes('deny 203.0.113.9;'));
  assert.ok(bundle.iptablesScript.includes('203.0.113.9 -j DROP'));
  assert.ok(bundle.dnsSinkholeHosts.includes('0.0.0.0 evil-phish-login.example'));
  assert.equal(bundle.cloudflareWafExpr, '(ip.src in {203.0.113.9})');
});

test('generateNginxHardeningConfig and generateRecommendedDnsRecords target actual audit gaps', () => {
  const mockScan: TargetScanResult = {
    query: 'victim.example',
    normalizedTarget: 'https://victim.example',
    targetType: 'url',
    scannedAt: '2026-11-20T00:00:00Z',
    verdict: 'ELEVATED',
    verdictReasons: [],
    feedMatches: [],
    dns: {
      a: ['93.184.216.34'],
      aaaa: [],
      mx: [],
      ns: [],
      txt: [],
      caa: [],
      spfRecord: null,
      dmarcRecord: null,
      emailSecurityStatus: 'missing',
    },
    attribution: [],
    tls: { valid: true, daysRemaining: 60 },
    httpAudit: {
      status: 200,
      headers: {},
      missingSecurityHeaders: ['content-security-policy', 'strict-transport-security'],
      cookieIssues: [],
      securityTxtFound: false,
    },
    hardeningRecommendations: [],
    webBreachSignals: [],
  };

  const nginx = generateNginxHardeningConfig(mockScan);
  assert.ok(nginx.includes('Content-Security-Policy'));
  assert.ok(nginx.includes('Strict-Transport-Security'));
  assert.ok(nginx.includes('limit_req_zone'));

  const dns = generateRecommendedDnsRecords(mockScan, 'victim.example');
  assert.ok(dns.some((r) => r.includes('v=spf1 -all')));
  assert.ok(dns.some((r) => r.includes('v=DMARC1; p=reject')));
  assert.ok(dns.some((r) => r.includes('CAA  0 issue "letsencrypt.org"')));
});
