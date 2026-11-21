import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrlTrapHeuristics,
  auditEmailDnsSecurity,
  classifyIncidentSeverity,
  computeTargetVerdict,
  extractTargetIdentifiers,
  generateHardeningRecommendations,
  parseCisaKevCatalog,
  parseIpBlocklistText,
  parseOpenPhishFeed,
} from './threatRules.ts';

test('parseIpBlocklistText extracts valid IPv4s and ignores comments', () => {
  const raw = `
# Blocklist header
185.220.101.45
not-an-ip
91.132.147.200
; comment
999.999.1.1
  `;
  const ips = parseIpBlocklistText(raw);
  assert.equal(ips.size, 2);
  assert.equal(ips.has('185.220.101.45'), true);
  assert.equal(ips.has('91.132.147.200'), true);
});

test('parseOpenPhishFeed indexes URLs, hosts, and attaches risk reasons', () => {
  const raw = [
    'https://paypal-verify-login.weeblysite.com/auth',
    'http://198.51.100.44/wallet',
    'invalid-line',
  ].join('\n');
  const parsed = parseOpenPhishFeed(raw, '2026-11-20T00:00:00Z');
  assert.equal(parsed.traps.length, 2);
  assert.equal(parsed.hostSet.has('paypal-verify-login.weeblysite.com'), true);
  assert.equal(parsed.traps[0].severity, 'CRITICAL');
  assert.ok(
    parsed.traps[0].riskReasons.some((r) => r.includes('brand impersonation')),
  );
});

test('analyzeUrlTrapHeuristics flags punycode and credential @ patterns', () => {
  const reasons = analyzeUrlTrapHeuristics('http://xn--pple-43d.com/login@evil.org');
  assert.ok(reasons.some((r) => r.includes('Unencrypted HTTP')));
  assert.ok(reasons.some((r) => r.includes('Punycode')));
});

test('parseCisaKevCatalog sorts by dateAdded descending and detects ransomware flag', () => {
  const catalog = {
    vulnerabilities: [
      {
        cveID: 'CVE-2024-1111',
        vendorProject: 'VendorA',
        product: 'ProdA',
        vulnerabilityName: 'Old Flaw',
        dateAdded: '2024-01-01',
        dueDate: '2024-01-21',
        knownRansomwareCampaignUse: 'Unknown',
        shortDescription: 'Old desc',
      },
      {
        cveID: 'CVE-2026-9999',
        vendorProject: 'VendorB',
        product: 'ProdB',
        vulnerabilityName: 'Zero Day RCE',
        dateAdded: '2026-11-18',
        dueDate: '2026-12-01',
        knownRansomwareCampaignUse: 'Known',
        shortDescription: 'Active RCE',
      },
    ],
  };
  const parsed = parseCisaKevCatalog(catalog);
  assert.equal(parsed[0].cveID, 'CVE-2026-9999');
  assert.equal(parsed[0].knownRansomware, true);
});

test('computeTargetVerdict returns CRITICAL on live feed match and CLEAN when clear', () => {
  const critical = computeTargetVerdict({
    feedMatches: [{ feed: 'OpenPhish', detail: 'Exact phishing URL match' }],
    heuristicWarnings: [],
    tlsValid: true,
    missingSecurityHeadersCount: 0,
    webBreachMatchesCount: 0,
  });
  assert.equal(critical.verdict, 'CRITICAL');

  const clean = computeTargetVerdict({
    feedMatches: [],
    heuristicWarnings: [],
    tlsValid: true,
    missingSecurityHeadersCount: 0,
    webBreachMatchesCount: 0,
  });
  assert.equal(clean.verdict, 'CLEAN');
});

test('extractTargetIdentifiers & classifyIncidentSeverity extract real IPs/domains cleanly', () => {
  const targets = extractTargetIdentifiers(
    'Attack originated from 45.155.205.91 targeting portal.example.org and 127.0.0.1',
  );
  assert.ok(targets.includes('45.155.205.91'));
  assert.ok(targets.includes('portal.example.org'));
  assert.equal(targets.includes('127.0.0.1'), false);
  assert.equal(
    classifyIncidentSeverity('Active zero-day ransomware campaign hits cloud gateways', ''),
    'CRITICAL',
  );
});

test('auditEmailDnsSecurity & generateHardeningRecommendations detect weak SPF/DMARC and exposed ports', () => {
  const weak = auditEmailDnsSecurity(['v=spf1 include:_spf.example.com ~all'], ['v=DMARC1; p=none;']);
  assert.equal(weak.emailSecurityStatus, 'weak');

  const strong = auditEmailDnsSecurity(['v=spf1 -all'], ['v=DMARC1; p=reject;']);
  assert.equal(strong.emailSecurityStatus, 'protected');

  const recs = generateHardeningRecommendations({
    targetType: 'domain',
    feedMatches: [],
    tlsValid: false,
    missingSecurityHeaders: ['strict-transport-security', 'content-security-policy'],
    cookieIssues: ['Missing HttpOnly flag'],
    emailSecurityStatus: 'missing',
    knownVulnsCount: 2,
    openPorts: [22, 3306, 443],
  });
  assert.ok(recs.some((r) => r.id === 'patch-cves'));
  assert.ok(recs.some((r) => r.id === 'close-exposed-ports'));
  assert.ok(recs.some((r) => r.id === 'fix-tls'));
  assert.ok(recs.some((r) => r.id === 'enforce-dmarc-spf'));
});

