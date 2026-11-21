import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { auditScheme, auditSetCookie, probeCorsAndMethods } from './modules/headersModule.ts';
import { buildCategorizedFindings } from './findingsBuilder.ts';

test('probeCorsAndMethods flags reflected credentials and dangerous methods', async () => {
  const server = createServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': 'https://sentinelglobe.example',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, TRACE',
        Allow: 'GET, TRACE',
      });
      res.end();
      return;
    }
    res.writeHead(200);
    res.end('ok');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  try {
    const result = await probeCorsAndMethods(`http://127.0.0.1:${address.port}`);
    assert.equal(result.cors.risky, true);
    assert.equal(result.cors.reflective, true);
    assert.equal(result.cors.allowCredentials, true);
    assert.deepEqual(result.httpMethods, ['GET', 'TRACE']);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('probeCorsAndMethods returns a safe default when the probe fails', async () => {
  const result = await probeCorsAndMethods('http://127.0.0.1:1');
  assert.equal(result.cors.risky, false);
  assert.equal(result.cors.allowCredentials, false);
  assert.deepEqual(result.httpMethods, []);
});

test('auditSetCookie classifies session cookies as Critical and tracking cookies as Info', () => {
  const session = auditSetCookie('PHPSESSID=abc123; Path=/; SameSite=Lax');
  assert.equal(session.category, 'session');
  assert.equal(session.severity, 'Critical');
  assert.deepEqual(session.missing, ['Secure', 'HttpOnly']);

  const jwt = auditSetCookie('access_token=eyJhbGciOi...; Max-Age=3600; SameSite=Lax');
  assert.equal(jwt.category, 'session');
  assert.equal(jwt.severity, 'Critical');

  const tracking = auditSetCookie('_ga=GA1.1.123; Domain=.example.com; Max-Age=63072000');
  assert.equal(tracking.category, 'tracking');
  assert.equal(tracking.severity, 'Info');
  assert.deepEqual(tracking.missing, ['Secure', 'HttpOnly', 'SameSite']);

  const googleNid = auditSetCookie('NID=511=abc; Domain=.google.com; Max-Age=31536000');
  assert.equal(googleNid.category, 'tracking');
  assert.equal(googleNid.severity, 'Info');
});

test('auditSetCookie keeps hardened session cookies out of Critical and flags SameSite only as High', () => {
  const hardened = auditSetCookie('PHPSESSID=abc; Secure; HttpOnly; SameSite=Lax');
  assert.equal(hardened.severity, 'Info');
  assert.deepEqual(hardened.missing, []);

  const missingSameSite = auditSetCookie('PHPSESSID=abc; Secure; HttpOnly');
  assert.equal(missingSameSite.category, 'session');
  assert.equal(missingSameSite.severity, 'High');
  assert.deepEqual(missingSameSite.missing, ['SameSite']);

  const hostPrefix = auditSetCookie('__Host-session=abc; Path=/; SameSite=Lax');
  assert.equal(hostPrefix.category, 'session');
  assert.equal(hostPrefix.severity, 'Critical');
  assert.ok(hostPrefix.missing.includes('Secure'));
});

test('auditScheme follows redirects and audits the final origin cookies/headers', async () => {
  const server = createServer((req, res) => {
    if (req.url === '/') {
      res.writeHead(302, { Location: '/final' });
      res.end();
      return;
    }
    if (req.url === '/final') {
      res.writeHead(200, {
        Server: 'gws',
        'Content-Type': 'text/html',
        'Set-Cookie': ['PHPSESSID=abc; Path=/', '_ga=GA1.1.1; Max-Age=63072000'],
      });
      res.end('<html>google</html>');
      return;
    }
    res.writeHead(200);
    res.end('ok');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  try {
    const audit = await auditScheme(`127.0.0.1:${address.port}`, 'http');
    assert.equal(audit.ok, true);
    assert.equal(audit.redirected, true);
    assert.ok(audit.finalUrl?.endsWith('/final'));
    assert.equal(audit.server, 'gws');
    const session = audit.cookieAudit.find((cookie) => cookie.name === 'PHPSESSID');
    const tracking = audit.cookieAudit.find((cookie) => cookie.name === '_ga');
    assert.equal(session?.severity, 'Critical');
    assert.equal(tracking?.severity, 'Info');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('buildCategorizedFindings downgrades Google-managed missing headers to Info', () => {
  const audit = {
    status: 200,
    server: 'gws',
    headers: { server: 'gws' },
    missingSecurityHeaders: ['content-security-policy', 'strict-transport-security'],
    cookieIssues: [],
    cookieAudit: [
      {
        name: 'PHPSESSID',
        category: 'session' as const,
        missing: ['Secure', 'HttpOnly'],
        severity: 'Critical' as const,
        hasExpiry: false,
        secure: false,
        httpOnly: false,
      },
      {
        name: '_ga',
        category: 'tracking' as const,
        missing: ['Secure', 'HttpOnly'],
        severity: 'Info' as const,
        hasExpiry: true,
        secure: false,
        httpOnly: false,
      },
    ],
    securityTxtFound: false,
  };
  const result = buildCategorizedFindings({
    targetType: 'domain',
    feedMatches: [],
    tls: null,
    httpAudit: audit,
    emailSecurityStatus: 'protected',
    attribution: [],
    executedModules: ['headers'],
  });
  const headerFindings = result.findings.filter((finding) => finding.id.startsWith('missing-header-'));
  assert.equal(headerFindings.length, 2);
  assert.ok(headerFindings.every((finding) => finding.riskLevel === 'Info'));
  assert.ok(result.findings.some((finding) => finding.id === 'cookie-flags-critical' && finding.riskLevel === 'Critical'));
  assert.ok(result.findings.some((finding) => finding.id === 'cookie-flags-info' && finding.riskLevel === 'Info'));
});

test('buildCategorizedFindings detects Google ASN even when Server header is hidden', () => {
  const result = buildCategorizedFindings({
    targetType: 'domain',
    feedMatches: [],
    tls: null,
    httpAudit: {
      status: 200,
      headers: {},
      missingSecurityHeaders: ['x-content-type-options'],
      cookieIssues: [],
      securityTxtFound: false,
    },
    emailSecurityStatus: 'protected',
    attribution: [
      {
        id: 't1',
        ip: '142.250.1.1',
        threatType: 'Live Attribution',
        sourceFeed: 'Live Attribution',
        severity: 'CLEAN',
        country: 'United States',
        countryCode: 'US',
        city: 'Mountain View',
        lat: 37.4,
        lon: -122.1,
        asn: 'AS15169',
        isp: 'GOOGLE',
        org: 'GOOGLE',
      },
    ],
    executedModules: ['headers'],
  });
  const finding = result.findings.find((item) => item.id === 'missing-header-x-content-type-options');
  assert.equal(finding?.riskLevel, 'Info');
});
