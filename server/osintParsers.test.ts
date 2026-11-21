import assert from 'node:assert/strict';
import test from 'node:test';
import {
  extractCertSpotterSubdomains,
  extractRootDomain,
  parseMitreCveRecord,
  parseRdapDomainProfile,
  parseRipeStatPrefix,
  parseWaybackCdx,
} from './osintParsers.ts';

test('extractRootDomain preserves multi-part ccTLDs and trims subdomains', () => {
  assert.equal(extractRootDomain('mail.accounts.google.com'), 'google.com');
  assert.equal(extractRootDomain('portal.gov.bd'), 'portal.gov.bd');
  assert.equal(extractRootDomain('api.sub.example.co.uk'), 'example.co.uk');
});

test('extractCertSpotterSubdomains deduplicates, strips wildcard prefix, and filters scope', () => {
  const sample = [
    { dns_names: ['*.api.example.com', 'docs.example.com', 'unrelated.org'] },
    { dns_names: ['api.example.com', 'auth.example.com'] },
  ];
  const subs = extractCertSpotterSubdomains(sample, 'example.com');
  assert.deepEqual(subs, ['api.example.com', 'auth.example.com', 'docs.example.com']);
});

test('parseMitreCveRecord extracts CVSS, CWE, affected products, and references', () => {
  const sample = {
    cveMetadata: { cveId: 'CVE-2024-3094', datePublished: '2024-03-29T16:51:12Z' },
    containers: {
      cna: {
        title: 'Xz: malicious code in distributed source',
        descriptions: [{ lang: 'en', value: 'Backdoor discovered in liblzma.' }],
        metrics: [
          {
            cvssV3_1: {
              baseScore: 10,
              baseSeverity: 'CRITICAL',
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            },
          },
        ],
        problemTypes: [{ descriptions: [{ cweId: 'CWE-506', description: 'Embedded Malicious Code' }] }],
        affected: [{ vendor: 'tukaani', packageName: 'xz' }],
        references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094' }],
      },
    },
  };

  const parsed = parseMitreCveRecord(sample);
  assert.ok(parsed);
  assert.equal(parsed.cveId, 'CVE-2024-3094');
  assert.equal(parsed.cvssScore, 10);
  assert.equal(parsed.cvssSeverity, 'CRITICAL');
  assert.deepEqual(parsed.cwes, ['CWE-506: Embedded Malicious Code']);
  assert.deepEqual(parsed.affectedProducts, ['tukaani / xz']);
});

test('parseRdapDomainProfile extracts registrar, dates, DNSSEC, and abuse contacts', () => {
  const sample = {
    status: ['client transfer prohibited'],
    secureDNS: { delegationSigned: false },
    events: [
      { eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' },
      { eventAction: 'expiration', eventDate: '2028-09-14T04:00:00Z' },
    ],
    entities: [
      {
        roles: ['registrar'],
        vcardArray: ['vcard', [['fn', {}, 'text', 'MarkMonitor Inc.']]],
        entities: [
          { vcardArray: ['vcard', [['email', {}, 'text', 'abusecomplaints@markmonitor.com']]] },
        ],
      },
    ],
  };

  const parsed = parseRdapDomainProfile(sample);
  assert.ok(parsed);
  assert.equal(parsed.registrar, 'MarkMonitor Inc.');
  assert.equal(parsed.registrationDate, '1997-09-15T04:00:00Z');
  assert.equal(parsed.expirationDate, '2028-09-14T04:00:00Z');
  assert.equal(parsed.dnssecSigned, false);
  assert.deepEqual(parsed.abuseEmails, ['abusecomplaints@markmonitor.com']);
});

test('parseRipeStatPrefix normalizes BGP announced prefix and ASNs', () => {
  const parsed = parseRipeStatPrefix({
    data: {
      resource: '1.1.1.0/24',
      announced: true,
      asns: [{ asn: 13335, holder: 'CLOUDFLARENET' }],
      block: { desc: 'APNIC (ALLOCATED)' },
    },
  });
  assert.ok(parsed);
  assert.equal(parsed.prefix, '1.1.1.0/24');
  assert.equal(parsed.announced, true);
  assert.equal(parsed.asns[0].asn, 13335);
});

test('parseWaybackCdx formats earliest and latest snapshot dates', () => {
  const parsed = parseWaybackCdx(
    [['timestamp', 'statuscode'], ['19981111184551', '200']],
    [['timestamp', 'statuscode'], ['20261119120000', '200']],
    'google.com',
  );
  assert.ok(parsed);
  assert.equal(parsed.firstSnapshot, '1998-11-11');
  assert.equal(parsed.latestSnapshot, '2026-11-19');
  assert.equal(parsed.archiveUrl, 'https://web.archive.org/web/*/google.com');
});
