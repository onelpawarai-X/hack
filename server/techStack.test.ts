import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { CveDetailRecord } from '../src/types/cyber.ts';
import { detectTechStack, filterContextualCves } from './techStack.ts';

function cve(id: string, products: string[]): CveDetailRecord {
  return {
    cveId: id,
    title: id,
    description: id,
    cwes: [],
    affectedProducts: products,
    references: [],
  };
}

test('detectTechStack extracts versions from headers and CPE-style fingerprints', () => {
  const stack = detectTechStack({
    headers: { server: 'nginx/1.24.0', 'x-powered-by': 'PHP/8.3.2' },
    cpes: ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'],
  });
  const nginx = stack.find((item) => item.name === 'Nginx');
  const php = stack.find((item) => item.name === 'PHP');
  assert.equal(nginx?.version, '1.24.0');
  assert.equal(nginx?.cpe, 'nginx:nginx');
  assert.equal(php?.version, '8.3.2');
});

test('filterContextualCves keeps matching products and suppresses cross-product CVEs', () => {
  const stack = detectTechStack({
    headers: { server: 'nginx/1.24.0' },
    cpes: ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'],
  });
  const result = filterContextualCves(
    [
      cve('CVE-NGINX', ['cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*']),
      cve('CVE-APACHE', ['cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*']),
      cve('CVE-NO-METADATA', ['unspecified product']),
    ],
    stack,
  );
  assert.deepEqual(result.kept.map((item) => item.cveId), ['CVE-NGINX', 'CVE-NO-METADATA']);
  assert.equal(result.kept[0].stackMatch?.confidence, 'High');
  assert.equal(result.kept[1].stackMatch?.confidence, 'Low');
  assert.deepEqual(result.excluded.map((item) => item.cveId), ['CVE-APACHE']);
});

test('filterContextualCves matches CPE-only stacks such as WordPress', () => {
  const stack = detectTechStack({
    headers: {},
    cpes: ['cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*'],
  });
  const result = filterContextualCves(
    [
      cve('CVE-WP', ['cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*']),
      cve('CVE-REDIS', ['cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*']),
    ],
    stack,
  );
  assert.deepEqual(result.kept.map((item) => item.cveId), ['CVE-WP']);
  assert.deepEqual(result.excluded.map((item) => item.cveId), ['CVE-REDIS']);
});
