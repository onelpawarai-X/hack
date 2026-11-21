import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyAttack, isBlockablePublicIp, isStaticAssetPath } from './attackSensor.ts';

test('classifies decoy asset probes as honeypot events', () => {
  const env = classifyAttack({ path: '/.env', userAgent: 'curl/8' });
  assert.equal(env.category, 'honeypot');
  assert.equal(env.severity, 'CRITICAL');
  assert.equal(env.honeypot, true);

  const login = classifyAttack({ path: '/wp-login.php', method: 'POST' });
  assert.equal(login.category, 'credential-stuffing');
  assert.equal(login.honeypot, true);
});

test('classifies SQL injection, XSS, traversal and RCE payloads', () => {
  assert.equal(
    classifyAttack({ path: '/search', query: '?q=1%20UNION%20SELECT%20password%20FROM%20users' }).category,
    'sqli',
  );
  assert.equal(
    classifyAttack({ path: '/search', query: '?q=%3Cscript%3Ealert(1)%3C/script%3E' }).category,
    'xss',
  );
  assert.equal(
    classifyAttack({ path: '/download', query: '?file=../../etc/passwd' }).category,
    'path-traversal',
  );
  assert.equal(
    classifyAttack({ path: '/ping', query: '?host=127.0.0.1;cat%20/etc/passwd' }).category,
    'rce',
  );
});

test('classifies offensive scanner user-agents', () => {
  const result = classifyAttack({ path: '/', userAgent: 'sqlmap/1.8.2#stable' });
  assert.equal(result.category, 'scanner');
  assert.equal(result.severity, 'ELEVATED');
});

test('leaves clean requests alone', () => {
  const result = classifyAttack({
    path: '/api/health',
    query: '',
    userAgent: 'Mozilla/5.0 SentinelGlobe',
  });
  assert.equal(result.category, 'other');
  assert.equal(result.severity, 'CLEAN');
});

test('excludes static assets from the sensor and rate shield', () => {
  assert.equal(isStaticAssetPath('/assets/index-abc.js'), true);
  assert.equal(isStaticAssetPath('/src/main.tsx'), true);
  assert.equal(isStaticAssetPath('/socket.io/?EIO=4'), true);
  assert.equal(isStaticAssetPath('/api/health'), false);
  assert.equal(isStaticAssetPath('/.env'), false);
});

test('never auto-blocks private, reserved or explicitly safe IPs', () => {
  assert.equal(isBlockablePublicIp('127.0.0.1'), false);
  assert.equal(isBlockablePublicIp('192.168.1.10'), false);
  assert.equal(isBlockablePublicIp('10.0.0.5'), false);
  assert.equal(isBlockablePublicIp('8.8.8.8'), true);
  assert.equal(isBlockablePublicIp('8.8.8.8', new Set(['8.8.8.8'])), false);
  assert.equal(isBlockablePublicIp('not-an-ip'), false);
});
