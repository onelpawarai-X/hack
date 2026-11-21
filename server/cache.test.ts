import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryCache } from './cache.ts';

test('MemoryCache stores and retrieves values before TTL expires', () => {
  const cache = new MemoryCache(15 * 60 * 1000);
  const t0 = 1_700_000_000_000;
  cache.set('briefing:en', { ok: true }, t0);

  const hit = cache.get<{ ok: boolean }>('briefing:en', t0 + 60_000);
  assert.ok(hit);
  assert.equal(hit.value.ok, true);
  assert.equal(hit.expiresAt, t0 + 15 * 60 * 1000);
});

test('MemoryCache expires entries at or after TTL', () => {
  const cache = new MemoryCache(1000);
  const t0 = 1_000_000;
  cache.set('k1', 'data', t0);

  assert.equal(cache.get('k1', t0 + 999)?.value, 'data');
  assert.equal(cache.get('k1', t0 + 1000), null);
});

test('MemoryCache clearByPrefix removes matching keys only', () => {
  const cache = new MemoryCache(60_000);
  const t0 = 5_000_000;
  cache.set('briefing:en', 1, t0);
  cache.set('briefing:bn', 2, t0);
  cache.set('markets:en', 3, t0);

  const removed = cache.clearByPrefix('briefing:');
  assert.equal(removed, 2);
  assert.equal(cache.get('briefing:en', t0), null);
  assert.equal(cache.get('markets:en', t0)?.value, 3);
});
