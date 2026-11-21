import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatCurrencyUsd,
  formatShortDate,
  formatSignedPercent,
  formatUtcTimestamp,
} from './formatters';

test('formatCurrencyUsd formats USD amounts consistently', () => {
  assert.equal(formatCurrencyUsd(92450.5), '$92,450.50');
  assert.equal(formatCurrencyUsd(1.2345), '$1.2345');
});

test('formatSignedPercent adds plus sign for positive values', () => {
  assert.equal(formatSignedPercent(3.456), '+3.46%');
  assert.equal(formatSignedPercent(-1.2), '-1.20%');
  assert.equal(formatSignedPercent(null), '—');
});

test('formatShortDate parses both GDELT and ISO timestamps', () => {
  assert.equal(formatShortDate('20261120T091500Z'), '2026-11-20 09:15 UTC');
  assert.equal(formatShortDate('2026-11-20T09:15:00.000Z'), '2026-11-20 09:15 UTC');
});

test('formatUtcTimestamp formats ISO timestamps with UTC suffix', () => {
  const formatted = formatUtcTimestamp('2026-11-20T09:15:30.000Z', 'en');
  assert.ok(formatted.includes('UTC'));
  assert.ok(formatted.includes('09:15:30'));
});
