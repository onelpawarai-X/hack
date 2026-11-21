import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildDomainVerificationToken,
  matchesHtmlMetaVerification,
  matchesHttpVerificationBody,
  matchesTxtVerificationToken,
  normalizeVerificationDomain,
} from './domainVerification.ts';

test('normalizeVerificationDomain extracts a root domain from URLs and bare hosts', () => {
  assert.equal(normalizeVerificationDomain('https://www.Example.com/path?q=1'), 'example.com');
  assert.equal(normalizeVerificationDomain('shop.example.co.uk'), 'example.co.uk');
});

test('buildDomainVerificationToken is stable for the same domain', () => {
  const first = buildDomainVerificationToken('example.com', 'test-secret');
  const second = buildDomainVerificationToken('https://www.example.com/', 'test-secret');
  assert.equal(first, second);
  assert.match(first, /^sentinelglobe-verify=[a-f0-9]{24}$/);
});

test('TXT and HTTP verification matchers accept the exact token only', () => {
  const token = buildDomainVerificationToken('example.com', 'test-secret');
  assert.equal(matchesTxtVerificationToken([`prefix ${token} suffix`], token), true);
  assert.equal(matchesTxtVerificationToken(['sentinelglobe-verify=deadbeef'], token), false);
  assert.equal(matchesHttpVerificationBody(`\n${token}\n`, token), true);
  assert.equal(matchesHttpVerificationBody('unrelated body', token), false);
});

test('meta-tag verification requires the named tag and token in the same tag', () => {
  const token = buildDomainVerificationToken('example.com', 'test-secret');
  assert.equal(
    matchesHtmlMetaVerification(
      `<html><head><meta name="sentinelglobe-site-verification" content="${token}"></head></html>`,
      token,
    ),
    true,
  );
  assert.equal(
    matchesHtmlMetaVerification(
      `<meta name="other" content="${token}"><p>${token}</p>`,
      token,
    ),
    false,
  );
  assert.equal(matchesHtmlMetaVerification('<html></html>', token), false);
});
