import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSelectedModules,
  resolveTargetDescriptor,
  runModularScanOrchestrator,
} from './orchestrator.ts';
import { ALL_SCAN_MODULES, type ScanModulePlugin } from './modules/types.ts';

function fakeActivePlugin(ran: { value: boolean }): ScanModulePlugin {
  return {
    id: 'portScan',
    label: 'Fake Active Probe',
    isActive: true,
    supportsTargetType: () => true,
    run: async (ctx) => {
      ran.value = true;
      ctx.log('fake active probe executed');
    },
  };
}

test('normalizeSelectedModules selects every module by default so the gate can report skips', () => {
  const selected = normalizeSelectedModules();
  assert.deepEqual(selected, [...ALL_SCAN_MODULES]);
  assert.ok(selected.includes('portScan'));
  assert.ok(selected.includes('sensitiveFiles'));
  assert.ok(selected.includes('activeVulns'));
});

test('normalizeSelectedModules drops invalid ids and falls back to all modules', () => {
  assert.deepEqual(normalizeSelectedModules(['portScan', 'bogus' as never]), ['portScan']);
  assert.deepEqual(normalizeSelectedModules(['bogus' as never]), [...ALL_SCAN_MODULES]);
});

test('resolveTargetDescriptor classifies domains, URLs, IPs and CVEs', () => {
  assert.equal(resolveTargetDescriptor('https://example.com/path').targetType, 'url');
  assert.equal(resolveTargetDescriptor('example.com').targetType, 'domain');
  assert.equal(resolveTargetDescriptor('example.com').rootDomain, 'example.com');
  assert.equal(resolveTargetDescriptor('1.1.1.1').targetType, 'ip');
  assert.equal(resolveTargetDescriptor('CVE-2024-3094').targetType, 'cve');
});

test('ethical gate blocks active modules until ownership is verified', async () => {
  const ran = { value: false };
  const result = await runModularScanOrchestrator({
    target: 'example.com',
    modules: ['portScan'],
    verifyOwnershipFn: () => false,
    customRegistry: { portScan: fakeActivePlugin(ran) },
  });

  assert.equal(ran.value, false);
  assert.equal(result.ownershipVerified, false);
  assert.deepEqual(result.executedModules, []);
  const skipped = result.skippedActiveModules ?? [];
  assert.equal(skipped.length, 1);
  assert.equal(skipped[0].moduleId, 'portScan');
});

test('ethical gate releases active modules after ownership verification', async () => {
  const ran = { value: false };
  const result = await runModularScanOrchestrator({
    target: 'example.com',
    modules: ['portScan'],
    verifyOwnershipFn: () => true,
    customRegistry: { portScan: fakeActivePlugin(ran) },
  });

  assert.equal(ran.value, true);
  assert.equal(result.ownershipVerified, true);
  assert.deepEqual(result.executedModules, ['portScan']);
  assert.deepEqual(result.skippedActiveModules, []);
});
