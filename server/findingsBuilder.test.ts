import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RiskLevel, SecurityFinding } from '../src/types/cyber.ts';
import { computeRiskScore } from './findingsBuilder.ts';

function finding(riskLevel: RiskLevel): SecurityFinding {
  return {
    id: `f-${riskLevel}`,
    moduleId: 'headers',
    title: `${riskLevel} finding`,
    description: 'test',
    riskLevel,
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    owaspId: 'A05:2021',
    evidence: 'test',
    remediation: 'test',
  };
}

test('computeRiskScore returns zero and grade A for a clean scan', () => {
  const result = computeRiskScore([], 'CLEAN');
  assert.equal(result.score, 0);
  assert.equal(result.grade, 'A');
  assert.equal(result.components.length, 0);
});

test('computeRiskScore applies severity weights and counts', () => {
  const result = computeRiskScore(
    [finding('Critical'), finding('High'), finding('High'), finding('Medium')],
    'CLEAN',
  );
  assert.equal(result.rawPoints, 40 + 20 + 20 + 8);
  assert.equal(result.score, 88);
  assert.equal(result.grade, 'F');
  assert.deepEqual(
    result.components.map((component) => [component.severity, component.count, component.points]),
    [
      ['Critical', 1, 40],
      ['High', 2, 40],
      ['Medium', 1, 8],
    ],
  );
});

test('computeRiskScore honors the verdict floor without findings', () => {
  assert.equal(computeRiskScore([], 'ELEVATED').score, 30);
  assert.equal(computeRiskScore([], 'HIGH').score, 55);
  assert.equal(computeRiskScore([], 'CRITICAL').score, 80);
});

test('computeRiskScore caps raw points at 100 and flags the cap', () => {
  const result = computeRiskScore([finding('Critical'), finding('Critical'), finding('Critical')], 'CLEAN');
  assert.equal(result.rawPoints, 120);
  assert.equal(result.score, 100);
  assert.equal(result.capped, true);
});
