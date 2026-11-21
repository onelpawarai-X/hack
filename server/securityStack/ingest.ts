import { randomUUID } from 'node:crypto';
import type { AttackEvent } from '../../src/types/defenseGrid.ts';
import type {
  SecurityToolId,
  StackIngestResult,
} from '../../src/types/securityStack.ts';
import { attackSensor, isBlockablePublicIp } from '../attackSensor.ts';
import { defenseEngine } from '../defenseEngine.ts';
import { isPrivateOrReservedIp, isValidIpv4 } from '../threatRules.ts';
import { parseNdjsonLines, parseSecurityStackPayload, type NormalizedStackEvent } from './parsers.ts';

const AUTO_BLOCK_ENABLED = process.env.SENTINEL_STACK_AUTO_BLOCK !== 'false';
const MAX_AUTO_BLOCKS_PER_REQUEST = Number(process.env.SENTINEL_STACK_MAX_BLOCKS) || 5;

function toAttackEvent(event: NormalizedStackEvent, action: AttackEvent['action']): AttackEvent {
  return {
    id: randomUUID(),
    ts: event.ts,
    ip: event.ip,
    method: event.method,
    path: event.path,
    host: event.host,
    userAgent: event.userAgent,
    category: event.category,
    severity: event.severity,
    detail: `[${event.source}] ${event.detail}`,
    action,
    source: 'sensor',
    sensorId: event.source,
    requestCount: 1,
  };
}

function shouldBlock(event: NormalizedStackEvent, safeIps: ReadonlySet<string>): boolean {
  if (!AUTO_BLOCK_ENABLED) return false;
  if (event.severity !== 'CRITICAL' && event.severity !== 'HIGH') return false;
  if (!isValidIpv4(event.ip) || isPrivateOrReservedIp(event.ip)) return false;
  if (safeIps.has(event.ip)) return false;
  return isBlockablePublicIp(event.ip, safeIps);
}

export async function ingestNormalizedEvents(
  source: SecurityToolId,
  normalized: NormalizedStackEvent[],
): Promise<StackIngestResult> {
  const result: StackIngestResult = {
    source,
    accepted: 0,
    blocked: 0,
    skipped: 0,
    events: [],
    errors: [],
  };
  if (normalized.length === 0) {
    result.errors.push('No parseable events in payload.');
    return result;
  }
  const safeIps = new Set(attackSensor.getSnapshotSafeIps());
  let autoBlocks = 0;
  for (const event of normalized) {
    if (!event.ip || event.ip === 'unknown') {
      result.skipped += 1;
      continue;
    }
    let action: AttackEvent['action'] = 'observed';
    if (
      autoBlocks < MAX_AUTO_BLOCKS_PER_REQUEST &&
      shouldBlock(event, safeIps) &&
      !defenseEngine.isIpBlocked(event.ip)
    ) {
      try {
        await defenseEngine.defendAttackerIp(
          event.ip,
          `${source}: ${event.detail}`,
          event.severity,
        );
        action = 'blocked';
        autoBlocks += 1;
        result.blocked += 1;
      } catch (error) {
        result.errors.push(
          `block ${event.ip}: ${error instanceof Error ? error.message : 'failed'}`,
        );
      }
    }
    const attackEvent = toAttackEvent(event, action);
    attackSensor.ingestExternalEvents([attackEvent]);
    result.accepted += 1;
    result.events.push({
      id: attackEvent.id,
      ip: attackEvent.ip,
      severity: attackEvent.severity,
      category: attackEvent.category,
      detail: attackEvent.detail,
      action: attackEvent.action,
    });
  }
  return result;
}

export async function ingestSecurityStackPayload(
  source: SecurityToolId,
  payload: unknown,
): Promise<StackIngestResult> {
  return ingestNormalizedEvents(source, parseSecurityStackPayload(source, payload));
}

export async function ingestSecurityStackText(
  source: SecurityToolId,
  text: string,
): Promise<StackIngestResult> {
  const trimmed = text.trim();
  if (!trimmed) {
    return { source, accepted: 0, blocked: 0, skipped: 0, events: [], errors: ['Empty body.'] };
  }
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return ingestSecurityStackPayload(source, JSON.parse(trimmed));
    } catch {
      // Fall through to NDJSON, which also handles multiple JSON objects.
    }
  }
  const parsed = parseNdjsonLines(source, trimmed);
  const result = await ingestNormalizedEvents(source, parsed.events);
  result.errors.push(...parsed.errors);
  return result;
}
