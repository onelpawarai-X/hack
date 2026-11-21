import { randomUUID } from 'node:crypto';
import type { AttackEvent } from '../src/types/defenseGrid.ts';
import type { BlockedIpEntry, ProtectedSystemShield, ThreatSeverity } from '../src/types/cyber.ts';
import { deleteConfig, getConfig, insertDelivery, setConfig } from './db.ts';

export type AlertChannel = 'slack' | 'telegram' | 'siem' | 'local';

export interface IntegrationStatus {
  channel: AlertChannel;
  name: string;
  configured: boolean;
  source: 'database' | 'environment' | 'none';
  target?: string;
  detail: string;
}

export interface DeliveryResult {
  channel: AlertChannel;
  ok: boolean;
  detail: string;
}

export function getIntegrationStatus(): {
  integrations: IntegrationStatus[];
  minSeverity: ThreatSeverity;
  notifyOnBlock: boolean;
} {
  return {
    minSeverity: (getConfig('alerts.minSeverity') as ThreatSeverity) || 'HIGH',
    notifyOnBlock: getConfig('alerts.notifyOnBlock') !== 'false',
    integrations: [],
  };
}

export function setIntegrationConfig(
  _channel: AlertChannel,
  _payload: Record<string, unknown>,
): { ok: boolean; error?: string } {
  return {
    ok: false,
    error:
      'Remote webhook/bot integrations are disabled. SentinelGlobe uses local event storage only.',
  };
}

export function clearIntegrationConfig(_channel: AlertChannel): void {
  // Remote integration state is intentionally not used.
}

export function setAlertPolicy(policy: { minSeverity?: ThreatSeverity; notifyOnBlock?: boolean }): void {
  if (policy.minSeverity) setConfig('alerts.minSeverity', policy.minSeverity);
  if (typeof policy.notifyOnBlock === 'boolean') {
    setConfig('alerts.notifyOnBlock', String(policy.notifyOnBlock));
  }
}

function severityRank(severity: ThreatSeverity): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'ELEVATED':
      return 2;
    default:
      return 1;
  }
}

function recordLocal(event: AttackEvent, blocked: boolean) {
  try {
    insertDelivery({
      id: randomUUID(),
      ts: new Date().toISOString(),
      channel: 'local',
      target: 'local-event-store',
      status: 'sent',
      detail: `${blocked ? 'AUTO-BLOCK' : 'OBSERVED'} ${event.severity} ${event.category} ${event.ip} ${event.method} ${event.path}`.slice(
        0,
        600,
      ),
      eventId: event.id,
    });
  } catch {
    // Delivery logging is best effort.
  }
}

export async function notifyAttack(event: AttackEvent, blocked: boolean): Promise<DeliveryResult[]> {
  const policy = getIntegrationStatus();
  if (severityRank(event.severity) < severityRank(policy.minSeverity)) return [];
  if (blocked && !policy.notifyOnBlock && event.action === 'blocked') return [];
  recordLocal(event, blocked);
  return [{ channel: 'local', ok: true, detail: 'Stored in the local event ledger.' }];
}

export async function notifyBlock(entry: BlockedIpEntry): Promise<DeliveryResult[]> {
  return [
    {
      channel: 'local',
      ok: true,
      detail: `Blocked ${entry.ip} in the local defense engine.`,
    },
  ];
}

export async function notifyShield(shield: ProtectedSystemShield): Promise<DeliveryResult[]> {
  return [
    {
      channel: 'local',
      ok: true,
      detail: `Shield ${shield.id} evaluated locally.`,
    },
  ];
}

export async function testIntegration(_channel: AlertChannel): Promise<DeliveryResult> {
  return {
    channel: 'local',
    ok: false,
    detail: 'Remote integrations and email delivery are disabled. Events stay in the local ledger.',
  };
}

export async function sendTestAlert(): Promise<DeliveryResult> {
  return {
    channel: 'local',
    ok: true,
    detail: 'Local event ledger is active. No remote API was called.',
  };
}

export function deleteIntegrationConfig(channel: AlertChannel): void {
  if (channel === 'slack') deleteConfig('integration.slack.webhook');
  if (channel === 'siem') deleteConfig('integration.siem.webhook');
  if (channel === 'telegram') {
    deleteConfig('integration.telegram.botToken');
    deleteConfig('integration.telegram.chatId');
  }
}

export const notifyBlockedIp = notifyBlock;
export const notifyShieldAlert = notifyShield;
