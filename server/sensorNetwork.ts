import { randomBytes, randomUUID } from 'node:crypto';
import type { Request } from 'express';
import type { AttackEvent, AttackCategory } from '../src/types/defenseGrid.ts';
import { attackSensor, classifyAttack, isBlockablePublicIp } from './attackSensor.ts';
import {
  ensureSensorNode,
  getConfig,
  listSensorNodes,
  recordSensorHeartbeat,
  setConfig,
  upsertSensorNode,
} from './db.ts';
import { defenseEngine } from './defenseEngine.ts';
import { ipv4Subnet, tlshFromText } from './fingerprint.ts';

export interface RawSensorEvent {
  ts?: string;
  ip: string;
  method?: string;
  path?: string;
  query?: string;
  host?: string;
  userAgent?: string;
  headers?: Record<string, string | undefined>;
  body?: unknown;
  country?: string;
  city?: string;
  asn?: string;
  ja3?: string;
  ja4?: string;
  tlsh?: string;
  tlsVersion?: string;
  cipher?: string;
}

export interface SensorOverview {
  nodes: Array<{
    id: string;
    name: string;
    region?: string;
    url?: string;
    enabled: boolean;
    createdAt: string;
    lastSeenAt?: string;
    eventCount: number;
    status: 'online' | 'stale' | 'pending' | 'disabled';
    ageSeconds?: number;
  }>;
  ingestUrl: string;
  tokenPreview: string;
  autoBlock: boolean;
}

export function getIngestToken(): string {
  const envToken = process.env.SENTINEL_SENSOR_TOKEN?.trim();
  if (envToken) return envToken;
  const stored = getConfig('sensor.ingestToken');
  if (stored) return stored;
  const token = randomBytes(32).toString('hex');
  setConfig('sensor.ingestToken', token);
  return token;
}

export function rotateIngestToken(): string {
  if (process.env.SENTINEL_SENSOR_TOKEN?.trim()) {
    throw new Error('Token is managed by SENTINEL_SENSOR_TOKEN and cannot be rotated here.');
  }
  const token = randomBytes(32).toString('hex');
  setConfig('sensor.ingestToken', token);
  return token;
}

export function tokenPreview(): string {
  const token = getIngestToken();
  return `${token.slice(0, 6)}…${token.slice(-4)}`;
}

export function verifySensorToken(req: Request): boolean {
  const header = req.headers['x-sentinel-sensor-token'];
  const auth = req.headers.authorization;
  const provided =
    typeof header === 'string'
      ? header.trim()
      : typeof auth === 'string' && auth.startsWith('Bearer ')
        ? auth.slice(7).trim()
        : '';
  const expected = getIngestToken();
  if (!provided || provided.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < provided.length; i += 1) {
    mismatch |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return mismatch === 0;
}

export function registerSensorNode(input: {
  id: string;
  name: string;
  region?: string;
  url?: string;
}): { ok: boolean; error?: string } {
  const id = input.id.trim();
  if (!/^[a-zA-Z0-9_-]{2,64}$/.test(id)) {
    return { ok: false, error: 'Sensor id must be 2-64 characters: letters, digits, _ or -.' };
  }
  upsertSensorNode({
    id,
    name: input.name.trim().slice(0, 80) || id,
    region: input.region?.trim().slice(0, 80),
    url: input.url?.trim().slice(0, 300),
    status: 'pending',
  });
  return { ok: true };
}

function sensorEventFromRaw(sensorId: string, raw: RawSensorEvent): AttackEvent {
  const headers = raw.headers ?? {};
  const ip = String(raw.ip ?? '').trim();
  const path = String(raw.path ?? '/').slice(0, 500);
  const query = raw.query ? String(raw.query).slice(0, 500) : '';
  const userAgent = String(raw.userAgent ?? headers['user-agent'] ?? '').slice(0, 300);
  const classification = classifyAttack({
    path,
    query,
    userAgent,
    method: raw.method,
  });
  const bodyText =
    raw.body === undefined || raw.body === null
      ? ''
      : typeof raw.body === 'string'
        ? raw.body
        : JSON.stringify(raw.body);
  const ja3 = raw.ja3 ?? headers['x-ja3-hash'] ?? headers['x-ja3'] ?? headers['cf-ja3-hash'];
  const ja4 = raw.ja4 ?? headers['x-ja4'] ?? headers['cf-ja4'];
  const asnHeader = headers['cf-asn'] ?? headers['x-asn'] ?? headers['x-ip-asn'];
  const asn = raw.asn ?? (asnHeader ? (/^\d+$/.test(asnHeader) ? `AS${asnHeader}` : asnHeader) : undefined);

  return {
    id: randomUUID(),
    ts: raw.ts && !Number.isNaN(new Date(raw.ts).getTime()) ? new Date(raw.ts).toISOString() : new Date().toISOString(),
    ip: ip || 'unknown',
    method: (raw.method ?? 'GET').toUpperCase().slice(0, 12),
    path,
    host: raw.host?.slice(0, 200),
    userAgent,
    category: classification.category as AttackCategory,
    severity: classification.severity,
    detail: classification.detail || 'Distributed honeypot request',
    action: 'observed',
    source: 'sensor',
    sensorId,
    country: raw.country,
    city: raw.city,
    asn,
    subnet: ipv4Subnet(ip),
    ja3,
    ja4,
    tlsh: raw.tlsh ?? tlshFromText(bodyText),
    tlsVersion: raw.tlsVersion ?? headers['x-tls-version'],
    cipher: raw.cipher ?? headers['x-tls-cipher'],
  };
}

export function ingestRawSensorEvents(
  sensorId: string,
  rawEvents: RawSensorEvent[],
): { accepted: number; blocked: number; events: AttackEvent[] } {
  const id = sensorId.trim().slice(0, 64) || 'unknown-sensor';
  ensureSensorNode(id);

  const events = rawEvents.slice(0, 200).map((raw) => sensorEventFromRaw(id, raw));
  const autoBlock = getConfig('sensor.autoBlock') !== 'false';
  let blocked = 0;

  for (const event of events) {
    const shouldBlock =
      autoBlock &&
      isBlockablePublicIp(event.ip) &&
      (event.category === 'honeypot' ||
        event.category === 'rce' ||
        event.category === 'sqli' ||
        event.category === 'ddos' ||
        event.severity === 'CRITICAL');
    if (shouldBlock) {
      event.action = 'blocked';
      blocked += 1;
      void defenseEngine
        .defendAttackerIp(
          event.ip,
          `Distributed sensor ${id}: ${event.category} ${event.detail}`,
          event.severity,
        )
        .catch(() => null);
    }
  }

  // Ingest through the main sensor so persistence, broadcasting and alerts stay in one path.
  attackSensor.ingestExternalEvents(events);

  recordSensorHeartbeat(id, 'online', events.length);
  return { accepted: events.length, blocked, events };
}

export function sensorOverview(baseUrl: string): SensorOverview {
  const nodes = listSensorNodes().map((node) => {
    const ageSeconds = node.lastSeenAt
      ? Math.max(0, Math.floor((Date.now() - new Date(node.lastSeenAt).getTime()) / 1000))
      : undefined;
    const status: 'online' | 'stale' | 'pending' | 'disabled' = !node.enabled
      ? 'disabled'
      : ageSeconds !== undefined && ageSeconds < 300
        ? 'online'
        : node.lastSeenAt
          ? 'stale'
          : 'pending';
    return { ...node, status, ageSeconds };
  });
  return {
    nodes,
    ingestUrl: `${baseUrl.replace(/\/$/, '')}/api/sensors/ingest`,
    tokenPreview: tokenPreview(),
    autoBlock: getConfig('sensor.autoBlock') !== 'false',
  };
}

export function setSensorAutoBlock(enabled: boolean): void {
  setConfig('sensor.autoBlock', String(enabled));
}

export function setSensorEnabled(id: string, enabled: boolean): boolean {
  const node = listSensorNodes().find((item) => item.id === id);
  if (!node) return false;
  upsertSensorNode({ ...node, enabled });
  return true;
}

export function agentCommand(baseUrl: string, sensorId = 'vps-fra-1', region = 'eu-central'): string {
  return [
    `SENTINEL_CENTRAL_URL='${baseUrl.replace(/\/$/, '')}'`,
    `SENTINEL_SENSOR_TOKEN='${getIngestToken()}'`,
    `SENSOR_ID='${sensorId}'`,
    `SENSOR_REGION='${region}'`,
    `SENSOR_PORT='8088'`,
    `SENSOR_TLS_PORT='8443'`,
    'node sensor-agent/agent.mjs',
  ].join(' ');
}
