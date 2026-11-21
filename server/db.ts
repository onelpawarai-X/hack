import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import type { AttackEvent } from '../src/types/defenseGrid.ts';

const DATA_DIR = path.resolve(process.cwd(), '.sentinel');
const DB_PATH = path.resolve(DATA_DIR, 'sentinel.db');

fs.mkdirSync(DATA_DIR, { recursive: true });

export const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS attack_events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT,
    path TEXT,
    host TEXT,
    user_agent TEXT,
    category TEXT,
    severity TEXT,
    detail TEXT,
    action TEXT,
    source TEXT,
    country TEXT,
    city TEXT,
    asn TEXT,
    isp TEXT,
    abuse_emails TEXT,
    request_count INTEGER,
    sensor_id TEXT,
    ja3 TEXT,
    ja4 TEXT,
    tlsh TEXT,
    tls_version TEXT,
    cipher TEXT,
    subnet TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_events_ts ON attack_events(ts DESC);
  CREATE INDEX IF NOT EXISTS idx_events_ip ON attack_events(ip);
  CREATE INDEX IF NOT EXISTS idx_events_source ON attack_events(source);
  CREATE INDEX IF NOT EXISTS idx_events_category ON attack_events(category);

  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

  CREATE TABLE IF NOT EXISTS sensor_nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    region TEXT,
    url TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_seen_at TEXT,
    event_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS alert_deliveries (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    channel TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL,
    detail TEXT,
    event_id TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_deliveries_ts ON alert_deliveries(ts DESC);

  CREATE TABLE IF NOT EXISTS waf_sync_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    provider TEXT NOT NULL,
    action TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL,
    detail TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_waf_sync_ts ON waf_sync_log(ts DESC);

  DROP TABLE IF EXISTS canary_tokens;
  DELETE FROM attack_events
  WHERE source = 'canarytokens'
     OR sensor_id = 'canarytokens'
     OR path LIKE '/api/canary/%'
     OR path LIKE '%.canary.sentinel.local';
`);

export interface AttackEventRow extends AttackEvent {
  sensorId?: string;
  ja3?: string;
  ja4?: string;
  tlsh?: string;
  tlsVersion?: string;
  cipher?: string;
  subnet?: string;
}

const insertEventStmt = db.prepare(`
  INSERT OR REPLACE INTO attack_events
    (id, ts, ip, method, path, host, user_agent, category, severity, detail, action, source,
     country, city, asn, isp, abuse_emails, request_count, sensor_id, ja3, ja4, tlsh,
     tls_version, cipher, subnet)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

export function insertAttackEvent(event: AttackEventRow): void {
  insertEventStmt.run(
    event.id,
    event.ts,
    event.ip,
    event.method ?? null,
    event.path ?? null,
    event.host ?? null,
    event.userAgent ?? null,
    event.category ?? null,
    event.severity ?? null,
    event.detail ?? null,
    event.action ?? null,
    event.source ?? null,
    event.country ?? null,
    event.city ?? null,
    event.asn ?? null,
    event.isp ?? null,
    event.abuseEmails ? JSON.stringify(event.abuseEmails) : null,
    event.requestCount ?? null,
    event.sensorId ?? null,
    event.ja3 ?? null,
    event.ja4 ?? null,
    event.tlsh ?? null,
    event.tlsVersion ?? null,
    event.cipher ?? null,
    event.subnet ?? null,
  );
}

export function insertAttackEvents(events: AttackEventRow[]): void {
  for (const event of events) insertAttackEvent(event);
}

interface EventQuery {
  limit?: number;
  offset?: number;
  ip?: string;
  source?: string;
  category?: string;
  since?: string;
}

export function listAttackEvents(query: EventQuery = {}): AttackEventRow[] {
  const limit = Math.min(Math.max(query.limit ?? 100, 1), 1000);
  const offset = Math.max(query.offset ?? 0, 0);
  const conditions: string[] = [];
  const params: Array<string | number> = [];

  if (query.ip) {
    conditions.push('ip = ?');
    params.push(query.ip);
  }
  if (query.source) {
    conditions.push('source = ?');
    params.push(query.source);
  }
  if (query.category) {
    conditions.push('category = ?');
    params.push(query.category);
  }
  if (query.since) {
    conditions.push('ts >= ?');
    params.push(query.since);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(limit, offset);
  const rows = db
    .prepare(`SELECT * FROM attack_events ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`)
    .all(...params) as Array<Record<string, unknown>>;

  return rows.map((row) => ({
    id: String(row.id),
    ts: String(row.ts),
    ip: String(row.ip),
    method: String(row.method ?? ''),
    path: String(row.path ?? ''),
    host: row.host ? String(row.host) : undefined,
    userAgent: row.user_agent ? String(row.user_agent) : undefined,
    category: String(row.category ?? 'other') as AttackEvent['category'],
    severity: String(row.severity ?? 'CLEAN') as AttackEvent['severity'],
    detail: String(row.detail ?? ''),
    action: String(row.action ?? 'observed') as AttackEvent['action'],
    source: String(row.source ?? 'sensor') as AttackEvent['source'],
    country: row.country ? String(row.country) : undefined,
    city: row.city ? String(row.city) : undefined,
    asn: row.asn ? String(row.asn) : undefined,
    isp: row.isp ? String(row.isp) : undefined,
    abuseEmails: row.abuse_emails ? (JSON.parse(String(row.abuse_emails)) as string[]) : undefined,
    requestCount: row.request_count ? Number(row.request_count) : undefined,
    sensorId: row.sensor_id ? String(row.sensor_id) : undefined,
    ja3: row.ja3 ? String(row.ja3) : undefined,
    ja4: row.ja4 ? String(row.ja4) : undefined,
    tlsh: row.tlsh ? String(row.tlsh) : undefined,
    tlsVersion: row.tls_version ? String(row.tls_version) : undefined,
    cipher: row.cipher ? String(row.cipher) : undefined,
    subnet: row.subnet ? String(row.subnet) : undefined,
  }));
}

export function countAttackEvents(): number {
  const row = db.prepare('SELECT COUNT(*) AS count FROM attack_events').get() as {
    count: number;
  };
  return Number(row?.count ?? 0);
}

export function pruneAttackEvents(retentionDays: number): number {
  const days = Math.max(1, Math.min(retentionDays, 3650));
  const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
  const result = db.prepare('DELETE FROM attack_events WHERE ts < ?').run(cutoff);
  return Number(result.changes ?? 0);
}

export function getConfig(key: string): string | null {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(key) as
    | { value: string }
    | undefined;
  return row?.value ?? null;
}

export function setConfig(key: string, value: string): void {
  db.prepare(
    'INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at',
  ).run(key, value, new Date().toISOString());
}

export function deleteConfig(key: string): void {
  db.prepare('DELETE FROM config WHERE key = ?').run(key);
}

export function getAllConfig(): Record<string, string> {
  const rows = db.prepare('SELECT key, value FROM config').all() as Array<{
    key: string;
    value: string;
  }>;
  return Object.fromEntries(rows.map((row) => [row.key, row.value]));
}

export interface SensorNodeRow {
  id: string;
  name: string;
  region?: string;
  url?: string;
  enabled: boolean;
  createdAt: string;
  lastSeenAt?: string;
  eventCount: number;
  status: string;
}

export function upsertSensorNode(node: {
  id: string;
  name: string;
  region?: string;
  url?: string;
  enabled?: boolean;
  status?: string;
}): void {
  db.prepare(
    `INSERT INTO sensor_nodes (id, name, region, url, enabled, created_at, status)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       name = excluded.name,
       region = excluded.region,
       url = excluded.url,
       enabled = excluded.enabled`,
  ).run(
    node.id,
    node.name,
    node.region ?? null,
    node.url ?? null,
    node.enabled === false ? 0 : 1,
    new Date().toISOString(),
    node.status ?? 'pending',
  );
}

export function ensureSensorNode(id: string): void {
  db.prepare(
    `INSERT OR IGNORE INTO sensor_nodes (id, name, enabled, created_at, status)
     VALUES (?, ?, 1, ?, 'pending')`,
  ).run(id, id, new Date().toISOString());
}

export function recordSensorHeartbeat(
  id: string,
  status: 'online' | 'offline',
  eventCount = 0,
): void {
  db.prepare(
    `UPDATE sensor_nodes
     SET last_seen_at = ?, status = ?, event_count = event_count + ?
     WHERE id = ?`,
  ).run(new Date().toISOString(), status, eventCount, id);
}

export function listSensorNodes(): SensorNodeRow[] {
  const rows = db.prepare('SELECT * FROM sensor_nodes ORDER BY created_at DESC').all() as Array<
    Record<string, unknown>
  >;
  return rows.map((row) => ({
    id: String(row.id),
    name: String(row.name),
    region: row.region ? String(row.region) : undefined,
    url: row.url ? String(row.url) : undefined,
    enabled: Number(row.enabled) === 1,
    createdAt: String(row.created_at),
    lastSeenAt: row.last_seen_at ? String(row.last_seen_at) : undefined,
    eventCount: Number(row.event_count ?? 0),
    status: String(row.status ?? 'pending'),
  }));
}

export function deleteSensorNode(id: string): boolean {
  const result = db.prepare('DELETE FROM sensor_nodes WHERE id = ?').run(id);
  return Number(result.changes ?? 0) > 0;
}

export interface DeliveryRow {
  id: string;
  ts: string;
  channel: string;
  target?: string;
  status: string;
  detail?: string;
  eventId?: string;
}

export function insertDelivery(delivery: DeliveryRow): void {
  db.prepare(
    'INSERT INTO alert_deliveries (id, ts, channel, target, status, detail, event_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(
    delivery.id,
    delivery.ts,
    delivery.channel,
    delivery.target ?? null,
    delivery.status,
    delivery.detail ?? null,
    delivery.eventId ?? null,
  );
}

export function listDeliveries(limit = 50): DeliveryRow[] {
  const rows = db
    .prepare('SELECT * FROM alert_deliveries ORDER BY ts DESC LIMIT ?')
    .all(Math.min(Math.max(limit, 1), 200)) as Array<Record<string, unknown>>;
  return rows.map((row) => ({
    id: String(row.id),
    ts: String(row.ts),
    channel: String(row.channel),
    target: row.target ? String(row.target) : undefined,
    status: String(row.status),
    detail: row.detail ? String(row.detail) : undefined,
    eventId: row.event_id ? String(row.event_id) : undefined,
  }));
}

export interface WafSyncRow {
  id: string;
  ts: string;
  provider: string;
  action: string;
  ip?: string;
  status: string;
  detail?: string;
}

export function insertWafSync(row: WafSyncRow): void {
  db.prepare(
    'INSERT INTO waf_sync_log (id, ts, provider, action, ip, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(row.id, row.ts, row.provider, row.action, row.ip ?? null, row.status, row.detail ?? null);
}

export function listWafSync(limit = 50): WafSyncRow[] {
  const rows = db
    .prepare('SELECT * FROM waf_sync_log ORDER BY ts DESC LIMIT ?')
    .all(Math.min(Math.max(limit, 1), 200)) as Array<Record<string, unknown>>;
  return rows.map((row) => ({
    id: String(row.id),
    ts: String(row.ts),
    provider: String(row.provider),
    action: String(row.action),
    ip: row.ip ? String(row.ip) : undefined,
    status: String(row.status),
    detail: row.detail ? String(row.detail) : undefined,
  }));
}

export function dbStats(): {
  path: string;
  sizeBytes: number;
  events: number;
  sensors: number;
  deliveries: number;
  wafSyncs: number;
} {
  let sizeBytes = 0;
  try {
    sizeBytes = fs.statSync(DB_PATH).size;
  } catch {
    sizeBytes = 0;
  }
  const count = (table: string) => {
    const row = db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number };
    return Number(row?.count ?? 0);
  };
  return {
    path: DB_PATH,
    sizeBytes,
    events: count('attack_events'),
    sensors: count('sensor_nodes'),
    deliveries: count('alert_deliveries'),
    wafSyncs: count('waf_sync_log'),
  };
}
