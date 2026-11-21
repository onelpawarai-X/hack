import type { ThreatSeverity } from './cyber.ts';

export interface SensorNodeView {
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
}

export interface SensorOverview {
  nodes: SensorNodeView[];
  ingestUrl: string;
  tokenPreview: string;
  autoBlock: boolean;
}

export interface WafProvider {
  id: 'local';
  name: string;
  configured: boolean;
  detail: string;
  env: string[];
}

export interface WafActionResult {
  provider: WafProvider['id'];
  ok: boolean;
  detail: string;
}

export interface WafSyncEntry {
  id: string;
  ts: string;
  provider: string;
  action: string;
  ip?: string;
  status: string;
  detail?: string;
}

export type AlertChannel = 'slack' | 'telegram' | 'siem';

export interface IntegrationStatus {
  channel: AlertChannel;
  name: string;
  configured: boolean;
  source: 'database' | 'environment' | 'none';
  target?: string;
  detail: string;
}

export interface IntegrationSnapshot {
  integrations: IntegrationStatus[];
  minSeverity: ThreatSeverity;
  notifyOnBlock: boolean;
}

export interface DeliveryEntry {
  id: string;
  ts: string;
  channel: string;
  target?: string;
  status: string;
  detail?: string;
  eventId?: string;
}

export interface DbStats {
  path: string;
  sizeBytes: number;
  events: number;
  sensors: number;
  deliveries: number;
  wafSyncs: number;
  totalEvents?: number;
}

export interface SystemInfo {
  uptimeSeconds: number;
  node: string;
  pid: number;
  memory: {
    rss: number;
    heapTotal: number;
    heapUsed: number;
    external: number;
    arrayBuffers: number;
  };
  auth: {
    authenticated: boolean;
    user: { id: string; username: string; role: string } | null;
    hasAdmin: boolean;
    setupRequired: boolean;
    ssoEnabled: boolean;
  };
  db: DbStats;
  waf: WafProvider[];
  integrations: {
    integrations: IntegrationStatus[];
    minSeverity: ThreatSeverity;
    notifyOnBlock: boolean;
  };
  sensors: SensorOverview;
  tlsSensor?: {
    enabled: boolean;
    listening: boolean;
    host: string;
    port: number;
    connections: number;
    fingerprints: number;
    lastAt?: string;
    lastError?: string;
  };
}

export interface DetectionConfig {
  windowSeconds: number;
  ipRateLimit: number;
  subnetRateLimit: number;
  asnRateLimit: number;
  autoBlockAfter: number;
  tarpitMs: number;
  autoDefenseEnabled: boolean;
  safeIps: string[];
  ja3Headers: string[];
  ja4Headers: string[];
  tlshEnabled: boolean;
}

export interface ControlCenterData {
  sensors: SensorOverview | null;
  wafProviders: WafProvider[];
  wafAutoPush: boolean;
  wafLog: WafSyncEntry[];
  integrations: IntegrationSnapshot | null;
  deliveries: DeliveryEntry[];
  dbStats: DbStats | null;
  system: SystemInfo | null;
  detection: DetectionConfig | null;
}
