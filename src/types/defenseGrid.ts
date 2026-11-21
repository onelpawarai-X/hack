import type { ProtectedSystemShield, ThreatSeverity } from './cyber.ts';

export type AttackCategory =
  | 'sqli'
  | 'xss'
  | 'path-traversal'
  | 'rce'
  | 'credential-stuffing'
  | 'scanner'
  | 'ddos'
  | 'bruteforce'
  | 'honeypot'
  | 'botnet-c2'
  | 'phishing'
  | 'other';

export type AttackAction = 'observed' | 'blocked' | 'tarpitted' | 'reported';

export interface AttackEvent {
  id: string;
  ts: string;
  ip: string;
  method: string;
  path: string;
  host?: string;
  userAgent?: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  detail: string;
  action: AttackAction;
  source: 'sensor' | 'feed';
  country?: string;
  city?: string;
  asn?: string;
  isp?: string;
  abuseEmails?: string[];
  requestCount?: number;
}

export interface DefenseGridStats {
  totalEvents: number;
  blocked: number;
  tarpitted: number;
  uniqueAttackers: number;
  eventsLastMinute: number;
  sensorRequests: number;
  autoDefenseEnabled: boolean;
  safeIps: string[];
}

export interface DefenseGridAttacker {
  ip: string;
  count: number;
  category: AttackCategory;
  severity: ThreatSeverity;
  country?: string;
  city?: string;
  blocked: boolean;
}

export interface DefenseGridSnapshot {
  events: AttackEvent[];
  stats: DefenseGridStats;
  topAttackers: DefenseGridAttacker[];
  categoryCounts: Array<{ category: AttackCategory; count: number }>;
  protectedSites: ProtectedSystemShield[];
  generatedAt: string;
}
