import type { ScanModuleId, TargetScanResult, ThreatSeverity } from './cyber.ts';
import type { AttackEvent } from './defenseGrid.ts';

export type ScanLogLevel = 'info' | 'success' | 'warn' | 'error' | 'debug';

export interface ScanLogEvent {
  id: string;
  ts: string;
  level: ScanLogLevel;
  moduleId?: ScanModuleId | 'init' | 'finalize' | 'socket';
  message: string;
}

export interface ScanProgressPayload {
  type: 'progress';
  moduleId: ScanModuleId | 'init' | 'finalize';
  label: string;
  percent: number;
  completedModules: ScanModuleId[];
}

export interface ScanGeoPoint {
  ip: string;
  label: string;
  lat: number;
  lon: number;
  severity: ThreatSeverity;
  role: 'target' | 'resolved' | 'scanner';
  city?: string;
  country?: string;
}

export interface ScanGeoPayload {
  target: string;
  points: ScanGeoPoint[];
  scanner?: {
    ip: string;
    lat: number;
    lon: number;
    city?: string;
    country?: string;
  } | null;
}

export interface ScanStartPayload {
  target: string;
  modules?: ScanModuleId[];
}

export interface ScanResultPayload {
  target: string;
  report: TargetScanResult;
  geo: ScanGeoPayload;
}

export interface ScanErrorPayload {
  target: string;
  error: string;
}

export interface ScannerOrigin {
  ip: string;
  lat: number;
  lon: number;
  city?: string;
  country?: string;
  asn?: string;
  isp?: string;
  resolvedAt: string;
}

export interface ScanSocketAck {
  ok: boolean;
  error?: string;
}

export interface DefenseAlertPayload {
  event: AttackEvent;
  blocked: boolean;
  firewallRules: {
    nginx: string;
    iptables: string;
    ufw: string;
    cloudflare: string;
  };
}

export interface TerminalOutputPayload {
  stream: 'stdout' | 'stderr' | 'system';
  data: string;
}

export interface TerminalExitPayload {
  code: number | null;
  cwd: string;
}

export interface TerminalExecAck {
  ok: boolean;
  cwd?: string;
  error?: string;
}

export interface ServerToClientEvents {
  'server:ready': (payload: { at: string; scannerOrigin: ScannerOrigin | null }) => void;
  'scan:log': (event: ScanLogEvent) => void;
  'scan:progress': (payload: ScanProgressPayload) => void;
  'scan:geo': (payload: ScanGeoPayload) => void;
  'scan:result': (payload: ScanResultPayload) => void;
  'scan:error': (payload: ScanErrorPayload) => void;
  'attack:event': (event: AttackEvent) => void;
  'defense:alert': (payload: DefenseAlertPayload) => void;
  'terminal:output': (payload: TerminalOutputPayload) => void;
  'terminal:exit': (payload: TerminalExitPayload) => void;
}

export interface ClientToServerEvents {
  'scan:start': (payload: ScanStartPayload, ack?: (res: ScanSocketAck) => void) => void;
  'scanner:origin': (ack?: (origin: ScannerOrigin | null) => void) => void;
  'terminal:exec': (
    payload: { command: string },
    ack?: (res: TerminalExecAck) => void,
  ) => void;
}
