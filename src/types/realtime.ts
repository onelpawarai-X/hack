import type { ScanModuleId, TargetScanResult, ThreatSeverity } from './cyber.ts';

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

export interface ServerToClientEvents {
  'server:ready': (payload: { at: string; scannerOrigin: ScannerOrigin | null }) => void;
  'scan:log': (event: ScanLogEvent) => void;
  'scan:progress': (payload: ScanProgressPayload) => void;
  'scan:geo': (payload: ScanGeoPayload) => void;
  'scan:result': (payload: ScanResultPayload) => void;
  'scan:error': (payload: ScanErrorPayload) => void;
}

export interface ClientToServerEvents {
  'scan:start': (payload: ScanStartPayload, ack?: (res: ScanSocketAck) => void) => void;
  'scanner:origin': (ack?: (origin: ScannerOrigin | null) => void) => void;
}
