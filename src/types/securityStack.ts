export type SecurityToolId =
  | 'suricata'
  | 'zeek'
  | 'wazuh'
  | 'security-onion'
  | 'fail2ban'
  | 'cowrie'
  | 't-pot'
  | 'opencanary'
  | 'hfish'
  | 'conpot'
  | 'beelzebub';

export type SecurityToolCategory =
  | 'nids'
  | 'hids-siem'
  | 'log-response'
  | 'honeypot'
  | 'deception'
  | 'platform';

export type SecurityDeploymentMode = 'docker' | 'host' | 'appliance' | 'hybrid';

export interface SecurityToolDefinition {
  id: SecurityToolId;
  name: string;
  category: SecurityToolCategory;
  deployment: SecurityDeploymentMode;
  description: string;
  capabilities: string[];
  image?: string;
  composeService?: string;
  profiles: string[];
  defaultPorts: number[];
  configPath?: string;
  upstreamRepo: string;
  docsUrl: string;
  ingestFormats: string[];
  privileged: boolean;
  hostBinary?: string;
}

export type SecurityToolState =
  | 'running'
  | 'stopped'
  | 'unavailable'
  | 'error'
  | 'host-managed';

export interface SecurityToolStatus {
  id: SecurityToolId;
  name: string;
  category: SecurityToolCategory;
  deployment: SecurityDeploymentMode;
  state: SecurityToolState;
  detail: string;
  containerName?: string;
  image?: string;
  health?: string;
  ports: number[];
  lastCheckedAt: string;
  logTail?: string[];
}

export interface SecurityStackSummary {
  total: number;
  running: number;
  stopped: number;
  unavailable: number;
  hostManaged: number;
  honeypots: number;
  detectors: number;
  ingestedEvents: number;
  blockedByStack: number;
}

export interface SecurityStackSnapshot {
  generatedAt: string;
  docker: {
    available: boolean;
    cliInstalled?: boolean;
    daemonReachable?: boolean;
    composeAvailable?: boolean;
    cliPath?: string;
    remoteHost?: string | null;
    serverlessSandbox?: boolean;
    nativeFallbackActive?: boolean;
    version?: string;
    detail: string;
    hint?: string;
  };
  tools: SecurityToolStatus[];
  summary: SecurityStackSummary;
  ingest: {
    tokenConfigured: boolean;
    endpoints: Array<{ source: SecurityToolId; path: string; formats: string[] }>;
  };
}

export interface GeneratedSecurityFile {
  path: string;
  content: string;
}

export interface SecurityToolConfigBundle {
  toolId: SecurityToolId;
  generatedAt: string;
  files: GeneratedSecurityFile[];
  deployCommands: string[];
  notes: string[];
}

export interface StackIngestResult {
  source: SecurityToolId;
  accepted: number;
  blocked: number;
  skipped: number;
  events: Array<{
    id: string;
    ip: string;
    severity: string;
    category: string;
    detail: string;
    action: string;
  }>;
  errors: string[];
}
