import type { AttackCategory } from '../../src/types/defenseGrid.ts';
import type { ThreatSeverity } from '../../src/types/cyber.ts';
import type { SecurityToolId } from '../../src/types/securityStack.ts';
import { classifyAttack } from '../attackSensor.ts';
import { isValidIpv4 } from '../threatRules.ts';

export interface NormalizedStackEvent {
  source: SecurityToolId;
  ts: string;
  ip: string;
  category: AttackCategory;
  severity: ThreatSeverity;
  detail: string;
  method: string;
  path: string;
  host?: string;
  userAgent?: string;
  raw?: Record<string, unknown>;
}

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Json)
    : null;
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function num(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return undefined;
}

function toIso(value: unknown, fallback = Date.now()): string {
  if (typeof value === 'string' && value.trim()) {
    const numeric = Number(value);
    const date = Number.isFinite(numeric)
      ? new Date(numeric > 10_000_000_000 ? numeric : numeric * 1000)
      : new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value > 10_000_000_000 ? value : value * 1000);
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  return new Date(fallback).toISOString();
}

function ipFrom(...values: unknown[]): string {
  for (const value of values) {
    const candidate = str(value).trim();
    if (isValidIpv4(candidate)) return candidate;
  }
  return '';
}

function severityFromScore(score: number): ThreatSeverity {
  if (score >= 12) return 'CRITICAL';
  if (score >= 8) return 'HIGH';
  if (score >= 4) return 'ELEVATED';
  return 'CLEAN';
}

function categoryFromText(text: string): AttackCategory {
  const lower = text.toLowerCase();
  if (/sql|sqli|injection/.test(lower)) return 'sqli';
  if (/xss|cross.site/.test(lower)) return 'xss';
  if (/traversal|lfi|rfi|\.\.\//.test(lower)) return 'path-traversal';
  if (/\brce\b|command|shell|exec|powershell|wget|curl/.test(lower)) return 'rce';
  if (/brute|password|login|auth|credential|ssh/.test(lower)) return 'bruteforce';
  if (/scan|nmap|nikto|masscan|recon/.test(lower)) return 'scanner';
  if (/ddos|flood|dos|syn/.test(lower)) return 'ddos';
  if (/c2|botnet|malware|beacon|mining/.test(lower)) return 'botnet-c2';
  if (/phish|credential.harvest/.test(lower)) return 'phishing';
  if (/honeypot|canary|decoy|trap/.test(lower)) return 'honeypot';
  return 'other';
}

function baseEvent(
  source: SecurityToolId,
  input: {
    ip: string;
    category: AttackCategory;
    severity: ThreatSeverity;
    detail: string;
    ts?: unknown;
    method?: string;
    path?: string;
    host?: string;
    userAgent?: string;
    raw?: Json;
  },
): NormalizedStackEvent {
  return {
    source,
    ts: toIso(input.ts),
    ip: input.ip || 'unknown',
    category: input.category,
    severity: input.severity,
    detail: input.detail.slice(0, 600),
    method: (input.method || 'LOG').toUpperCase().slice(0, 16),
    path: (input.path || '').slice(0, 500),
    host: input.host?.slice(0, 255),
    userAgent: input.userAgent?.slice(0, 300),
    raw: input.raw,
  };
}

export function parseSuricataEve(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const eventType = str(record.event_type).toLowerCase();
  const alert = asRecord(record.alert);
  if (!alert && !['alert', 'anomaly', 'drop'].includes(eventType)) return [];
  const signature = str(alert?.signature) || str(record.event_type) || 'Suricata alert';
  const sev = num(alert?.severity) ?? 3;
  const severity: ThreatSeverity =
    sev <= 1 ? 'CRITICAL' : sev === 2 ? 'HIGH' : sev === 3 ? 'ELEVATED' : 'CLEAN';
  const http = asRecord(record.http);
  const dns = asRecord(record.dns);
  const tls = asRecord(record.tls);
  const ip = ipFrom(record.src_ip, record.dest_ip);
  return [
    baseEvent('suricata', {
      ip,
      category: categoryFromText(`${signature} ${str(alert?.category)}`),
      severity,
      detail: `${signature}${alert?.category ? ` (${str(alert.category)})` : ''}`,
      ts: record.timestamp,
      method: str(http?.http_method) || str(record.proto) || 'NET',
      path: str(http?.url) || str(dns?.rrname) || str(tls?.sni) || '',
      host: str(http?.hostname) || str(tls?.sni) || str(dns?.rrname),
      userAgent: str(http?.http_user_agent),
      raw: record,
    }),
  ];
}

export function parseZeekLog(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const path = str(record._path).toLowerCase();
  const notice = str(record.note);
  const msg = str(record.msg);
  const id = asRecord(record.id);
  const ip = ipFrom(id?.orig_h, record['id.orig_h'], record.orig_h, record.src_ip);
  if (!ip) return [];
  if (path === 'notice' || path === 'weird' || notice) {
    const text = `${notice} ${msg} ${str(record.sub)}`;
    const score = /critical|attack|malicious|exploit/i.test(text) ? 12 : /scan|brute|probe/i.test(text) ? 8 : 5;
    return [
      baseEvent('zeek', {
        ip,
        category: categoryFromText(text),
        severity: severityFromScore(score),
        detail: text.trim() || 'Zeek notice',
        ts: record.ts,
        method: str(record.proto) || 'NET',
        path: str(record.uri) || str(record.query) || '',
        host: str(record.host),
        userAgent: str(record.user_agent),
        raw: record,
      }),
    ];
  }
  if (path === 'http') {
    const classification = classifyAttack({
      path: str(record.uri),
      query: str(record.query),
      userAgent: str(record.user_agent),
      method: str(record.method),
    });
    if (classification.severity === 'CLEAN' && classification.category === 'other') return [];
    return [
      baseEvent('zeek', {
        ip,
        category: classification.category,
        severity: classification.severity,
        detail: classification.detail || 'Suspicious Zeek HTTP request',
        ts: record.ts,
        method: str(record.method) || 'GET',
        path: str(record.uri),
        host: str(record.host),
        userAgent: str(record.user_agent),
        raw: record,
      }),
    ];
  }
  return [];
}

export function parseWazuhAlert(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const rule = asRecord(record.rule);
  const agent = asRecord(record.agent);
  const data = asRecord(record.data);
  const mitre = asRecord(rule?.mitre);
  const level = num(rule?.level) ?? 0;
  if (level < 3) return [];
  const description = str(rule?.description) || 'Wazuh alert';
  const ip = ipFrom(data?.srcip, data?.src_ip, agent?.ip, record.src_ip);
  const groups = Array.isArray(rule?.groups) ? rule.groups.map(str).join(' ') : '';
  const text = `${description} ${groups} ${str(record.full_log)}`;
  return [
    baseEvent('wazuh', {
      ip,
      category: categoryFromText(text),
      severity: severityFromScore(level),
      detail: `${description}${mitre?.id ? ` · MITRE ${Array.isArray(mitre.id) ? mitre.id.join(',') : str(mitre.id)}` : ''}`,
      ts: record.timestamp,
      method: str(data?.method) || 'LOG',
      path: str(data?.url) || str(data?.path) || '',
      host: str(agent?.name),
      userAgent: str(data?.['http_user_agent']),
      raw: record,
    }),
  ];
}

export function parseCowrieEvent(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const eventid = str(record.eventid);
  if (!eventid) return [];
  const ip = ipFrom(record.src_ip);
  const session = str(record.session);
  const username = str(record.username);
  const password = str(record.password);
  const command = str(record.input) || str(record.command);
  const filename = str(record.filename);
  let category: AttackCategory = 'honeypot';
  let severity: ThreatSeverity = 'ELEVATED';
  let detail = eventid;
  if (eventid === 'cowrie.login.failed') {
    category = 'bruteforce';
    severity = 'HIGH';
    detail = `Cowrie SSH/Telnet login failed for ${username || 'unknown'}:${password ? '***' : ''}`;
  } else if (eventid === 'cowrie.login.success') {
    category = 'credential-stuffing';
    severity = 'CRITICAL';
    detail = `Cowrie accepted decoy credentials for ${username || 'unknown'}`;
  } else if (eventid === 'cowrie.command.input') {
    category = 'rce';
    severity = 'CRITICAL';
    detail = `Cowrie shell command: ${command}`;
  } else if (eventid === 'cowrie.session.file_download' || eventid === 'cowrie.session.file_upload') {
    category = 'botnet-c2';
    severity = 'CRITICAL';
    detail = `Cowrie file transfer: ${filename || command}`;
  } else if (eventid === 'cowrie.session.connect') {
    category = 'honeypot';
    severity = 'ELEVATED';
    detail = 'Cowrie SSH/Telnet session opened';
  } else if (eventid.startsWith('cowrie.direct-tcpip')) {
    category = 'botnet-c2';
    severity = 'HIGH';
    detail = `Cowrie proxy attempt: ${str(record.dst_ip)}:${str(record.dst_port)}`;
  }
  return [
    baseEvent('cowrie', {
      ip,
      category,
      severity,
      detail: session ? `${detail} [session ${session}]` : detail,
      ts: record.timestamp,
      method: 'SSH',
      path: command || filename || eventid,
      host: 'cowrie',
      raw: record,
    }),
  ];
}

export function parseOpenCanaryEvent(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const logtype = num(record.logtype);
  const logdata = asRecord(record.logdata);
  const ip = ipFrom(record.src_host, record.src_ip, logdata?.src_ip);
  if (!ip) return [];
  const detail = `${str(record.logtype)}${logdata?.USERNAME ? ` user=${str(logdata.USERNAME)}` : ''}${logdata?.PASSWORD ? ' password=***' : ''}`;
  return [
    baseEvent('opencanary', {
      ip,
      category: logtype === 2000 || logtype === 3000 ? 'bruteforce' : 'honeypot',
      severity: 'HIGH',
      detail: detail || 'OpenCanary decoy access',
      ts: record.utc_time || record.timestamp,
      method: str(logdata?.METHOD) || 'TCP',
      path: str(logdata?.PATH) || str(logdata?.URL) || '',
      host: str(record.dst_host),
      userAgent: str(logdata?.USERAGENT) || str(logdata?.USER_AGENT),
      raw: record,
    }),
  ];
}

export function parseFail2BanEvent(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (record) {
    const ip = ipFrom(record.ip, record.src_ip, record.host);
    if (!ip) return [];
    const jail = str(record.jail) || 'fail2ban';
    const action = str(record.action) || 'ban';
    return [
      baseEvent('fail2ban', {
        ip,
        category: /ssh/i.test(jail) ? 'bruteforce' : categoryFromText(jail),
        severity: action.toLowerCase().includes('ban') ? 'HIGH' : 'ELEVATED',
        detail: `Fail2Ban ${action} in jail ${jail}${record.reason ? `: ${str(record.reason)}` : ''}`,
        ts: record.timestamp || record.ts,
        method: 'LOG',
        path: jail,
        raw: record,
      }),
    ];
  }
  const text = typeof payload === 'string' ? payload : '';
  const match = text.match(/\b(?:Ban|Found|Block)\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
  if (!match) return [];
  return [
    baseEvent('fail2ban', {
      ip: match[1],
      category: /ssh/i.test(text) ? 'bruteforce' : categoryFromText(text),
      severity: 'HIGH',
      detail: text.slice(0, 300),
      method: 'LOG',
      path: 'fail2ban',
      raw: { line: text },
    }),
  ];
}

export function parseConpotEvent(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const data = asRecord(record.data) ?? record;
  const ip = ipFrom(record.remote, record.src_ip, data.remote, data.src_ip);
  if (!ip) return [];
  return [
    baseEvent('conpot', {
      ip,
      category: 'honeypot',
      severity: 'HIGH',
      detail: `Conpot ICS/SCADA interaction: ${str(record.data_type) || str(data.data_type) || 'protocol event'}`,
      ts: record.timestamp || record.ts,
      method: str(record.protocol) || 'OT',
      path: str(record.request) || str(data.request) || '',
      host: 'conpot',
      raw: record,
    }),
  ];
}

export function parseBeelzebubEvent(payload: unknown): NormalizedStackEvent[] {
  const wrapper = asRecord(payload);
  if (!wrapper) return [];
  const record = asRecord(wrapper.event) ?? asRecord(wrapper.data) ?? wrapper;
  const ip = ipFrom(record.SourceIp, record.source_ip, record.src_ip, record.ip);
  if (!ip) return [];
  const command =
    str(record.Command) || str(record.command) || str(record.input) || str(record.request);
  const protocol = str(record.Protocol) || str(record.protocol) || 'TCP';
  const path = str(record.RequestURI) || str(record.path) || '';
  return [
    baseEvent('beelzebub', {
      ip,
      category: command ? 'rce' : 'honeypot',
      severity: command ? 'CRITICAL' : 'HIGH',
      detail: `Beelzebub ${protocol} event${path ? `: ${path}` : ''}${command ? `: ${command}` : ''}`,
      ts: record.DateTime || record.timestamp || record.ts || wrapper.time,
      method: str(record.HTTPMethod) || protocol,
      path,
      host: str(record.HostHTTPRequest) || str(record.host) || 'beelzebub',
      userAgent: str(record.UserAgent) || str(record.user_agent),
      raw: wrapper,
    }),
  ];
}

export function parseHfishEvent(payload: unknown): NormalizedStackEvent[] {
  const record = asRecord(payload);
  if (!record) return [];
  const data = asRecord(record.data) ?? record;
  const ip = ipFrom(data.src_ip, data.ip, record.src_ip, record.ip);
  if (!ip) return [];
  const text = `${str(data.type)} ${str(data.event)} ${str(record.message)}`;
  return [
    baseEvent('hfish', {
      ip,
      category: categoryFromText(text) || 'honeypot',
      severity: /critical|high/i.test(text) ? 'CRITICAL' : 'HIGH',
      detail: text.trim() || 'HFish honeypot event',
      ts: record.timestamp || record.ts,
      method: str(data.protocol) || 'TCP',
      path: str(data.url) || str(data.path) || '',
      host: str(data.host),
      raw: record,
    }),
  ];
}

const PARSERS: Record<SecurityToolId, (payload: unknown) => NormalizedStackEvent[]> = {
  suricata: parseSuricataEve,
  zeek: parseZeekLog,
  wazuh: parseWazuhAlert,
  'security-onion': (payload) => {
    const record = asRecord(payload);
    if (!record) return [];
    if (record.alert || record.event_type) return parseSuricataEve(record);
    if (record._path || record.uid) return parseZeekLog(record);
    return parseWazuhAlert(record);
  },
  fail2ban: parseFail2BanEvent,
  cowrie: parseCowrieEvent,
  't-pot': (payload) => {
    const record = asRecord(payload);
    if (!record) return [];
    if (record.eventid) return parseCowrieEvent(record);
    if (record.alert || record.event_type) return parseSuricataEve(record);
    return parseHfishEvent(record);
  },
  opencanary: parseOpenCanaryEvent,
  hfish: parseHfishEvent,
  conpot: parseConpotEvent,
  beelzebub: parseBeelzebubEvent,
};

export function parseSecurityStackPayload(
  source: SecurityToolId,
  payload: unknown,
): NormalizedStackEvent[] {
  const parser = PARSERS[source];
  if (!parser) return [];
  if (Array.isArray(payload)) return payload.flatMap((item) => parser(item));
  const record = asRecord(payload);
  if (record && Array.isArray(record.events)) {
    return record.events.flatMap((item) => parser(item));
  }
  if (record && Array.isArray(record.alerts)) {
    return record.alerts.flatMap((item) => parser(item));
  }
  return parser(payload);
}

export function parseNdjsonLines(
  source: SecurityToolId,
  text: string,
): { events: NormalizedStackEvent[]; errors: string[] } {
  const events: NormalizedStackEvent[] = [];
  const errors: string[] = [];
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      events.push(...parseSecurityStackPayload(source, JSON.parse(trimmed)));
    } catch (error) {
      if (errors.length < 10) {
        errors.push(`line ${index + 1}: ${error instanceof Error ? error.message : 'invalid JSON'}`);
      }
    }
  }
  return { events, errors };
}
