import type {
  ActiveVulnFinding,
  BgpRouteProfile,
  CveDetailRecord,
  CyberIncident,
  PortScanReport,
  RdapDomainProfile,
  ScanModuleId,
  SensitivePathFinding,
  TargetScanResult,
  TechFingerprint,
  ThreatNode,
  WafDetectionResult,
  WaybackArchiveProfile,
} from '../../src/types/cyber.ts';
import type { ScanLogLevel } from '../../src/types/realtime.ts';

export const PASSIVE_SCAN_MODULES: ScanModuleId[] = [
  'threatIntel',
  'dns',
  'tls',
  'headers',
  'portsBgp',
  'osintMeta',
  'waf',
];

export const ACTIVE_SCAN_MODULES: ScanModuleId[] = [
  'portScan',
  'sensitiveFiles',
  'activeVulns',
];

export const ALL_SCAN_MODULES: ScanModuleId[] = [
  ...PASSIVE_SCAN_MODULES,
  ...ACTIVE_SCAN_MODULES,
];

export interface ScanExecutionContext {
  query: string;
  normalizedTarget: string;
  targetType: TargetScanResult['targetType'];
  host: string;
  probeUrl: string;
  rootDomain: string;
  ownershipVerified: boolean;
  // Shared intermediate results populated by modules
  feedMatches: Array<{ feed: string; detail: string }>;
  heuristicWarnings: string[];
  dns: TargetScanResult['dns'];
  tls: TargetScanResult['tls'];
  httpAudit: TargetScanResult['httpAudit'];
  rawHttpHeaders: Record<string, string>;
  rawSetCookies: string[];
  htmlSample: string;
  attribution: ThreatNode[];
  bgpProfile: BgpRouteProfile | null;
  cveDetails: CveDetailRecord[];
  discoveredSubdomains: string[];
  rdapProfile: RdapDomainProfile | null;
  waybackProfile: WaybackArchiveProfile | null;
  webBreachSignals: CyberIncident[];
  waf: WafDetectionResult | null;
  portScan: PortScanReport | null;
  techStack: TechFingerprint[];
  sensitivePaths: SensitivePathFinding[];
  activeVulns: ActiveVulnFinding[];
  log: (
    message: string,
    level?: ScanLogLevel,
    moduleId?: ScanModuleId | 'init' | 'finalize',
  ) => void;
}

export interface ScanModulePlugin {
  id: ScanModuleId;
  label: string;
  isActive: boolean;
  supportsTargetType: (targetType: TargetScanResult['targetType']) => boolean;
  run: (ctx: ScanExecutionContext) => Promise<void>;
}

export async function fetchJsonWithTimeout<T>(url: string, timeoutMs = 5500): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        Accept: 'application/json, application/rdap+json, */*',
        'User-Agent': 'SentinelGlobe-OSINT/1.0',
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function resolveDnsRecord(
  name: string,
  type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'PTR' | 'CAA',
): Promise<string[]> {
  const json = await fetchJsonWithTimeout<{ Answer?: Array<{ data?: string }> }>(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
    5000,
  );
  if (!json || !Array.isArray(json.Answer)) return [];
  return json.Answer.map((a) =>
    String(a.data ?? '')
      .replace(/^"|"$/g, '')
      .replace(/\.$/, '')
      .trim(),
  ).filter(Boolean);
}
