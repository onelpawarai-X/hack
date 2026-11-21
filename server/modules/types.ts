import { resolve4, resolve6, resolveCaa, resolveMx, resolveNs, resolvePtr, resolveTxt } from 'node:dns/promises';
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

export async function resolveDnsRecord(
  name: string,
  type: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | 'PTR' | 'CAA',
): Promise<string[]> {
  try {
    if (type === 'A') return await resolve4(name);
    if (type === 'AAAA') return await resolve6(name);
    if (type === 'MX') {
      return (await resolveMx(name)).map((record) => `${record.priority} ${record.exchange}`);
    }
    if (type === 'NS') return await resolveNs(name);
    if (type === 'TXT') {
      return (await resolveTxt(name)).map((parts) => parts.join(''));
    }
    if (type === 'PTR') return await resolvePtr(name);
    if (type === 'CAA') {
      return (await resolveCaa(name)).map((record) =>
        [record.critical ? 'critical' : '', record.issue, record.iodef, record.contactemail, record.contactphone]
          .filter(Boolean)
          .join(' '),
      );
    }
    return [];
  } catch {
    return [];
  }
}
