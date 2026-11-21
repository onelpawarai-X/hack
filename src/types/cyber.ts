export type Language = 'bn' | 'en';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'CLEAN';

export interface ThreatNode {
  id: string;
  ip: string;
  port?: number;
  threatType: string;
  malware?: string;
  sourceFeed:
    | 'Feodo C2'
    | 'Blocklist.de'
    | 'CINS Army'
    | 'Live Attribution'
    | 'Photo GPS'
    | 'Image Embedded IP';
  severity: ThreatSeverity;
  country: string;
  countryCode: string;
  city: string;
  region?: string;
  postal?: string;
  physicalAddress?: string;
  timezone?: string;
  lat: number;
  lon: number;
  asn: string;
  isp: string;
  org: string;
  reverse?: string;
  isProxy?: boolean;
  isHosting?: boolean;
  isTorExit?: boolean;
  openPorts?: number[];
  knownVulns?: string[];
  cpes?: string[];
  shodanTags?: string[];
  abuseEmails?: string[];
  cidr?: string;
  defended?: boolean;
  firstSeen?: string;
  lastSeen?: string;
}

export interface PhishingTrap {
  id: string;
  url: string;
  host: string;
  sourceFeed: 'OpenPhish';
  severity: 'CRITICAL' | 'HIGH';
  riskReasons: string[];
  detectedAt: string;
}

export interface ExploitedCve {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomware: boolean;
  shortDescription: string;
}

export interface CyberIncident {
  id: string;
  title: string;
  summary: string;
  source: string;
  url: string;
  publishedAt: string;
  severity: 'CRITICAL' | 'HIGH' | 'ELEVATED';
  extractedTargets: string[];
}

export interface FeedHealthItem {
  name: string;
  status: 'online' | 'degraded';
  recordCount: number;
}

export interface RadarSnapshot {
  scannedAt: string;
  nextScanAt: string;
  scanCycleCount: number;
  feedHealth: FeedHealthItem[];
  summary: {
    activeAttackers: number;
    c2Botnets: number;
    phishingTraps: number;
    exploitedCves: number;
    globalIncidents: number;
    torExitNodes: number;
  };
  threatNodes: ThreatNode[];
  phishingTraps: PhishingTrap[];
  cves: ExploitedCve[];
  incidents: CyberIncident[];
  webScanHighlights: CyberIncident[];
}

export interface HardeningRecommendation {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  remediation: string;
}

export interface CveDetailRecord {
  cveId: string;
  title: string;
  description: string;
  cvssScore?: number;
  cvssSeverity?: string;
  cvssVector?: string;
  cwes: string[];
  affectedProducts: string[];
  publishedDate?: string;
  references: string[];
}

export interface RdapDomainProfile {
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastChangedDate?: string;
  dnssecSigned?: boolean;
  statuses: string[];
  abuseEmails: string[];
}

export interface BgpRouteProfile {
  prefix: string;
  announced: boolean;
  asns: Array<{ asn: number; holder: string }>;
  rirBlock?: string;
}

export interface WaybackArchiveProfile {
  firstSnapshot?: string;
  latestSnapshot?: string;
  archiveUrl: string;
}

export type ScanModuleId =
  | 'threatIntel'
  | 'dns'
  | 'tls'
  | 'headers'
  | 'portsBgp'
  | 'osintMeta'
  | 'waf'
  | 'sensitiveFiles'
  | 'activeVulns';

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type OwaspCategory =
  | 'A01:2021 - Broken Access Control'
  | 'A02:2021 - Cryptographic Failures'
  | 'A03:2021 - Injection'
  | 'A05:2021 - Security Misconfiguration'
  | 'A06:2021 - Vulnerable and Outdated Components'
  | 'A07:2021 - Identification and Authentication Failures'
  | 'A08:2021 - Software and Data Integrity Failures';

export interface RemediationSnippets {
  nginx?: string;
  apache?: string;
  cloudflare?: string;
}

export interface SecurityFinding {
  id: string;
  moduleId: ScanModuleId;
  title: string;
  description: string;
  riskLevel: RiskLevel;
  owaspCategory: OwaspCategory;
  owaspId: string;
  cwe?: string;
  evidence?: string;
  remediation: string;
  snippets?: RemediationSnippets;
}

export interface WafDetectionResult {
  detected: boolean;
  provider?: string;
  confidence: 'High' | 'Medium' | 'None';
  signals: string[];
}

export interface SensitivePathFinding {
  path: string;
  status: number;
  riskLevel: RiskLevel;
  exposed: boolean;
  detail: string;
}

export interface ActiveVulnFinding {
  id: string;
  category: 'Reflected XSS' | 'SQL Injection Indicator' | 'Missing CSRF Protection';
  riskLevel: RiskLevel;
  endpoint: string;
  parameter?: string;
  evidence: string;
  owaspCategory: OwaspCategory;
  remediation: string;
}

export interface DomainVerificationStatus {
  domain: string;
  verified: boolean;
  method?: 'dns-txt' | 'http-file';
  verifiedAt?: string;
  token: string;
  txtRecordHost: string;
  txtRecordValue: string;
  httpFilePath: string;
  httpFileContent: string;
  expiresAt: string;
  error?: string;
}

export interface ScanProgressEvent {
  type: 'progress';
  moduleId: ScanModuleId | 'init' | 'finalize';
  label: string;
  percent: number;
  completedModules: ScanModuleId[];
}

export interface TargetScanResult {
  query: string;
  normalizedTarget: string;
  targetType: 'url' | 'domain' | 'ip' | 'cve' | 'search';
  scannedAt: string;
  legalDisclaimer?: string;
  verdict: ThreatSeverity;
  verdictReasons: string[];
  feedMatches: Array<{ feed: string; detail: string }>;
  dns: {
    a: string[];
    aaaa: string[];
    mx: string[];
    ns: string[];
    txt: string[];
    caa: string[];
    spfRecord?: string | null;
    dmarcRecord?: string | null;
    emailSecurityStatus: 'protected' | 'weak' | 'missing';
  };
  attribution: ThreatNode[];
  tls: {
    valid: boolean;
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    protocol?: string;
    cipher?: string;
    sanCount?: number;
    error?: string;
  } | null;
  httpAudit: {
    status?: number;
    finalUrl?: string;
    server?: string;
    headers: Record<string, string>;
    missingSecurityHeaders: string[];
    cookieIssues: string[];
    securityTxtFound: boolean;
    robotsTxtFound?: boolean;
    error?: string;
  } | null;
  discoveredSubdomains?: string[];
  rdapProfile?: RdapDomainProfile | null;
  bgpProfile?: BgpRouteProfile | null;
  waybackProfile?: WaybackArchiveProfile | null;
  cveDetails?: CveDetailRecord[];
  hardeningRecommendations: HardeningRecommendation[];
  webBreachSignals: CyberIncident[];
  selectedModules?: ScanModuleId[];
  executedModules?: ScanModuleId[];
  skippedActiveModules?: Array<{ moduleId: ScanModuleId; reason: string }>;
  ownershipVerified?: boolean;
  waf?: WafDetectionResult | null;
  sensitivePaths?: SensitivePathFinding[];
  activeVulns?: ActiveVulnFinding[];
  findings?: SecurityFinding[];
  riskCounts?: Record<RiskLevel, number>;
}

export interface ImageForensicsResult {
  filename: string;
  declaredMimeType: string;
  detectedFormat: string;
  mimeMismatch: boolean;
  fileSizeBytes: number;
  hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  entropyBitsPerByte: number;
  appendedTrailingBytes: number;
  trailingPayloadPreview?: string;
  polyglotWarnings: string[];
  containerAnalysis: {
    pipelineClass: string;
    recompressionSignals: string[];
    markersOrChunks: string[];
    zlibExtractedCount: number;
  };
  embeddedThumbnailDataUrl?: string;
  dimensions: {
    width?: number;
    height?: number;
    colorSpace?: string;
  };
  camera: {
    make?: string;
    model?: string;
    hostComputer?: string;
    lensMake?: string;
    lens?: string;
    serialNumber?: string;
    bodySerialNumber?: string;
    software?: string;
    artist?: string;
    ownerName?: string;
    copyright?: string;
    imageUniqueId?: string;
    dateTimeOriginal?: string;
    createDate?: string;
    modifyDate?: string;
    iso?: number;
    fNumber?: number;
    exposureTime?: string;
    focalLength?: string;
  };
  gps: {
    latitude: number;
    longitude: number;
    altitude?: number;
    compassHeading?: number;
    speed?: number;
    gpsMethod?: string;
    gpsTimestamp?: string;
    physicalAddress?: string;
    osmUrl?: string;
    mapNode?: ThreatNode;
  } | null;
  textualLocation: {
    city?: string;
    sublocation?: string;
    state?: string;
    country?: string;
    countryCode?: string;
  } | null;
  embeddedStrings: {
    urls: string[];
    domains: string[];
    ips: string[];
    ipv6s: string[];
    emails: string[];
    filePaths: string[];
    suspiciousTokens: string[];
  };
  embeddedIpTraces: ThreatNode[];
  privacyAndOriginNote: string;
  rawTags: Array<{ group: string; key: string; value: string }>;
  analyzedAt: string;
}

export interface BlockedIpEntry {
  ip: string;
  blockedAt: string;
  lastCheckedAt: string;
  reason: string;
  severity: ThreatSeverity;
  country?: string;
  city?: string;
  physicalAddress?: string;
  asn?: string;
  isp?: string;
  cidr?: string;
  abuseEmails: string[];
  openPorts: number[];
  knownVulns: string[];
  watchdogStatus: 'blocked-monitoring';
  firewallRules: {
    nginx: string;
    iptables: string;
    ufw: string;
    cloudflare: string;
  };
}

export interface BlockedDomainEntry {
  domain: string;
  fullUrl?: string;
  sinkholedAt: string;
  reason: string;
  resolvedIps: string[];
  abuseEmails: string[];
  hostsEntry: string;
  piholeRule: string;
  safeBrowsingUrl: string;
  netcraftReportUrl: string;
}

export interface ProtectedSystemShield {
  id: string;
  target: string;
  host: string;
  activatedAt: string;
  lastCheckedAt: string;
  verdict: ThreatSeverity;
  tlsValid: boolean | null;
  tlsDaysRemaining?: number;
  missingHeadersCount: number;
  emailSecurityStatus: 'protected' | 'weak' | 'missing';
  baselineA: string[];
  status: 'shielded' | 'alert';
  alertReason?: string;
  nginxHardeningConfig: string;
  recommendedDnsRecords: string[];
}

export interface DefenseStateSnapshot {
  blockedIps: BlockedIpEntry[];
  blockedDomains: BlockedDomainEntry[];
  protectedShields: ProtectedSystemShield[];
  globalFirewallBundle: {
    nginxDenyList: string;
    iptablesScript: string;
    dnsSinkholeHosts: string;
    cloudflareWafExpr: string;
  };
}
