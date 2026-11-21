import type {
  CveDetailRecord,
  ScanModuleId,
  ScanProgressEvent,
  TargetScanResult,
} from '../src/types/cyber.ts';
import { domainVerificationStore } from './domainVerification.ts';
import {
  buildCategorizedFindings,
  ETHICAL_LEGAL_DISCLAIMER,
} from './findingsBuilder.ts';
import { activeVulnsModule } from './modules/activeVulnsModule.ts';
import { dnsModule } from './modules/dnsModule.ts';
import { headersModule } from './modules/headersModule.ts';
import { osintMetaModule, searchWebBreachSignals } from './modules/osintMetaModule.ts';
import { fetchMitreCveDetail, portsBgpModule } from './modules/portsBgpModule.ts';
import { sensitiveFilesModule } from './modules/sensitiveFilesModule.ts';
import { threatIntelModule } from './modules/threatIntelModule.ts';
import { tlsModule } from './modules/tlsModule.ts';
import {
  ALL_SCAN_MODULES,
  PASSIVE_SCAN_MODULES,
  type ScanExecutionContext,
  type ScanModulePlugin,
} from './modules/types.ts';
import { wafModule } from './modules/wafModule.ts';
import { extractRootDomain } from './osintParsers.ts';
import { threatMonitor } from './threatMonitor.ts';
import {
  computeTargetVerdict,
  generateHardeningRecommendations,
  isValidIpv4,
} from './threatRules.ts';

export const MODULE_REGISTRY: Record<ScanModuleId, ScanModulePlugin> = {
  dns: dnsModule,
  tls: tlsModule,
  headers: headersModule,
  threatIntel: threatIntelModule,
  portsBgp: portsBgpModule,
  osintMeta: osintMetaModule,
  waf: wafModule,
  sensitiveFiles: sensitiveFilesModule,
  activeVulns: activeVulnsModule,
};

// Execution waves respect module dependencies (DNS + Headers inform ThreatIntel, Ports/BGP, WAF, and Active checks)
const EXECUTION_WAVES: ScanModuleId[][] = [
  ['dns', 'tls', 'headers', 'osintMeta'],
  ['threatIntel', 'portsBgp', 'waf'],
  ['sensitiveFiles', 'activeVulns'],
];

export interface OrchestratorOptions {
  target: string;
  modules?: ScanModuleId[];
  onProgress?: (event: ScanProgressEvent) => void;
  // Used in deterministic unit tests without live network verification
  verifyOwnershipFn?: (domain: string) => boolean;
  customRegistry?: Partial<Record<ScanModuleId, ScanModulePlugin>>;
}

export function normalizeSelectedModules(modules?: ScanModuleId[]): ScanModuleId[] {
  if (!Array.isArray(modules) || modules.length === 0) {
    return [...PASSIVE_SCAN_MODULES];
  }
  const validSet = new Set<ScanModuleId>(ALL_SCAN_MODULES);
  const filtered = Array.from(new Set(modules.filter((m) => validSet.has(m))));
  return filtered.length > 0 ? filtered : [...PASSIVE_SCAN_MODULES];
}

export function resolveTargetDescriptor(rawInput: string): {
  query: string;
  normalizedTarget: string;
  targetType: TargetScanResult['targetType'];
  host: string;
  probeUrl: string;
  rootDomain: string;
} {
  const query = rawInput.trim();
  let targetType: TargetScanResult['targetType'] = 'search';
  let normalizedTarget = query;
  let host = '';
  let probeUrl = '';

  if (/^CVE-\d{4}-\d{4,}$/i.test(query)) {
    targetType = 'cve';
    normalizedTarget = query.toUpperCase();
  } else if (isValidIpv4(query)) {
    targetType = 'ip';
    host = query;
    normalizedTarget = query;
  } else if (/^https?:\/\//i.test(query)) {
    try {
      const u = new URL(query);
      targetType = 'url';
      host = u.hostname.toLowerCase();
      probeUrl = u.toString();
      normalizedTarget = u.toString();
    } catch {
      targetType = 'search';
    }
  } else if (/^[a-z0-9.-]+\.[a-z]{2,}(?:\/.*)?$/i.test(query) && !query.includes(' ')) {
    const urlStr = `https://${query}`;
    try {
      const u = new URL(urlStr);
      targetType = query.includes('/') ? 'url' : 'domain';
      host = u.hostname.toLowerCase();
      probeUrl = u.toString();
      normalizedTarget = query.includes('/') ? u.toString() : host;
    } catch {
      targetType = 'search';
    }
  }

  return {
    query,
    normalizedTarget,
    targetType,
    host,
    probeUrl,
    rootDomain: host ? extractRootDomain(host) : '',
  };
}

export async function runModularScanOrchestrator(
  options: OrchestratorOptions,
): Promise<TargetScanResult> {
  const scannedAt = new Date().toISOString();
  const selectedModules = normalizeSelectedModules(options.modules);
  const desc = resolveTargetDescriptor(options.target);
  const completedModules: ScanModuleId[] = [];
  const registry: Record<ScanModuleId, ScanModulePlugin> = {
    ...MODULE_REGISTRY,
    ...options.customRegistry,
  };

  const emitProgress = (
    moduleId: ScanModuleId | 'init' | 'finalize',
    label: string,
    percent: number,
  ) => {
    options.onProgress?.({
      type: 'progress',
      moduleId,
      label,
      percent: Math.min(100, Math.max(0, Math.round(percent))),
      completedModules: [...completedModules],
    });
  };

  emitProgress('init', 'Initializing modular scan pipeline...', 8);

  // 1. Direct CVE Deep Investigation
  if (desc.targetType === 'cve') {
    emitProgress('osintMeta', `Querying MITRE CVE & CISA KEV for ${desc.normalizedTarget}...`, 45);
    const snapshot = await threatMonitor.getSnapshot(false);
    const [cveDetail, webSignals] = await Promise.all([
      fetchMitreCveDetail(desc.normalizedTarget),
      searchWebBreachSignals(desc.normalizedTarget),
    ]);
    const kevMatch = snapshot.cves.find(
      (c) => c.cveID.toUpperCase() === desc.normalizedTarget,
    );

    const feedMatches: Array<{ feed: string; detail: string }> = [];
    if (kevMatch) {
      feedMatches.push({
        feed: 'CISA Known Exploited Vulnerabilities',
        detail: `${kevMatch.vendorProject} ${kevMatch.product}: ${kevMatch.vulnerabilityName}`,
      });
    }

    const score = cveDetail?.cvssScore ?? 0;
    const verdict: TargetScanResult['verdict'] =
      kevMatch || score >= 9 || cveDetail?.cvssSeverity === 'CRITICAL'
        ? 'CRITICAL'
        : score >= 7 || cveDetail?.cvssSeverity === 'HIGH'
          ? 'HIGH'
          : cveDetail
            ? 'ELEVATED'
            : 'CLEAN';

    const reasons: string[] = [];
    if (kevMatch) {
      reasons.push(`Actively exploited in the wild (CISA KEV, due ${kevMatch.dueDate})`);
    }
    if (cveDetail?.cvssScore !== undefined) {
      reasons.push(
        `MITRE CVSS ${cveDetail.cvssScore} (${cveDetail.cvssSeverity || 'Scored'}) · ${cveDetail.cwes[0] || cveDetail.title}`,
      );
    } else if (cveDetail) {
      reasons.push(`Official MITRE CVE record retrieved: ${cveDetail.title}`);
    } else {
      reasons.push(`No published MITRE CVE record returned for ${desc.normalizedTarget}`);
    }

    const cveList: CveDetailRecord[] = cveDetail ? [cveDetail] : [];
    const { findings, riskCounts } = buildCategorizedFindings({
      targetType: 'cve',
      feedMatches,
      tls: null,
      httpAudit: null,
      emailSecurityStatus: 'missing',
      attribution: [],
      cveDetails: cveList,
      executedModules: ['osintMeta'],
    });
    if (cveDetail) {
      const riskLevel =
        score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
      findings.unshift({
        id: `cve-${desc.normalizedTarget}`,
        moduleId: 'osintMeta',
        title: `${desc.normalizedTarget}: ${cveDetail.title}`,
        description: cveDetail.description,
        riskLevel,
        owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
        owaspId: 'A06:2021',
        cwe: cveDetail.cwes[0],
        evidence: `CVSS ${cveDetail.cvssScore ?? 'N/A'}`,
        remediation:
          'Upgrade affected components to patched releases and enforce WAF virtual patching rules.',
      });
      riskCounts[riskLevel] += 1;
    }

    emitProgress('finalize', 'Finalizing OWASP & CVE report...', 100);
    return {
      query: desc.query,
      normalizedTarget: desc.normalizedTarget,
      targetType: 'cve',
      scannedAt,
      legalDisclaimer: ETHICAL_LEGAL_DISCLAIMER,
      verdict,
      verdictReasons: reasons,
      feedMatches,
      dns: {
        a: [],
        aaaa: [],
        mx: [],
        ns: [],
        txt: [],
        caa: [],
        emailSecurityStatus: 'missing',
      },
      attribution: [],
      tls: null,
      httpAudit: null,
      cveDetails: cveList,
      hardeningRecommendations: [
        {
          id: `mitigate-${desc.normalizedTarget}`,
          severity: verdict === 'CRITICAL' || verdict === 'HIGH' ? 'CRITICAL' : 'HIGH',
          title: `Vendor Patching & Attack-Surface Mitigation for ${desc.normalizedTarget}`,
          remediation: cveDetail?.affectedProducts.length
            ? `Upgrade affected software (${cveDetail.affectedProducts.join(', ')}) to the vendor's fixed release, audit exposed artifacts/dependencies, and enforce strict network ACLs until patched.`
            : 'Apply vendor security updates immediately, restrict vulnerable service exposure via firewall/WAF rules, and monitor logs for exploitation indicators.',
        },
      ],
      webBreachSignals: webSignals,
      selectedModules,
      executedModules: ['osintMeta'],
      findings,
      riskCounts,
    };
  }

  // 2. General Web Threat Intelligence Search
  if (desc.targetType === 'search') {
    emitProgress('osintMeta', `Searching global breach signals for "${desc.query}"...`, 60);
    const signals = await searchWebBreachSignals(desc.query);
    const highSignals = signals.filter((s) => s.severity === 'CRITICAL' || s.severity === 'HIGH');
    emitProgress('finalize', 'Finalizing search dossier...', 100);
    return {
      query: desc.query,
      normalizedTarget: desc.query,
      targetType: 'search',
      scannedAt,
      legalDisclaimer: ETHICAL_LEGAL_DISCLAIMER,
      verdict: highSignals.length >= 2 ? 'ELEVATED' : 'CLEAN',
      verdictReasons:
        signals.length > 0
          ? [`Found ${signals.length} live global web security dispatches matching "${desc.query}"`]
          : [`No active breach or attack reports indexed for "${desc.query}"`],
      feedMatches: [],
      dns: {
        a: [],
        aaaa: [],
        mx: [],
        ns: [],
        txt: [],
        caa: [],
        emailSecurityStatus: 'missing',
      },
      attribution: [],
      tls: null,
      httpAudit: null,
      hardeningRecommendations: [],
      webBreachSignals: signals,
      selectedModules,
      executedModules: ['osintMeta'],
      findings: [],
      riskCounts: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    };
  }

  // 3. Modular Execution Pipeline for IP / Domain / URL Targets
  const isVerifiedFn =
    options.verifyOwnershipFn ?? ((d: string) => domainVerificationStore.isDomainVerified(d));
  const ownershipVerified =
    (desc.targetType === 'domain' || desc.targetType === 'url') &&
    Boolean(desc.rootDomain) &&
    isVerifiedFn(desc.rootDomain);

  const ctx: ScanExecutionContext = {
    query: desc.query,
    normalizedTarget: desc.normalizedTarget,
    targetType: desc.targetType,
    host: desc.host,
    probeUrl: desc.probeUrl,
    rootDomain: desc.rootDomain,
    ownershipVerified,
    feedMatches: [],
    heuristicWarnings: [],
    dns: {
      a: desc.targetType === 'ip' ? [desc.host] : [],
      aaaa: [],
      mx: [],
      ns: [],
      txt: [],
      caa: [],
      emailSecurityStatus: 'missing',
    },
    tls: null,
    httpAudit: null,
    rawHttpHeaders: {},
    rawSetCookies: [],
    htmlSample: '',
    attribution: [],
    bgpProfile: null,
    cveDetails: [],
    discoveredSubdomains: [],
    rdapProfile: null,
    waybackProfile: null,
    webBreachSignals: [],
    waf: null,
    sensitivePaths: [],
    activeVulns: [],
  };

  const applicableSelected = selectedModules.filter((id) =>
    registry[id]?.supportsTargetType(desc.targetType),
  );
  const runnableCount = Math.max(1, applicableSelected.length);
  const skippedActiveModules: Array<{ moduleId: ScanModuleId; reason: string }> = [];

  for (const wave of EXECUTION_WAVES) {
    const waveModules = wave.filter((id) => applicableSelected.includes(id));
    if (waveModules.length === 0) continue;

    await Promise.all(
      waveModules.map(async (id) => {
        const plugin = registry[id];
        if (!plugin) return;

        // Ethical Authorization Gate: Block active scans unless Domain Ownership Verification passed
        if (plugin.isActive && !ctx.ownershipVerified) {
          skippedActiveModules.push({
            moduleId: id,
            reason:
              'Blocked by ethical safeguard: Mandatory domain ownership verification required before running active probes.',
          });
          return;
        }

        const startPct = 10 + (completedModules.length / runnableCount) * 80;
        emitProgress(id, `Scanning ${plugin.label}... ${Math.round(startPct)}%`, startPct);
        try {
          await plugin.run(ctx);
        } catch {
          // Isolate plugin failure so one module never breaks the entire scan
        }
        completedModules.push(id);
        const donePct = 10 + (completedModules.length / runnableCount) * 80;
        emitProgress(id, `Completed ${plugin.label}`, donePct);
      }),
    );
  }

  emitProgress('finalize', 'Mapping OWASP Top 10 & generating remediation snippets...', 95);

  const allPorts = Array.from(new Set(ctx.attribution.flatMap((a) => a.openPorts ?? [])));
  const allVulns = Array.from(new Set(ctx.attribution.flatMap((a) => a.knownVulns ?? [])));

  const verdictInfo = computeTargetVerdict({
    feedMatches: ctx.feedMatches,
    heuristicWarnings: ctx.heuristicWarnings,
    tlsValid: ctx.tls ? ctx.tls.valid : null,
    missingSecurityHeadersCount: ctx.httpAudit?.missingSecurityHeaders.length ?? 0,
    webBreachMatchesCount: ctx.webBreachSignals.length,
  });

  // Escalate verdict if active scan discovered confirmed exposed secrets or high vulnerabilities
  const hasCriticalSensitive = ctx.sensitivePaths.some(
    (s) => s.exposed && s.riskLevel === 'Critical',
  );
  const hasHighActiveVuln = ctx.activeVulns.some((v) => v.riskLevel === 'High' || v.riskLevel === 'Critical');
  let finalVerdict = verdictInfo.verdict;
  const finalReasons = [...verdictInfo.reasons];

  if (hasCriticalSensitive && finalVerdict !== 'CRITICAL') {
    finalVerdict = 'CRITICAL';
    finalReasons.unshift('Confirmed publicly exposed sensitive configuration/backup file!');
  } else if (hasHighActiveVuln && (finalVerdict === 'CLEAN' || finalVerdict === 'ELEVATED')) {
    finalVerdict = 'HIGH';
    finalReasons.unshift('Active verification flagged high-risk injection/error exposure!');
  }

  const hardeningRecommendations = generateHardeningRecommendations({
    targetType: desc.targetType,
    feedMatches: ctx.feedMatches,
    tlsValid: ctx.tls ? ctx.tls.valid : null,
    tlsDaysRemaining: ctx.tls?.daysRemaining,
    missingSecurityHeaders: ctx.httpAudit?.missingSecurityHeaders ?? [],
    cookieIssues: ctx.httpAudit?.cookieIssues ?? [],
    emailSecurityStatus:
      desc.targetType === 'ip' ? undefined : ctx.dns.emailSecurityStatus,
    knownVulnsCount: allVulns.length,
    openPorts: allPorts,
  });

  const { findings, riskCounts } = buildCategorizedFindings({
    targetType: desc.targetType,
    feedMatches: ctx.feedMatches,
    tls: ctx.tls,
    httpAudit: ctx.httpAudit,
    emailSecurityStatus: ctx.dns.emailSecurityStatus,
    attribution: ctx.attribution,
    cveDetails: ctx.cveDetails,
    waf: ctx.waf,
    sensitivePaths: ctx.sensitivePaths,
    activeVulns: ctx.activeVulns,
    executedModules: completedModules,
  });

  emitProgress('finalize', 'Security assessment complete', 100);

  return {
    query: desc.query,
    normalizedTarget: desc.normalizedTarget,
    targetType: desc.targetType,
    scannedAt,
    legalDisclaimer: ETHICAL_LEGAL_DISCLAIMER,
    verdict: finalVerdict,
    verdictReasons: finalReasons,
    feedMatches: ctx.feedMatches,
    dns: ctx.dns,
    attribution: ctx.attribution,
    tls: ctx.tls,
    httpAudit: ctx.httpAudit,
    discoveredSubdomains: ctx.discoveredSubdomains,
    rdapProfile: ctx.rdapProfile,
    bgpProfile: ctx.bgpProfile,
    waybackProfile: ctx.waybackProfile,
    cveDetails: ctx.cveDetails,
    hardeningRecommendations,
    webBreachSignals: ctx.webBreachSignals,
    selectedModules,
    executedModules: completedModules,
    skippedActiveModules,
    ownershipVerified: ctx.ownershipVerified,
    waf: ctx.waf,
    sensitivePaths: ctx.sensitivePaths,
    activeVulns: ctx.activeVulns,
    findings,
    riskCounts,
  };
}
