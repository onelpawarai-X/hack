import { RefreshCw } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { AttackerInspector } from './components/AttackerInspector';
import { ImageForensicsPanel } from './components/ImageForensicsPanel';
import { RadarCanvas } from './components/RadarCanvas';
import { TargetScannerPanel } from './components/TargetScannerPanel';
import { ThreatFeedsMatrix, type MatrixTab } from './components/ThreatFeedsMatrix';
import { getCyberTranslations } from './i18n/cyberTranslations';
import type {
  DefenseStateSnapshot,
  Language,
  PhishingTrap,
  RadarSnapshot,
  TargetScanResult,
  ThreatNode,
} from './types/cyber';
import { formatUtcTimestamp } from './utils/formatters';

const POLL_SECONDS = 30;

const EMPTY_DEFENSE_STATE: DefenseStateSnapshot = {
  blockedIps: [],
  blockedDomains: [],
  protectedShields: [],
  globalFirewallBundle: {
    nginxDenyList: '# No blocked attacker IPs yet',
    iptablesScript: '#!/usr/bin/env bash\n# No blocked attacker IPs yet',
    dnsSinkholeHosts: '# No sinkholed phishing domains yet',
    cloudflareWafExpr: '(false)',
  },
};

export default function App() {
  const [lang, setLang] = useState<Language>('bn');
  const t = getCyberTranslations(lang);

  const [radar, setRadar] = useState<RadarSnapshot | null>(null);
  const [loadingRadar, setLoadingRadar] = useState(true);
  const [radarError, setRadarError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);
  const [pinnedNode, setPinnedNode] = useState<ThreatNode | null>(null);
  const [countdown, setCountdown] = useState(POLL_SECONDS);

  const [scanResult, setScanResult] = useState<TargetScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const [defenseState, setDefenseState] = useState<DefenseStateSnapshot>(EMPTY_DEFENSE_STATE);
  const [activatingShield, setActivatingShield] = useState(false);
  const [shieldNotice, setShieldNotice] = useState<string | null>(null);
  const [activeMatrixTab, setActiveMatrixTab] = useState<MatrixTab>('attackers');

  const radarSectionRef = useRef<HTMLDivElement | null>(null);
  const scannerSectionRef = useRef<HTMLDivElement | null>(null);
  const matrixSectionRef = useRef<HTMLDivElement | null>(null);

  const fetchDefenseState = useCallback(async () => {
    try {
      const res = await fetch('/api/defense/state');
      if (res.ok) {
        const data = (await res.json()) as DefenseStateSnapshot;
        setDefenseState(data);
      }
    } catch {
      // ignore transient error
    }
  }, []);

  const fetchRadar = useCallback(async (forceRefresh = false) => {
    setLoadingRadar(true);
    setRadarError(null);
    try {
      const url = forceRefresh ? '/api/radar?refresh=1' : '/api/radar';
      const res = await fetch(url);
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.details || errBody.error || `HTTP ${res.status}`);
      }
      const data = (await res.json()) as RadarSnapshot;
      setRadar(data);
      setCountdown(POLL_SECONDS);
      setSelectedNode((prev) => {
        if (
          prev &&
          (prev.sourceFeed === 'Live Attribution' ||
            prev.sourceFeed === 'Photo GPS' ||
            prev.sourceFeed === 'Image Embedded IP')
        ) {
          return prev;
        }
        if (prev && data.threatNodes.some((n) => n.id === prev.id)) {
          return prev;
        }
        return (
          data.threatNodes.find((n) => n.severity === 'CRITICAL') ??
          data.threatNodes[0] ??
          null
        );
      });
    } catch (err) {
      setRadarError(err instanceof Error ? err.message : 'Unable to load threat radar');
    } finally {
      setLoadingRadar(false);
    }
  }, []);

  useEffect(() => {
    void fetchRadar(false);
    void fetchDefenseState();
  }, [fetchRadar, fetchDefenseState]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          void fetchRadar(false);
          void fetchDefenseState();
          return POLL_SECONDS;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [fetchRadar, fetchDefenseState]);

  const handleSelectNode = async (node: ThreatNode) => {
    setSelectedNode(node);
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(node.ip) && (!node.physicalAddress || !node.abuseEmails)) {
      try {
        const res = await fetch(`/api/trace/${encodeURIComponent(node.ip)}`);
        if (res.ok) {
          const enriched = (await res.json()) as ThreatNode;
          setSelectedNode({
            ...node,
            physicalAddress: enriched.physicalAddress,
            timezone: enriched.timezone,
            isTorExit: enriched.isTorExit,
            openPorts: enriched.openPorts,
            knownVulns: enriched.knownVulns,
            cpes: enriched.cpes,
            cidr: enriched.cidr,
            abuseEmails: enriched.abuseEmails,
            defended: enriched.defended,
            reverse: node.reverse || enriched.reverse,
          });
        }
      } catch {
        // retain existing node details
      }
    }
  };

  const handleFocusNodeOnMap = (node: ThreatNode) => {
    setPinnedNode(node);
    setSelectedNode(node);
    radarSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleScanTarget = async (target: string, scrollToScanner = true) => {
    const clean = target.trim();
    if (clean.length < 2) return;
    setScanning(true);
    setScanError(null);
    setShieldNotice(null);
    if (scrollToScanner) {
      scannerSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: clean }),
      });
      const data = (await res.json()) as TargetScanResult & {
        error?: string;
        details?: string;
      };
      if (!res.ok) {
        throw new Error(data.details || data.error || 'Target scan failed');
      }
      setScanResult(data);
      if (data.attribution.length > 0) {
        setPinnedNode(data.attribution[0]);
        setSelectedNode(data.attribution[0]);
      }
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  // Defend button: jumps to Map + launches deep attribution/scan + blocks IP + retrieves RDAP abuse emails + activates monitoring
  const handleDefendIp = async (ip: string, reason?: string, originNode?: ThreatNode) => {
    if (originNode) {
      setPinnedNode(originNode);
      setSelectedNode(originNode);
    }
    radarSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    setActivatingShield(true);
    setShieldNotice(null);

    try {
      const [blockRes] = await Promise.all([
        fetch('/api/defense/block-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, reason }),
        }),
        handleScanTarget(ip, false),
      ]);

      if (blockRes.ok) {
        const payload = (await blockRes.json()) as {
          entry: DefenseStateSnapshot['blockedIps'][number];
          state: DefenseStateSnapshot;
        };
        setDefenseState(payload.state);
        setSelectedNode((prev) =>
          prev && prev.ip === ip
            ? {
                ...prev,
                cidr: payload.entry.cidr ?? prev.cidr,
                abuseEmails: payload.entry.abuseEmails,
                defended: true,
                physicalAddress: payload.entry.physicalAddress ?? prev.physicalAddress,
              }
            : prev,
        );
        setShieldNotice(`${ip} — ${t.defendedBlockedBadge}`);
      }
    } finally {
      setActivatingShield(false);
    }
  };

  const handleTakedownPhishing = async (trap: PhishingTrap) => {
    setActivatingShield(true);
    try {
      const res = await fetch('/api/defense/takedown-domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: trap.url,
          reason: trap.riskReasons.join(', '),
        }),
      });
      if (res.ok) {
        const data = (await res.json()) as { state: DefenseStateSnapshot };
        setDefenseState(data.state);
        setActiveMatrixTab('defenseCenter');
      }
    } finally {
      setActivatingShield(false);
    }
  };

  const handleActivateWebsiteShield = async (target: string) => {
    setActivatingShield(true);
    setShieldNotice(null);
    try {
      const res = await fetch('/api/defense/shield-target', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      if (res.ok) {
        const data = (await res.json()) as { state: DefenseStateSnapshot };
        setDefenseState(data.state);
        setShieldNotice(t.scanner.shieldActivatedMsg);
        setActiveMatrixTab('defenseCenter');
      }
    } finally {
      setActivatingShield(false);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    const res = await fetch(`/api/defense/block-ip/${encodeURIComponent(ip)}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      const data = (await res.json()) as { state: DefenseStateSnapshot };
      setDefenseState(data.state);
    }
  };

  const handleRemoveSinkhole = async (domain: string) => {
    const res = await fetch(`/api/defense/takedown-domain/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      const data = (await res.json()) as { state: DefenseStateSnapshot };
      setDefenseState(data.state);
    }
  };

  const handleRecheckShield = async (id: string) => {
    const res = await fetch(`/api/defense/recheck-shield/${encodeURIComponent(id)}`, {
      method: 'POST',
    });
    if (res.ok) {
      const data = (await res.json()) as { state: DefenseStateSnapshot };
      setDefenseState(data.state);
    }
  };

  const handleRemoveShield = async (id: string) => {
    const res = await fetch(`/api/defense/shield/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (res.ok) {
      const data = (await res.json()) as { state: DefenseStateSnapshot };
      setDefenseState(data.state);
    }
  };

  const blockedIpStrings = defenseState.blockedIps.map((b) => b.ip);
  const selectedIsBlocked = Boolean(
    selectedNode && blockedIpStrings.includes(selectedNode.ip),
  );
  const totalActiveShields =
    defenseState.protectedShields.length +
    defenseState.blockedIps.length +
    defenseState.blockedDomains.length;

  return (
    <div className="min-h-screen flex flex-col">
      {/* Clean 3-Zone Top Control Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-[#06090F]/92 backdrop-blur-md">
        <div className="max-w-[1440px] mx-auto px-3 sm:px-6 py-2.5 flex items-center justify-between gap-2 sm:gap-4">
          <div className="text-sm sm:text-lg font-extrabold tracking-tight text-white whitespace-nowrap shrink-0 font-display">
            {t.appName}
          </div>

          <div className="hidden md:flex items-center gap-2.5 text-xs text-slate-300">
            <span className="font-medium text-emerald-400 whitespace-nowrap">
              {t.liveSweepActive}
            </span>
            <span aria-hidden="true" className="text-slate-600">
              ·
            </span>
            <span className="font-mono tabular-nums text-slate-300 whitespace-nowrap">
              {t.nextSweepLabel}: {String(countdown).padStart(2, '0')}s
            </span>
            {radar?.scannedAt && (
              <>
                <span aria-hidden="true" className="text-slate-600 hidden lg:inline">
                  ·
                </span>
                <span className="font-mono tabular-nums text-slate-400 hidden lg:inline whitespace-nowrap">
                  {formatUtcTimestamp(radar.scannedAt, lang)}
                </span>
              </>
            )}
          </div>

          <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => void fetchRadar(true)}
              disabled={loadingRadar}
              className="inline-flex items-center gap-1.5 px-2.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-60 text-white text-[11px] sm:text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${loadingRadar ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              <span>{loadingRadar ? t.scanningNow : t.scanNowBtn}</span>
            </button>

            <div
              role="group"
              aria-label="Language toggle"
              className="inline-flex items-center p-0.5 rounded-lg bg-[#0B101B] border border-slate-800"
            >
              <button
                type="button"
                onClick={() => setLang('bn')}
                aria-pressed={lang === 'bn'}
                className={`px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-md text-[11px] sm:text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  lang === 'bn'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                বাংলা
              </button>
              <button
                type="button"
                onClick={() => setLang('en')}
                aria-pressed={lang === 'en'}
                className={`px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-md text-[11px] sm:text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  lang === 'en'
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                English
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {radarError && (
          <div className="p-4 rounded-xl bg-red-950/50 border border-red-500/40 text-xs text-red-200">
            {radarError}
          </div>
        )}

        {/* Hero Split: Real 3D Globe & Tactical Cyber Threat Radar + Attacker Inspector */}
        <div ref={radarSectionRef} className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-stretch">
          <div className="xl:col-span-8 flex flex-col">
            <RadarCanvas
              t={t}
              nodes={radar?.threatNodes ?? []}
              pinnedNode={pinnedNode}
              selectedNodeId={selectedNode?.id ?? null}
              blockedIps={blockedIpStrings}
              onSelectNode={(n) => void handleSelectNode(n)}
              loading={loadingRadar}
            />
          </div>
          <div className="xl:col-span-4 flex flex-col">
            <AttackerInspector
              t={t}
              node={selectedNode}
              isBlocked={selectedIsBlocked}
              onDefendIp={(ip, reason) => void handleDefendIp(ip, reason, selectedNode ?? undefined)}
              onDeepScanIp={(ip) => void handleScanTarget(ip)}
            />
          </div>
        </div>

        {/* 4-Column Live Telemetry Summary Strip */}
        <section
          aria-label="Global Threat Telemetry"
          className="soc-panel rounded-xl grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-800/80"
        >
          <div className="p-4 sm:p-5 space-y-1">
            <div className="text-xs text-slate-400">{t.metrics.activeAttackers}</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-red-400">
              {(radar?.summary.activeAttackers ?? 0).toLocaleString('en-US')}
            </div>
          </div>
          <div className="p-4 sm:p-5 space-y-1">
            <div className="text-xs text-slate-400">{t.metrics.c2Botnets}</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-orange-400">
              {(radar?.summary.c2Botnets ?? 0).toLocaleString('en-US')}
            </div>
          </div>
          <div className="p-4 sm:p-5 space-y-1">
            <div className="text-xs text-slate-400">{t.metrics.phishingTraps}</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-red-400">
              {(radar?.summary.phishingTraps ?? 0).toLocaleString('en-US')}
            </div>
          </div>
          <div className="p-4 sm:p-5 space-y-1">
            <div className="text-xs text-slate-400">{t.metrics.activeDefenseShields}</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {totalActiveShields.toLocaleString('en-US')}
            </div>
          </div>
        </section>

        {/* Deep Target, IP Map Plotting & Website Defense Shield Scanner */}
        <div ref={scannerSectionRef}>
          <TargetScannerPanel
            t={t}
            lang={lang}
            scanResult={scanResult}
            scanning={scanning}
            scanError={scanError}
            activatingShield={activatingShield}
            shieldNotice={shieldNotice}
            onScanTarget={(target) => void handleScanTarget(target)}
            onFocusNodeOnMap={handleFocusNodeOnMap}
            onActivateWebsiteShield={(target) => void handleActivateWebsiteShield(target)}
            onDefendIp={(ip, reason) => void handleDefendIp(ip, reason)}
            samplePhishUrl={radar?.phishingTraps[0]?.url}
            sampleAttackerIp={radar?.threatNodes[0]?.ip}
          />
        </div>

        {/* Ultra-Deep Picture Forensics, Device, Location & Embedded IP Lab */}
        <ImageForensicsPanel
          t={t}
          lang={lang}
          onPinNodeOnMap={handleFocusNodeOnMap}
          onDefendIp={(ip, reason) => void handleDefendIp(ip, reason)}
        />

        {/* 4 Command Sections: Active Attackers | Phishing Takedowns | Global Threats | Defense & System Shields */}
        <div ref={matrixSectionRef}>
          <ThreatFeedsMatrix
            t={t}
            lang={lang}
            activeTab={activeMatrixTab}
            onChangeTab={setActiveMatrixTab}
            threatNodes={radar?.threatNodes ?? []}
            phishingTraps={radar?.phishingTraps ?? []}
            incidents={radar?.incidents ?? []}
            webScanHighlights={radar?.webScanHighlights ?? []}
            cves={radar?.cves ?? []}
            feedHealth={radar?.feedHealth ?? []}
            defenseState={defenseState}
            selectedNodeId={selectedNode?.id ?? null}
            onSelectNode={(n) => void handleSelectNode(n)}
            onDefendAttacker={(n) => void handleDefendIp(n.ip, n.threatType, n)}
            onTakedownPhishing={(trap) => void handleTakedownPhishing(trap)}
            onScanTarget={(target) => void handleScanTarget(target)}
            onUnblockIp={(ip) => void handleUnblockIp(ip)}
            onRemoveSinkhole={(dom) => void handleRemoveSinkhole(dom)}
            onRecheckShield={(id) => void handleRecheckShield(id)}
            onRemoveShield={(id) => void handleRemoveShield(id)}
          />
        </div>
      </main>
    </div>
  );
}
