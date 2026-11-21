import { Camera, RefreshCw, SlidersHorizontal, SquareTerminal } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AttackerDossierPanel } from './components/AttackerDossierPanel';
import { AttackerInspector } from './components/AttackerInspector';
import { AuthGate } from './components/AuthGate';
import { ControlCenter } from './components/ControlCenter';
import { DefenseGrid } from './components/DefenseGrid';
import { GlobalCameraSection } from './components/GlobalCameraSection';
import { GlobalExposureSection } from './components/GlobalExposureSection';
import { SentinelAgentBadge } from './components/SentinelAgentBadge';
import { SiteAgentDownloadButton } from './components/SiteAgentDownloadButton';
import { WebsiteNetworkSection } from './components/WebsiteNetworkSection';
import { DomainVerificationPanel } from './components/DomainVerificationPanel';
import { EthicalBanner } from './components/EthicalBanner';
import { ImageForensicsPanel } from './components/ImageForensicsPanel';
import { LiveScanTerminal } from './components/LiveScanTerminal';
import { LiveThreatMap } from './components/LiveThreatMap';
import { RadarCanvas } from './components/RadarCanvas';
import { ScanProgressBar } from './components/ScanProgressBar';
import { SecurityStackPanel } from './components/SecurityStackPanel';
import { SystemTerminal } from './components/SystemTerminal';
import { SeverityCharts } from './components/SeverityCharts';
import { TargetScannerPanel } from './components/TargetScannerPanel';
import { ThreatFeedsMatrix, type MatrixTab } from './components/ThreatFeedsMatrix';
import { AuthProvider, useAuth } from './hooks/useAuth.tsx';
import { useDefenseGrid } from './hooks/useDefenseGrid';
import { useScanSocket } from './hooks/useScanSocket';
import { getCyberTranslations } from './i18n/cyberTranslations';
import { getDefenseGridTranslations } from './i18n/defenseGridTranslations';
import { getLabTranslations } from './i18n/labTranslations';
import type {
  DefenseStateSnapshot,
  Language,
  PhishingTrap,
  RadarSnapshot,
  TargetScanResult,
  ThreatNode,
} from './types/cyber';
import type { ScanGeoPayload, ScanLogEvent, ScanProgressPayload } from './types/realtime';
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

function AppDashboard() {
  const [lang, setLang] = useState<Language>('bn');
  const t = getCyberTranslations(lang);
  const auth = useAuth();
  const [controlOpen, setControlOpen] = useState(false);

  const [radar, setRadar] = useState<RadarSnapshot | null>(null);
  const [loadingRadar, setLoadingRadar] = useState(true);
  const [radarError, setRadarError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);
  const [pinnedNode, setPinnedNode] = useState<ThreatNode | null>(null);
  const [countdown, setCountdown] = useState(POLL_SECONDS);

  const [scanResult, setScanResult] = useState<TargetScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const lab = useMemo(() => getLabTranslations(lang), [lang]);
  const defenseGridT = useMemo(() => getDefenseGridTranslations(lang), [lang]);
  const defenseGrid = useDefenseGrid();
  const scanSocket = useScanSocket();
  const [fallbackLogs, setFallbackLogs] = useState<ScanLogEvent[]>([]);
  const [fallbackProgress, setFallbackProgress] = useState<ScanProgressPayload | null>(null);
  const [activeTransport, setActiveTransport] = useState<'socket' | 'rest' | null>(null);
  const isScanning = scanSocket.scanning || scanning;
  const terminalLogs = activeTransport === 'rest' ? fallbackLogs : scanSocket.logs;
  const activeProgress = activeTransport === 'rest' ? fallbackProgress : scanSocket.progress;

  const [defenseState, setDefenseState] = useState<DefenseStateSnapshot>(EMPTY_DEFENSE_STATE);
  const [activatingShield, setActivatingShield] = useState(false);
  const [shieldNotice, setShieldNotice] = useState<string | null>(null);
  const [activeMatrixTab, setActiveMatrixTab] = useState<MatrixTab>('attackers');
  const [activeShieldId, setActiveShieldId] = useState<string>('');

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
    if (!activeShieldId && defenseState.protectedShields.length > 0) {
      setActiveShieldId(defenseState.protectedShields[0].id);
    }
  }, [activeShieldId, defenseState.protectedShields]);

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

  const applyScanResult = useCallback((report: TargetScanResult) => {
    setScanResult(report);
    if (report.attribution.length > 0) {
      setPinnedNode(report.attribution[0]);
      setSelectedNode(report.attribution[0]);
    }
  }, []);

  useEffect(() => {
    if (scanSocket.result) {
      applyScanResult(scanSocket.result);
      setScanError(null);
    }
  }, [scanSocket.result, applyScanResult]);

  useEffect(() => {
    if (scanSocket.error) setScanError(scanSocket.error);
  }, [scanSocket.error]);

  const effectiveGeo: ScanGeoPayload | null = useMemo(() => {
    if (scanSocket.geo) return scanSocket.geo;
    if (!scanResult) return null;
    const points = scanResult.attribution
      .filter(
        (node) =>
          Number.isFinite(node.lat) &&
          Number.isFinite(node.lon) &&
          !(node.lat === 0 && node.lon === 0),
      )
      .map((node) => ({
        ip: node.ip,
        label: `${node.city || 'Unknown'}, ${node.country || 'Unknown'}`,
        lat: node.lat,
        lon: node.lon,
        severity: node.severity,
        role: 'target' as const,
        city: node.city,
        country: node.country,
      }));
    if (points.length === 0) return null;
    return {
      target: scanResult.normalizedTarget,
      points,
      scanner: scanSocket.scannerOrigin
        ? {
            ip: scanSocket.scannerOrigin.ip,
            lat: scanSocket.scannerOrigin.lat,
            lon: scanSocket.scannerOrigin.lon,
            city: scanSocket.scannerOrigin.city,
            country: scanSocket.scannerOrigin.country,
          }
        : null,
    };
  }, [scanSocket.geo, scanSocket.scannerOrigin, scanResult]);

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
    setScanError(null);
    setShieldNotice(null);
    setFallbackLogs([]);
    setFallbackProgress(null);
    if (scrollToScanner) {
      scannerSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Preferred path: realtime Socket.io stream with live progress + terminal logs
    if (scanSocket.connected) {
      setActiveTransport('socket');
      scanSocket.startScan(clean);
      return;
    }

    // Fallback path: NDJSON streaming endpoint keeps the live terminal working without websockets
    setActiveTransport('rest');
    setScanning(true);
    try {
      const res = await fetch('/api/scan/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: clean }),
      });
      if (!res.ok || !res.body) {
        const payload = (await res.json().catch(() => ({}))) as { error?: string; details?: string };
        throw new Error(payload.details || payload.error || `Scan failed (HTTP ${res.status})`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line) as
            | ({ type: 'progress' } & ScanProgressPayload)
            | ({ type: 'log' } & ScanLogEvent)
            | { type: 'result'; report: TargetScanResult }
            | { type: 'error'; error: string };
          if (event.type === 'log') {
            setFallbackLogs((prev) => [...prev.slice(-499), event]);
          } else if (event.type === 'progress') {
            setFallbackProgress(event);
          } else if (event.type === 'result') {
            applyScanResult(event.report);
          } else if (event.type === 'error') {
            throw new Error(event.error);
          }
        }
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
          body: JSON.stringify({ ip, reason, assetId: activeShieldId || undefined }),
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
        const site = payload.entry.shieldHost;
        setShieldNotice(
          site
            ? `${ip} — ${site} ${lang === 'bn' ? 'সাইটে ব্লক রুল তৈরি হয়েছে' : 'block rule generated for site'}`
            : `${ip} — ${t.defendedBlockedBadge}`,
        );
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
      const payload = (await res.json().catch(() => null)) as
        | {
            state?: DefenseStateSnapshot;
            error?: string;
            verification?: { txtRecordHost: string; txtRecordValue: string; httpFilePath: string };
          }
        | null;
      if (res.ok && payload?.state) {
        setDefenseState(payload.state);
        setShieldNotice(t.scanner.shieldActivatedMsg);
        setActiveMatrixTab('defenseCenter');
      } else {
        const verification = payload?.verification;
        setShieldNotice(
          verification
            ? `${payload?.error ?? 'Ownership verification required.'} TXT: ${verification.txtRecordHost} = ${verification.txtRecordValue} · File: ${verification.httpFilePath}`
            : payload?.error ?? 'Shield activation failed.',
        );
      }
    } finally {
      setActivatingShield(false);
    }
  };

  const handleDeployShield = async (id: string) => {
    setActivatingShield(true);
    setShieldNotice(null);
    try {
      const res = await fetch(`/api/defense/shield/${encodeURIComponent(id)}/deploy`, {
        method: 'POST',
      });
      const payload = (await res.json().catch(() => null)) as
        | { detail?: string; error?: string; directory?: string }
        | null;
      setShieldNotice(
        res.ok
          ? `${lang === 'bn' ? 'রুল ফাইল তৈরি হয়েছে' : 'Rule files deployed'}: ${payload?.directory ?? ''}`
          : payload?.error ?? (lang === 'bn' ? 'ডিপ্লয় ব্যর্থ' : 'Deploy failed'),
      );
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

  const handleGridBlockIp = async (ip: string, reason: string) => {
    try {
      const res = await fetch('/api/defense/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason }),
      });
      if (res.ok) {
        const payload = (await res.json()) as { state: DefenseStateSnapshot };
        setDefenseState(payload.state);
        await defenseGrid.refresh();
      }
    } catch {
      // keep the grid state; the next poll will reconcile
    }
  };

  const handleGridAddSite = async (target: string) => {
    await handleActivateWebsiteShield(target);
    await defenseGrid.refresh();
  };

  const handleGridRecheckSite = async (id: string) => {
    await handleRecheckShield(id);
    await defenseGrid.refresh();
  };

  const handleGridRemoveSite = async (id: string) => {
    await handleRemoveShield(id);
    await defenseGrid.refresh();
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

            <button
              type="button"
              onClick={() => document.getElementById('global-cameras')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
              className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 sm:py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 text-[11px] sm:text-xs font-semibold hover:bg-cyan-500/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Camera className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">{lang === 'bn' ? 'ক্যামেরা' : 'Cameras'}</span>
            </button>

            <button
              type="button"
              onClick={() => document.getElementById('system-terminal')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
              className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 sm:py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-200 text-[11px] sm:text-xs font-semibold hover:bg-emerald-500/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <SquareTerminal className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">{lang === 'bn' ? 'টার্মিনাল' : 'Terminal'}</span>
            </button>

            <button
              type="button"
              onClick={() => setControlOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 sm:py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 text-[11px] sm:text-xs font-semibold hover:bg-cyan-500/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <SlidersHorizontal className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">
                {lang === 'bn' ? 'কন্ট্রোল সেন্টার' : 'Control Center'}
              </span>
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

            <SiteAgentDownloadButton lang={lang} />
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {radarError && (
          <div className="p-4 rounded-xl bg-red-950/50 border border-red-500/40 text-xs text-red-200">
            {radarError}
          </div>
        )}

        <EthicalBanner t={lab} />

        <LiveThreatMap
          t={lab}
          nodes={radar?.threatNodes ?? []}
          scanResult={scanResult}
          scanGeo={effectiveGeo}
          scannerOrigin={scanSocket.scannerOrigin}
          selectedNodeId={selectedNode?.id ?? null}
          blockedIps={blockedIpStrings}
          scanning={isScanning}
          loading={loadingRadar}
          onSelectNode={(node) => void handleSelectNode(node)}
        />

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

        {/* Global Defense Grid: real honeypot sensor, live attack stream, auto-defense */}
        <DefenseGrid
          t={defenseGridT}
          snapshot={defenseGrid.snapshot}
          incidents={radar?.incidents ?? []}
          loading={defenseGrid.loading}
          connected={defenseGrid.connected}
          latestAlert={defenseGrid.latestAlert}
          report={defenseGrid.report}
          busy={defenseGrid.busy}
          onRefresh={() => void defenseGrid.refresh()}
          onToggleAuto={(enabled) => void defenseGrid.setAutoDefense(enabled)}
          onAddSafeIp={(ip) => void defenseGrid.addSafeIp(ip)}
          onReportIp={(ip) => void defenseGrid.reportIp(ip)}
          onClearReport={defenseGrid.clearReport}
          onClearStream={() => void defenseGrid.clearStream()}
          onBlockIp={(ip, reason) => void handleGridBlockIp(ip, reason)}
          onAddSite={(target) => void handleGridAddSite(target)}
          onRecheckSite={(id) => void handleGridRecheckSite(id)}
          onRemoveSite={(id) => void handleGridRemoveSite(id)}
        />

        <GlobalExposureSection lang={lang} />

        <WebsiteNetworkSection
          lang={lang}
          onProtect={(site) => void handleActivateWebsiteShield(site)}
          protecting={activatingShield}
          notice={shieldNotice}
        />

        <section
          id="global-cameras"
          aria-label={lang === 'bn' ? 'ক্যামেরা সেকশন' : 'Camera section'}
          className="scroll-mt-24 space-y-3 border-t-2 border-cyan-500/30 pt-6"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-cyan-200">
              <Camera className="h-3 w-3" />
              {lang === 'bn' ? 'ক্যামেরা সেকশন' : 'Camera section'}
            </span>
            <span className="text-[10px] text-slate-500">
              {lang === 'bn'
                ? 'আলাদা ওএসআইএনটি সেকশন — শুধু পাবলিক ও অপারেটর-অনুমোদিত স্ট্রিম'
                : 'Separate OSINT section — public and operator-authorised streams only'}
            </span>
          </div>
          <GlobalCameraSection
            lang={lang}
            focus={
              selectedNode
                ? { lat: selectedNode.lat, lon: selectedNode.lon, label: `${selectedNode.ip} · ${selectedNode.city}` }
                : null
            }
          />
        </section>

        <SecurityStackPanel lang={lang} />

        <SystemTerminal lang={lang} />

        <AttackerDossierPanel
          lang={lang}
          initialIp={selectedNode?.ip}
          onBlocked={() => void fetchDefenseState()}
        />

        {/* Deep Target, IP Map Plotting & Website Defense Shield Scanner */}
        <div ref={scannerSectionRef} className="space-y-6">
          {/* Realtime Scan Lab: Progress + Live Terminal + Ownership Verification */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 space-y-6">
              <ScanProgressBar t={lab} progress={activeProgress} scanning={isScanning} />
              <LiveScanTerminal
                t={lab}
                logs={terminalLogs}
                connected={scanSocket.connected}
                scanning={isScanning}
                onClear={() => {
                  if (activeTransport === 'rest') {
                    setFallbackLogs([]);
                  } else {
                    scanSocket.clearLogs();
                  }
                }}
              />
            </div>
            <div className="xl:col-span-1">
              <DomainVerificationPanel
                t={lab}
                defaultDomain={scanResult?.normalizedTarget}
                onVerified={(domain) => {
                  setShieldNotice(`Ownership verified for ${domain}. Active modules unlocked.`);
                  void handleScanTarget(domain, false);
                }}
              />
            </div>
          </div>

          <TargetScannerPanel
            t={t}
            lang={lang}
            scanResult={scanResult}
            scanning={isScanning}
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

        <SeverityCharts
          t={lab}
          riskCounts={scanResult?.riskCounts ?? null}
          portScan={scanResult?.portScan ?? null}
          techStack={scanResult?.techStack ?? null}
          excludedCves={scanResult?.excludedCves ?? null}
        />

        {/* Ultra-Deep Picture Forensics, Device, Location & Embedded IP Lab */}
        <ImageForensicsPanel
          t={t}
          lang={lang}
          onPinNodeOnMap={handleFocusNodeOnMap}
          onDefendIp={(ip, reason) => void handleDefendIp(ip, reason)}
        />

        {/* 4 Command Sections: Active Attackers | Phishing Takedowns | Global Threats | Defense & System Shields */}
        <div ref={matrixSectionRef}>
          {defenseState.protectedShields.length > 0 && (
            <div className="soc-panel mb-3 flex flex-wrap items-center gap-2 rounded-xl px-3 py-2">
              <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                {lang === 'bn' ? 'সুরক্ষিত সাইটের জন্য ব্লক' : 'Block for protected site'}
              </span>
              <select
                value={activeShieldId}
                onChange={(event) => setActiveShieldId(event.target.value)}
                className="rounded-lg border border-slate-700 bg-[#04060A] px-2 py-1 text-[11px] text-slate-100"
              >
                {defenseState.protectedShields.map((shield) => (
                  <option key={shield.id} value={shield.id}>
                    {shield.host}
                  </option>
                ))}
                <option value="">{lang === 'bn' ? 'শুধু এই কন্ট্রোল প্লেন' : 'Control plane only'}</option>
              </select>
              <span className="text-[10px] text-slate-500">
                {lang === 'bn'
                  ? 'এই সাইটের ফায়ারওয়াল/WAF-এ রুল তৈরি হবে; আমাদের সার্ভারে নয়।'
                  : 'Rules target this site’s firewall/WAF, not our server.'}
              </span>
            </div>
          )}
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
            onDeployShield={(id) => void handleDeployShield(id)}
          />
        </div>

        <SentinelAgentBadge lang={lang} />

        <ControlCenter
          open={controlOpen}
          onClose={() => setControlOpen(false)}
          lang={lang}
          user={auth.status?.user ?? null}
          onLogout={() => void auth.logout()}
          autoDefense={defenseGrid.snapshot?.stats.autoDefenseEnabled ?? true}
          onToggleAutoDefense={(enabled) => void defenseGrid.setAutoDefense(enabled)}
        />
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AuthGate>
        <AppDashboard />
      </AuthGate>
    </AuthProvider>
  );
}
