import {
  Activity,
  BadgeAlert,
  Check,
  Clipboard,
  Copy,
  Loader2,
  Lock,
  Radio,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldPlus,
  Siren,
  Trash2,
  Zap,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import type { CyberIncident } from '../types/cyber.ts';
import type { AttackEvent, DefenseGridSnapshot } from '../types/defenseGrid.ts';
import type { DefenseGridTranslations } from '../i18n/defenseGridTranslations.ts';

interface DefenseGridProps {
  t: DefenseGridTranslations;
  snapshot: DefenseGridSnapshot | null;
  incidents: CyberIncident[];
  loading: boolean;
  connected: boolean;
  latestAlert: AttackEvent | null;
  report: string | null;
  busy: boolean;
  onRefresh: () => void;
  onToggleAuto: (enabled: boolean) => void;
  onAddSafeIp: (ip: string) => void;
  onReportIp: (ip: string) => void;
  onClearReport: () => void;
  onClearStream: () => void;
  onBlockIp: (ip: string, reason: string) => void;
  onAddSite: (target: string) => void;
  onRecheckSite: (id: string) => void;
  onRemoveSite: (id: string) => void;
}

type Filter = 'all' | 'sensor' | 'feed' | 'blocked';

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function isIp(value: string): boolean {
  return IPV4.test(value) && value.split('.').every((part) => Number(part) <= 255);
}

function timeOf(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '--:--:--' : date.toISOString().slice(11, 19);
}

function severityDot(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]';
    case 'HIGH':
      return 'bg-orange-500';
    case 'ELEVATED':
      return 'bg-amber-400';
    default:
      return 'bg-emerald-400';
  }
}

function actionClass(action: string): string {
  switch (action) {
    case 'blocked':
      return 'bg-red-500/15 border-red-500/40 text-red-200';
    case 'tarpitted':
      return 'bg-amber-500/15 border-amber-500/40 text-amber-200';
    case 'reported':
      return 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200';
    default:
      return 'bg-slate-800/60 border-slate-700 text-slate-300';
  }
}

function categoryClass(category: string): string {
  switch (category) {
    case 'ddos':
    case 'rce':
    case 'sqli':
      return 'bg-red-500/10 border-red-500/30 text-red-200';
    case 'xss':
    case 'path-traversal':
    case 'credential-stuffing':
      return 'bg-orange-500/10 border-orange-500/30 text-orange-200';
    case 'botnet-c2':
    case 'phishing':
      return 'bg-fuchsia-500/10 border-fuchsia-500/30 text-fuchsia-200';
    default:
      return 'bg-cyan-500/10 border-cyan-500/30 text-cyan-200';
  }
}

export function DefenseGrid({
  t,
  snapshot,
  incidents,
  loading,
  connected,
  latestAlert,
  report,
  busy,
  onRefresh,
  onToggleAuto,
  onAddSafeIp,
  onReportIp,
  onClearReport,
  onClearStream,
  onBlockIp,
  onAddSite,
  onRecheckSite,
  onRemoveSite,
}: DefenseGridProps) {
  const [filter, setFilter] = useState<Filter>('all');
  const [siteInput, setSiteInput] = useState('');
  const [safeIpInput, setSafeIpInput] = useState('');
  const [copied, setCopied] = useState(false);
  const [showAlert, setShowAlert] = useState(false);

  useEffect(() => {
    if (!latestAlert) return;
    setShowAlert(true);
    const timer = setTimeout(() => setShowAlert(false), 20_000);
    return () => clearTimeout(timer);
  }, [latestAlert]);

  const events = snapshot?.events ?? [];
  const filtered = useMemo(() => {
    if (filter === 'all') return events;
    if (filter === 'blocked') return events.filter((event) => event.action === 'blocked');
    return events.filter((event) => event.source === filter);
  }, [events, filter]);

  const stats = snapshot?.stats;
  const autoDefense = stats?.autoDefenseEnabled ?? true;
  const protectedSites = snapshot?.protectedSites ?? [];
  const topAttackers = snapshot?.topAttackers ?? [];

  const copyReport = async () => {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard can be blocked
    }
  };

  return (
    <section aria-label={t.title} className="defense-grid soc-panel rounded-xl overflow-hidden">
      <div className="defense-grid-header p-4 sm:p-5 border-b border-slate-800/80">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" aria-hidden="true" />
              <h2 className="text-base sm:text-lg font-bold text-slate-50">{t.title}</h2>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/30 text-[10px] font-semibold text-red-300">
                <span className={`w-1.5 h-1.5 rounded-full bg-red-400 ${showAlert ? 'animate-ping' : ''}`} />
                {t.live}
              </span>
              <span
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-semibold ${
                  connected
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                }`}
              >
                <Radio className="w-3 h-3" aria-hidden="true" />
                {connected ? t.sensorOnline : t.sensorOffline}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-4xl">{t.subtitle}</p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onToggleAuto(!autoDefense)}
              disabled={busy}
              role="switch"
              aria-checked={autoDefense}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-[11px] font-semibold transition-colors cursor-pointer ${
                autoDefense
                  ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
                  : 'bg-[#06090F] border-slate-700 text-slate-400'
              }`}
            >
              <span
                className={`relative w-8 h-4 rounded-full transition-colors ${
                  autoDefense ? 'bg-emerald-500/70' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                    autoDefense ? 'translate-x-4' : ''
                  }`}
                />
              </span>
              {autoDefense ? t.autoDefenseOn : t.autoDefenseOff}
            </button>
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#06090F] border border-slate-700 text-slate-300 text-[11px] font-semibold hover:border-slate-500 transition-colors cursor-pointer disabled:opacity-60"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
              {t.refresh}
            </button>
          </div>
        </div>

        {showAlert && latestAlert && (
          <div className="mt-4 flex items-start gap-3 rounded-lg border border-red-500/50 bg-red-950/40 p-3 defense-alert">
            <Siren className="w-5 h-5 text-red-400 shrink-0 animate-pulse" aria-hidden="true" />
            <div className="min-w-0">
              <div className="text-xs font-bold text-red-200">{t.alertTitle}</div>
              <div className="text-[11px] text-red-100/90 break-words">
                {t.alertBody(latestAlert.ip, t.categoryLabels[latestAlert.category] ?? latestAlert.category)}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 lg:divide-x divide-slate-800/80 border-b border-slate-800/80">
        <div className="p-4">
          <div className="text-[11px] text-slate-400">{t.statEvents}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-50">
            {(stats?.totalEvents ?? 0).toLocaleString('en-US')}
          </div>
        </div>
        <div className="p-4">
          <div className="text-[11px] text-slate-400">{t.statBlocked}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-red-400">
            {(stats?.blocked ?? 0).toLocaleString('en-US')}
          </div>
        </div>
        <div className="p-4">
          <div className="text-[11px] text-slate-400">{t.statAttackers}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-orange-400">
            {(stats?.uniqueAttackers ?? 0).toLocaleString('en-US')}
          </div>
        </div>
        <div className="p-4">
          <div className="text-[11px] text-slate-400">{t.statSensorRequests}</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-cyan-400">
            {(stats?.sensorRequests ?? 0).toLocaleString('en-US')}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 p-4 sm:p-5">
        <div className="xl:col-span-2 space-y-5">
          <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" aria-hidden="true" />
                  <h3 className="text-sm font-bold text-slate-100">{t.streamTitle}</h3>
                </div>
                <p className="text-[10px] text-slate-500">{t.streamSubtitle}</p>
              </div>
              <div className="flex items-center gap-1">
                {(['all', 'sensor', 'feed', 'blocked'] as Filter[]).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setFilter(value)}
                    className={`px-2 py-1 rounded-md border text-[10px] font-semibold transition-colors cursor-pointer ${
                      filter === value
                        ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200'
                        : 'bg-[#0B101B] border-slate-700 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {value === 'all'
                      ? t.filterAll
                      : value === 'sensor'
                        ? t.filterSensor
                        : value === 'feed'
                          ? t.filterFeed
                          : t.filterBlocked}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={onClearStream}
                  disabled={busy}
                  className="ml-1 inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-700 text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer disabled:opacity-60"
                >
                  <Trash2 className="w-3 h-3" aria-hidden="true" />
                  {t.clear}
                </button>
              </div>
            </div>

            <div className="max-h-[430px] overflow-y-auto divide-y divide-slate-800/70">
              {filtered.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">{t.emptyStream}</div>
              ) : (
                filtered.slice(0, 80).map((event) => {
                  const blocked = event.action === 'blocked';
                  return (
                    <div key={event.id} className="px-3 py-2.5 flex items-start gap-2.5 hover:bg-slate-900/40">
                      <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${severityDot(event.severity)}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-[11px] text-slate-100">{event.ip}</span>
                          <span className={`px-1.5 py-0.5 rounded border text-[9px] font-semibold ${categoryClass(event.category)}`}>
                            {t.categoryLabels[event.category] ?? event.category}
                          </span>
                          <span className="px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800/50 text-[9px] text-slate-400">
                            {event.source === 'sensor' ? t.sourceSensor : t.sourceFeed}
                          </span>
                          <span className={`px-1.5 py-0.5 rounded border text-[9px] font-semibold ${actionClass(event.action)}`}>
                            {event.action === 'blocked'
                              ? t.actionBlocked
                              : event.action === 'tarpitted'
                                ? t.actionTarpitted
                                : event.action === 'reported'
                                  ? t.actionReported
                                  : t.actionObserved}
                          </span>
                          <span className="ml-auto text-[9px] text-slate-500 tabular-nums">{timeOf(event.ts)}</span>
                        </div>
                        <div className="mt-0.5 text-[10px] text-slate-400 truncate">
                          {event.method} {event.path}
                        </div>
                        <div className="text-[10px] text-slate-500 truncate">
                          {event.detail}
                          {event.city ? ` · ${event.city}, ${event.country ?? ''}` : ''}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1 shrink-0">
                        {isIp(event.ip) && !blocked && (
                          <button
                            type="button"
                            onClick={() => onBlockIp(event.ip, event.detail)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-500/40 bg-red-500/10 text-[9px] font-semibold text-red-200 hover:bg-red-500/20 cursor-pointer"
                          >
                            <Lock className="w-3 h-3" aria-hidden="true" />
                            {t.block}
                          </button>
                        )}
                        {isIp(event.ip) && (
                          <button
                            type="button"
                            onClick={() => onReportIp(event.ip)}
                            disabled={busy}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/10 text-[9px] font-semibold text-cyan-200 hover:bg-cyan-500/20 cursor-pointer disabled:opacity-60"
                          >
                            <Clipboard className="w-3 h-3" aria-hidden="true" />
                            {t.report}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 p-3">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-orange-400" aria-hidden="true" />
                <h3 className="text-xs font-bold text-slate-100">{t.topAttackersTitle}</h3>
              </div>
              {topAttackers.length === 0 ? (
                <div className="text-[10px] text-slate-500">{t.topAttackersEmpty}</div>
              ) : (
                <div className="space-y-1.5">
                  {topAttackers.slice(0, 8).map((attacker) => (
                    <div key={attacker.ip} className="flex items-center gap-2 text-[10px]">
                      <span className={`w-1.5 h-1.5 rounded-full ${severityDot(attacker.severity)}`} />
                      <span className="font-mono text-slate-200 truncate flex-1">{attacker.ip}</span>
                      <span className="text-slate-500">{t.categoryLabels[attacker.category] ?? attacker.category}</span>
                      <span className="font-mono text-orange-300 tabular-nums">{attacker.count}</span>
                      {attacker.blocked ? (
                        <span className="text-emerald-300 inline-flex items-center gap-0.5">
                          <Check className="w-3 h-3" aria-hidden="true" />
                        </span>
                      ) : isIp(attacker.ip) ? (
                        <button
                          type="button"
                          onClick={() => onBlockIp(attacker.ip, `${attacker.category} from defense grid`)}
                          className="text-red-300 hover:text-red-200 cursor-pointer"
                        >
                          {t.block}
                        </button>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 p-3">
              <div className="flex items-center gap-2 mb-2">
                <BadgeAlert className="w-4 h-4 text-amber-400" aria-hidden="true" />
                <h3 className="text-xs font-bold text-slate-100">{t.incidentsTitle}</h3>
              </div>
              <p className="text-[10px] text-slate-500 mb-2">{t.incidentsSubtitle}</p>
              {incidents.length === 0 ? (
                <div className="text-[10px] text-slate-500">{t.incidentsEmpty}</div>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {incidents.slice(0, 8).map((incident) => (
                    <a
                      key={incident.id}
                      href={incident.url}
                      target="_blank"
                      rel="noreferrer"
                      className="block rounded-md border border-slate-800 bg-[#0B101B] p-2 hover:border-amber-500/40 transition-colors"
                    >
                      <div className="text-[10px] font-semibold text-slate-200 line-clamp-2">{incident.title}</div>
                      <div className="text-[9px] text-slate-500 mt-0.5">
                        {incident.source} · {new Date(incident.publishedAt).toLocaleString()}
                      </div>
                    </a>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="space-y-5">
          <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 p-3">
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              <h3 className="text-xs font-bold text-slate-100">{t.sitesTitle}</h3>
            </div>
            <p className="text-[10px] text-slate-500 mb-2">{t.sitesSubtitle}</p>

            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (siteInput.trim().length < 3) return;
                onAddSite(siteInput.trim());
                setSiteInput('');
              }}
              className="flex gap-1.5"
            >
              <input
                value={siteInput}
                onChange={(event) => setSiteInput(event.target.value)}
                placeholder={t.addSitePlaceholder}
                className="flex-1 min-w-0 rounded-lg bg-[#04060A] border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
              />
              <button
                type="submit"
                disabled={busy}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-[10px] font-semibold text-emerald-200 hover:bg-emerald-500/25 cursor-pointer disabled:opacity-60"
              >
                <ShieldPlus className="w-3.5 h-3.5" aria-hidden="true" />
                {t.addSite}
              </button>
            </form>
            <p className="text-[9px] text-slate-500 mt-1">{t.addSiteNote}</p>

            <div className="mt-3 space-y-2 max-h-56 overflow-y-auto pr-1">
              {protectedSites.length === 0 ? (
                <div className="text-[10px] text-slate-500">{t.sitesEmpty}</div>
              ) : (
                protectedSites.map((site) => (
                  <div key={site.id} className="rounded-lg border border-slate-800 bg-[#0B101B] p-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[10px] text-slate-100 truncate">{site.host}</span>
                      <span
                        className={`px-1.5 py-0.5 rounded border text-[9px] font-semibold ${
                          site.status === 'alert'
                            ? 'bg-red-500/10 border-red-500/40 text-red-200'
                            : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
                        }`}
                      >
                        {site.status === 'alert' ? t.statusAlert : t.statusShielded}
                      </span>
                    </div>
                    <div className="text-[9px] text-slate-500 mt-0.5">
                      {site.verdict} · TLS {site.tlsValid === false ? 'FAIL' : site.tlsValid ? 'OK' : 'N/A'} ·{' '}
                      {site.missingHeadersCount} headers · {t.lastChecked}: {timeOf(site.lastCheckedAt)}
                    </div>
                    {site.alertReason ? (
                      <div className="text-[9px] text-red-300 mt-0.5 line-clamp-2">{site.alertReason}</div>
                    ) : (
                      <div className="text-[9px] text-slate-600 mt-0.5">{t.noAlert}</div>
                    )}
                    <div className="flex gap-1.5 mt-1.5">
                      <button
                        type="button"
                        onClick={() => onRecheckSite(site.id)}
                        disabled={busy}
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-slate-700 text-[9px] text-slate-300 hover:border-cyan-500/40 cursor-pointer disabled:opacity-60"
                      >
                        <RefreshCw className="w-2.5 h-2.5" aria-hidden="true" />
                        {t.recheck}
                      </button>
                      <button
                        type="button"
                        onClick={() => onRemoveSite(site.id)}
                        disabled={busy}
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-slate-700 text-[9px] text-slate-400 hover:text-red-300 cursor-pointer disabled:opacity-60"
                      >
                        <Trash2 className="w-2.5 h-2.5" aria-hidden="true" />
                        {t.remove}
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Lock className="w-4 h-4 text-cyan-400" aria-hidden="true" />
              <h3 className="text-xs font-bold text-slate-100">{t.addSafeIp}</h3>
            </div>
            <p className="text-[9px] text-slate-500 mb-2">{t.safeIpNote}</p>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (!isIp(safeIpInput.trim())) return;
                onAddSafeIp(safeIpInput.trim());
                setSafeIpInput('');
              }}
              className="flex gap-1.5"
            >
              <input
                value={safeIpInput}
                onChange={(event) => setSafeIpInput(event.target.value)}
                placeholder={t.safeIpPlaceholder}
                className="flex-1 min-w-0 rounded-lg bg-[#04060A] border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
              />
              <button
                type="submit"
                disabled={busy}
                className="px-2.5 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-[10px] font-semibold text-cyan-200 hover:bg-cyan-500/25 cursor-pointer disabled:opacity-60"
              >
                {t.addSafeIp}
              </button>
            </form>
            <div className="flex flex-wrap gap-1 mt-2">
              {(stats?.safeIps ?? []).map((ip) => (
                <span key={ip} className="px-1.5 py-0.5 rounded bg-slate-800/60 border border-slate-700 text-[9px] font-mono text-slate-300">
                  {ip}
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-[#06090F]/70 p-3">
            <div className="flex items-center justify-between gap-2 mb-1">
              <div className="flex items-center gap-2">
                <Copy className="w-4 h-4 text-fuchsia-400" aria-hidden="true" />
                <h3 className="text-xs font-bold text-slate-100">{t.abuseReportTitle}</h3>
              </div>
              {report && (
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={() => void copyReport()}
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-slate-700 text-[9px] text-slate-300 hover:border-fuchsia-500/40 cursor-pointer"
                  >
                    {copied ? <Check className="w-2.5 h-2.5" aria-hidden="true" /> : <Copy className="w-2.5 h-2.5" aria-hidden="true" />}
                    {copied ? t.copied : t.copy}
                  </button>
                  <button
                    type="button"
                    onClick={onClearReport}
                    className="px-1.5 py-0.5 rounded border border-slate-700 text-[9px] text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {t.close}
                  </button>
                </div>
              )}
            </div>
            {report ? (
              <pre className="max-h-48 overflow-auto rounded-lg bg-[#04060A] border border-slate-800 p-2 text-[9px] leading-relaxed text-slate-300 whitespace-pre-wrap">
                {report}
              </pre>
            ) : (
              <p className="text-[10px] text-slate-500">{t.abuseReportEmpty}</p>
            )}
          </div>
        </div>
      </div>

      {loading && !snapshot && (
        <div className="px-4 pb-4 text-[10px] text-slate-500 inline-flex items-center gap-2">
          <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
          {t.refresh}
        </div>
      )}
    </section>
  );
}
