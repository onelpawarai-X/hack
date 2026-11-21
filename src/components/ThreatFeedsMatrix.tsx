import {
  Check,
  Copy,
  Crosshair,
  Download,
  ExternalLink,
  Mail,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useState } from 'react';
import type { CyberTranslations } from '../i18n/cyberTranslations';
import type {
  CyberIncident,
  DefenseStateSnapshot,
  ExploitedCve,
  FeedHealthItem,
  Language,
  PhishingTrap,
  ThreatNode,
} from '../types/cyber';
import { formatShortDate, formatUtcTimestamp } from '../utils/formatters';

export type MatrixTab = 'attackers' | 'phishing' | 'globalThreats' | 'defenseCenter';

interface ThreatFeedsMatrixProps {
  t: CyberTranslations;
  lang: Language;
  activeTab: MatrixTab;
  onChangeTab: (tab: MatrixTab) => void;
  threatNodes: ThreatNode[];
  phishingTraps: PhishingTrap[];
  incidents: CyberIncident[];
  webScanHighlights: CyberIncident[];
  cves: ExploitedCve[];
  feedHealth: FeedHealthItem[];
  defenseState: DefenseStateSnapshot;
  selectedNodeId: string | null;
  onSelectNode: (node: ThreatNode) => void;
  onDefendAttacker: (node: ThreatNode) => void;
  onTakedownPhishing: (trap: PhishingTrap) => void;
  onScanTarget: (target: string) => void;
  onUnblockIp: (ip: string) => void;
  onRemoveSinkhole: (domain: string) => void;
  onRecheckShield: (id: string) => void;
  onRemoveShield: (id: string) => void;
  onDeployShield: (id: string) => void;
}

export function ThreatFeedsMatrix({
  t,
  lang,
  activeTab,
  onChangeTab,
  threatNodes,
  phishingTraps,
  incidents,
  webScanHighlights,
  cves,
  feedHealth,
  defenseState,
  selectedNodeId,
  onSelectNode,
  onDefendAttacker,
  onTakedownPhishing,
  onScanTarget,
  onUnblockIp,
  onRemoveSinkhole,
  onRecheckShield,
  onRemoveShield,
  onDeployShield,
}: ThreatFeedsMatrixProps) {
  const [filterQuery, setFilterQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const q = filterQuery.trim().toLowerCase();
  const blockedIpSet = new Set(defenseState.blockedIps.map((b) => b.ip));
  const sinkholedDomainSet = new Set(defenseState.blockedDomains.map((d) => d.domain));

  const copyText = (key: string, text: string) => {
    void navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
  };

  const filteredNodes = threatNodes.filter((n) => {
    if (!q) return true;
    return (
      n.ip.toLowerCase().includes(q) ||
      n.country.toLowerCase().includes(q) ||
      n.city.toLowerCase().includes(q) ||
      n.asn.toLowerCase().includes(q) ||
      n.isp.toLowerCase().includes(q) ||
      n.threatType.toLowerCase().includes(q)
    );
  });

  const filteredPhish = phishingTraps.filter((p) => {
    if (!q) return true;
    return (
      p.url.toLowerCase().includes(q) ||
      p.host.toLowerCase().includes(q) ||
      p.riskReasons.some((r) => r.toLowerCase().includes(q))
    );
  });

  const combinedGlobalIncidents = [...webScanHighlights, ...incidents].filter((item) => {
    if (!q) return true;
    return (
      item.title.toLowerCase().includes(q) ||
      item.source.toLowerCase().includes(q) ||
      item.summary.toLowerCase().includes(q)
    );
  });

  const filteredCves = cves.filter((c) => {
    if (!q) return true;
    return (
      c.cveID.toLowerCase().includes(q) ||
      c.vendorProject.toLowerCase().includes(q) ||
      c.product.toLowerCase().includes(q) ||
      c.vulnerabilityName.toLowerCase().includes(q)
    );
  });

  const totalDefenseCount =
    defenseState.protectedShields.length +
    defenseState.blockedIps.length +
    defenseState.blockedDomains.length;

  const globalThreatsCount = webScanHighlights.length + incidents.length + cves.length;

  return (
    <section aria-label={t.tabs.attackers} className="soc-panel rounded-xl overflow-hidden">
      {/* Header + 4 Command Sections Tabs + Search */}
      <div className="p-4 sm:p-5 border-b border-slate-800/80 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div
          role="tablist"
          aria-label="Cyber defense and threat sections"
          className="flex flex-wrap items-center gap-1.5 p-1 rounded-lg bg-[#05070B] border border-slate-800/90"
        >
          {(
            [
              { id: 'attackers', label: `${t.tabs.attackers} (${threatNodes.length})` },
              { id: 'phishing', label: `${t.tabs.phishing} (${phishingTraps.length})` },
              { id: 'globalThreats', label: `${t.tabs.globalThreats} (${globalThreatsCount})` },
              { id: 'defenseCenter', label: `${t.tabs.defenseCenter} (${totalDefenseCount})` },
            ] as Array<{ id: MatrixTab; label: string }>
          ).map((tab) => {
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onChangeTab(tab.id)}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? tab.id === 'phishing'
                      ? 'bg-red-600 text-white'
                      : tab.id === 'defenseCenter'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-100'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        <div className="relative w-full lg:w-72">
          <label htmlFor="threat-matrix-filter" className="sr-only">
            {t.tables.filterPlaceholder}
          </label>
          <Search
            className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
            aria-hidden="true"
          />
          <input
            id="threat-matrix-filter"
            type="text"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            placeholder={t.tables.filterPlaceholder}
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#05070B] border border-slate-800 focus:border-slate-600 focus:outline-none text-xs text-slate-100 placeholder:text-slate-500"
          />
        </div>
      </div>

      {/* Section 1: Active Attacker Nodes + One-Click Defend */}
      {activeTab === 'attackers' && (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800/80 text-slate-400 bg-slate-950/40">
                <th className="py-2.5 px-4 font-medium">{t.tables.ipAddress}</th>
                <th className="py-2.5 px-4 font-medium">{t.tables.threatType}</th>
                <th className="py-2.5 px-4 font-medium">{t.tables.originLocation}</th>
                <th className="py-2.5 px-4 font-medium">{t.tables.asnIsp}</th>
                <th className="py-2.5 px-4 font-medium">{t.tables.sourceFeed}</th>
                <th className="py-2.5 px-4 font-medium text-right">{t.tables.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredNodes.map((node) => {
                const isSelected = node.id === selectedNodeId;
                const isCritical = node.severity === 'CRITICAL';
                const isBlocked = blockedIpSet.has(node.ip);
                return (
                  <tr
                    key={node.id}
                    className={`transition-colors ${
                      isSelected ? 'bg-red-950/35' : 'hover:bg-slate-900/55'
                    }`}
                  >
                    <td className="py-2.5 px-4 font-mono tabular-nums whitespace-nowrap">
                      <span
                        className={
                          isBlocked
                            ? 'text-emerald-400 font-semibold'
                            : isCritical
                              ? 'text-red-400 font-semibold'
                              : 'text-orange-300 font-semibold'
                        }
                      >
                        {node.ip}
                      </span>
                      {node.port ? (
                        <span className="text-slate-400">:{node.port}</span>
                      ) : null}
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 max-w-[230px] truncate">
                      {node.threatType}
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 whitespace-nowrap">
                      {node.city}, {node.country} ({node.countryCode})
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-[240px] truncate">
                      <span className="font-mono text-slate-300">{node.asn}</span> · {node.isp}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 whitespace-nowrap">
                      {node.sourceFeed}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap space-x-2">
                      <button
                        type="button"
                        onClick={() => onSelectNode(node)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:border-sky-500/50 text-slate-200 cursor-pointer"
                      >
                        <Crosshair className="w-3 h-3 text-sky-400" aria-hidden="true" />
                        <span>{t.tables.traceOnRadar}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => onDefendAttacker(node)}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded font-semibold cursor-pointer ${
                          isBlocked
                            ? 'bg-emerald-950/80 border border-emerald-500/50 text-emerald-300'
                            : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                        }`}
                      >
                        <ShieldCheck className="w-3 h-3" aria-hidden="true" />
                        <span>{isBlocked ? t.tables.defendedBadge : t.tables.defendNow}</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Section 2: Live Phishing & Trap URLs + Takedown & Sinkhole */}
      {activeTab === 'phishing' && (
        <div className="p-4 sm:p-5 space-y-3">
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/35 text-xs text-red-200 flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" aria-hidden="true" />
            <span>{t.tables.phishWarningNote}</span>
          </div>

          <div className="divide-y divide-slate-800/70">
            {filteredPhish.map((trap) => {
              const isSinkholed = sinkholedDomainSet.has(trap.host.toLowerCase());
              return (
                <div
                  key={trap.id}
                  className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="min-w-0 space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-bold text-red-400">
                        {t.severityLabels[trap.severity]}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="font-mono text-slate-300">{trap.host}</span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">{trap.sourceFeed}</span>
                    </div>
                    <div className="font-mono text-xs text-red-200/90 break-all">
                      {trap.url}
                    </div>
                    <div className="text-xs text-slate-400">
                      {trap.riskReasons.join(' · ')}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => onScanTarget(trap.url)}
                      className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-red-500/50 text-slate-200 text-xs font-medium whitespace-nowrap cursor-pointer"
                    >
                      {t.tables.inspectSafely}
                    </button>
                    <button
                      type="button"
                      onClick={() => onTakedownPhishing(trap)}
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap cursor-pointer ${
                        isSinkholed
                          ? 'bg-emerald-950/80 border border-emerald-500/50 text-emerald-300'
                          : 'bg-red-600 hover:bg-red-500 text-white'
                      }`}
                    >
                      <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>
                        {isSinkholed ? t.tables.sinkholedBadge : t.tables.takedownDomainBtn}
                      </span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Section 3: Global Threats (Threat Actors, Attacks, Campaigns + Exploited CVEs) */}
      {activeTab === 'globalThreats' && (
        <div className="divide-y divide-slate-800/70 px-4 sm:px-5">
          {combinedGlobalIncidents.map((item) => {
            const isCrit = item.severity === 'CRITICAL';
            return (
              <article
                key={item.id}
                className="py-4 flex flex-col sm:flex-row sm:items-start justify-between gap-3"
              >
                <div className="min-w-0 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span
                      className={`font-bold ${
                        isCrit
                          ? 'text-red-400'
                          : item.severity === 'HIGH'
                            ? 'text-orange-400'
                            : 'text-amber-300'
                      }`}
                    >
                      {t.severityLabels[item.severity]}
                    </span>
                    <span aria-hidden="true" className="text-slate-600">
                      ·
                    </span>
                    <span className="text-slate-300 font-medium">{item.source}</span>
                    {item.publishedAt && (
                      <>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="font-mono tabular-nums text-slate-400">
                          {formatShortDate(item.publishedAt)}
                        </span>
                      </>
                    )}
                  </div>
                  <h3 className="text-sm font-semibold text-slate-100 leading-snug">
                    {item.title}
                  </h3>
                  {item.summary && (
                    <p className="text-xs text-slate-400 line-clamp-2 max-w-4xl">
                      {item.summary}
                    </p>
                  )}

                  {item.extractedTargets.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      {item.extractedTargets.map((target) => (
                        <button
                          key={target}
                          type="button"
                          onClick={() => onScanTarget(target)}
                          className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 hover:border-emerald-400 text-[11px] font-mono text-emerald-200 cursor-pointer"
                        >
                          <ShieldCheck className="w-3 h-3" aria-hidden="true" />
                          <span>
                            {t.tables.countermeasureBtn}: {target}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() =>
                      onScanTarget(item.extractedTargets[0] || item.title.slice(0, 48))
                    }
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold whitespace-nowrap cursor-pointer"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>{t.tables.countermeasureBtn}</span>
                  </button>
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-xs font-medium text-slate-200 whitespace-nowrap"
                  >
                    <span>{t.tables.openReport}</span>
                    <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  </a>
                </div>
              </article>
            );
          })}

          {filteredCves.map((cve) => (
            <div
              key={cve.cveID}
              className="py-3.5 flex flex-col sm:flex-row sm:items-start justify-between gap-3"
            >
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono font-bold text-red-400">{cve.cveID}</span>
                  <span aria-hidden="true" className="text-slate-600">
                    ·
                  </span>
                  <span className="text-slate-200 font-medium">
                    {cve.vendorProject} / {cve.product}
                  </span>
                  <span aria-hidden="true" className="text-slate-600">
                    ·
                  </span>
                  <span
                    className={
                      cve.knownRansomware ? 'text-red-400 font-semibold' : 'text-amber-300'
                    }
                  >
                    {cve.knownRansomware ? t.tables.ransomwareLinked : t.tables.standardCve}
                  </span>
                  <span aria-hidden="true" className="text-slate-600">
                    ·
                  </span>
                  <span className="font-mono tabular-nums text-slate-400">
                    {t.tables.addedDate}: {cve.dateAdded}
                  </span>
                </div>
                <div className="text-sm font-semibold text-slate-100">
                  {cve.vulnerabilityName}
                </div>
                <p className="text-xs text-slate-400 max-w-4xl leading-relaxed">
                  {cve.shortDescription}
                </p>
              </div>

              <button
                type="button"
                onClick={() => onScanTarget(cve.cveID)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-red-500/50 text-xs font-medium text-slate-200 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                <span>{t.tables.countermeasureBtn}</span>
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Section 4: Active Defense Shields, Blocked Attackers, Sinkholes & Production Rules */}
      {activeTab === 'defenseCenter' && (
        <div className="p-4 sm:p-6 space-y-6 text-xs">
          <p className="text-slate-300">{t.defense.subtitle}</p>

          {/* 4A: Protected Website Watchdogs */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              <span>
                {t.defense.protectedWebsitesTitle} ({defenseState.protectedShields.length})
              </span>
            </h3>
            {defenseState.protectedShields.length > 0 ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {defenseState.protectedShields.map((shield) => (
                  <div
                    key={shield.id}
                    className={`p-4 rounded-xl border space-y-3 ${
                      shield.status === 'alert'
                        ? 'bg-amber-950/25 border-amber-500/40'
                        : 'bg-emerald-950/20 border-emerald-500/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="font-mono font-bold text-sm text-white break-all">
                          {shield.host}
                        </div>
                        <div
                          className={`font-semibold mt-0.5 ${
                            shield.status === 'alert' ? 'text-amber-300' : 'text-emerald-400'
                          }`}
                        >
                          {shield.status === 'alert'
                            ? t.defense.statusAlert
                            : t.defense.statusShielded}
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          type="button"
                          onClick={() => onRecheckShield(shield.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:border-emerald-500/50 text-slate-200 cursor-pointer"
                        >
                          <RefreshCw className="w-3 h-3" aria-hidden="true" />
                          <span>{t.defense.recheckBtn}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => onDeployShield(shield.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-700 hover:border-cyan-500/50 text-slate-200 cursor-pointer"
                        >
                          <Download className="w-3 h-3" aria-hidden="true" />
                          <span>{lang === 'bn' ? 'রুল ডিপ্লয়' : 'Deploy rules'}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => onRemoveShield(shield.id)}
                          aria-label={t.defense.removeBtn}
                          className="p-1.5 rounded bg-slate-900 border border-slate-700 hover:border-red-500/50 text-slate-400 hover:text-red-300 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>

                    <div className="font-mono text-[11px] text-slate-300 space-y-1">
                      <div>
                        TLS: {shield.tlsValid ? 'Valid' : 'Invalid'}{' '}
                        {typeof shield.tlsDaysRemaining === 'number'
                          ? `(${shield.tlsDaysRemaining}d)`
                          : ''}
                        {' · '}Missing Headers: {shield.missingHeadersCount}
                        {' · '}Email Auth: {shield.emailSecurityStatus}
                      </div>
                      {shield.baselineA.length > 0 && (
                        <div>Baseline DNS A: {shield.baselineA.join(', ')}</div>
                      )}
                      {shield.alertReason && (
                        <div className="text-amber-300">Notice: {shield.alertReason}</div>
                      )}
                      <div className="text-slate-500">
                        Last audit: {formatUtcTimestamp(shield.lastCheckedAt, lang)}
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-300">
                          Nginx Security Hardening Config
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            copyText(`shield-${shield.id}`, shield.nginxHardeningConfig)
                          }
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[11px] text-slate-200 cursor-pointer"
                        >
                          {copiedKey === `shield-${shield.id}` ? (
                            <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                          ) : (
                            <Copy className="w-3 h-3" aria-hidden="true" />
                          )}
                          <span>
                            {copiedKey === `shield-${shield.id}`
                              ? t.defense.copiedBtn
                              : t.defense.copyBtn}
                          </span>
                        </button>
                      </div>
                      <pre className="p-2.5 rounded bg-[#05070B] border border-slate-800 text-[10px] font-mono text-emerald-200 overflow-x-auto max-h-28">
                        {shield.nginxHardeningConfig}
                      </pre>
                    </div>

                    {defenseState.shieldFirewallBundles?.[shield.id] && (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-300">
                            Site block rules (Nginx)
                          </span>
                          <button
                            type="button"
                            onClick={() =>
                              copyText(
                                `shield-block-${shield.id}`,
                                defenseState.shieldFirewallBundles?.[shield.id]?.nginxDenyList ?? '',
                              )
                            }
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[11px] text-slate-200 cursor-pointer"
                          >
                            {copiedKey === `shield-block-${shield.id}` ? (
                              <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                            ) : (
                              <Copy className="w-3 h-3" aria-hidden="true" />
                            )}
                            <span>
                              {copiedKey === `shield-block-${shield.id}`
                                ? t.defense.copiedBtn
                                : t.defense.copyBtn}
                            </span>
                          </button>
                        </div>
                        <pre className="p-2.5 rounded bg-[#05070B] border border-slate-800 text-[10px] font-mono text-red-200 overflow-x-auto max-h-24">
                          {defenseState.shieldFirewallBundles?.[shield.id]?.nginxDenyList}
                        </pre>
                      </div>
                    )}

                    {shield.recommendedDnsRecords.length > 0 && (
                      <div className="p-2.5 rounded bg-[#05070B] border border-slate-800 font-mono text-[10px] text-amber-200 space-y-0.5">
                        {shield.recommendedDnsRecords.map((rec, i) => (
                          <div key={i}>{rec}</div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-400">{t.defense.noShieldsYet}</p>
            )}
          </div>

          {/* 4B: Blocked Attacker IPs + RDAP Abuse Takedown */}
          <div className="space-y-3 pt-4 border-t border-slate-800/80">
            <h3 className="text-sm font-bold text-red-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4" aria-hidden="true" />
              <span>
                {t.defense.blockedAttackersTitle} ({defenseState.blockedIps.length})
              </span>
            </h3>
            {defenseState.blockedIps.length > 0 ? (
              <div className="divide-y divide-slate-800/70 rounded-xl border border-slate-800 bg-[#05070B]/70 px-4">
                {defenseState.blockedIps.map((entry) => {
                  const mailtoHref =
                    entry.abuseEmails.length > 0
                      ? `mailto:${entry.abuseEmails[0]}?subject=${encodeURIComponent(
                          `Abuse / Cyber Attack Report: ${entry.ip}`,
                        )}&body=${encodeURIComponent(
                          `Observed malicious activity from IP ${entry.ip} (${entry.cidr || entry.asn || ''}). Reason: ${entry.reason}. Blocked timestamp: ${entry.blockedAt}.`,
                        )}`
                      : null;

                  return (
                    <div
                      key={entry.ip}
                      className="py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3"
                    >
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono font-bold text-emerald-400 text-sm">
                            {entry.ip}
                          </span>
                          {entry.cidr && (
                            <span className="font-mono text-slate-400">({entry.cidr})</span>
                          )}
                          <span className="text-slate-300">
                            {[entry.city, entry.country, entry.asn, entry.isp]
                              .filter(Boolean)
                              .join(' · ')}
                          </span>
                        </div>
                        <div className="text-slate-300">{entry.reason}</div>
                        <div className="font-mono text-[11px] text-amber-300">
                          {entry.firewallRules.iptables}
                        </div>
                        {entry.abuseEmails.length > 0 && (
                          <div className="font-mono text-[11px] text-sky-300">
                            RDAP Abuse Contacts: {entry.abuseEmails.join(', ')}
                          </div>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-2 shrink-0">
                        {mailtoHref && (
                          <a
                            href={mailtoHref}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold"
                          >
                            <Mail className="w-3.5 h-3.5" aria-hidden="true" />
                            <span>{t.defense.reportAbuseEmailBtn}</span>
                          </a>
                        )}
                        <button
                          type="button"
                          onClick={() => onUnblockIp(entry.ip)}
                          aria-label={t.defense.removeBtn}
                          className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-red-500/50 text-slate-400 hover:text-red-300 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-slate-400">{t.defense.noBlockedIpsYet}</p>
            )}
          </div>

          {/* 4C: Sinkholed Phishing Domains + Direct Takedown Portals */}
          <div className="space-y-3 pt-4 border-t border-slate-800/80">
            <h3 className="text-sm font-bold text-orange-300">
              {t.defense.sinkholedDomainsTitle} ({defenseState.blockedDomains.length})
            </h3>
            {defenseState.blockedDomains.length > 0 ? (
              <div className="divide-y divide-slate-800/70 rounded-xl border border-slate-800 bg-[#05070B]/70 px-4">
                {defenseState.blockedDomains.map((dom) => (
                  <div
                    key={dom.domain}
                    className="py-3 flex flex-col lg:flex-row lg:items-center justify-between gap-3"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="font-mono font-bold text-red-300 break-all">
                        {dom.domain}
                      </div>
                      <div className="font-mono text-[11px] text-emerald-300">
                        {dom.hostsEntry} · Pi-hole: {dom.piholeRule}
                      </div>
                      {dom.resolvedIps.length > 0 && (
                        <div className="font-mono text-[11px] text-slate-400">
                          Host IPs: {dom.resolvedIps.join(', ')}
                        </div>
                      )}
                      {dom.abuseEmails.length > 0 && (
                        <div className="font-mono text-[11px] text-amber-300">
                          Registrar/Host Abuse: {dom.abuseEmails.join(', ')}
                        </div>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      {dom.abuseEmails.length > 0 && (
                        <a
                          href={`mailto:${dom.abuseEmails.join(',')}?subject=${encodeURIComponent(`Abuse report: ${dom.domain}`)}&body=${encodeURIComponent(`Phishing/malicious domain: ${dom.domain}\nResolved IPs: ${dom.resolvedIps.join(', ') || 'unknown'}\nReason: ${dom.reason}\nPlease suspend the offending infrastructure.`)}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold"
                        >
                          <span>{t.defense.reportAbuseEmailBtn}</span>
                          <Mail className="w-3 h-3" aria-hidden="true" />
                        </a>
                      )}
                      <button
                        type="button"
                        onClick={() => onRemoveSinkhole(dom.domain)}
                        aria-label={t.defense.removeBtn}
                        className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-red-500/50 text-slate-400 hover:text-red-300 cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-400">{t.defense.noSinkholesYet}</p>
            )}
          </div>

          {/* 4D: Global Production Firewall & Sinkhole Bundle */}
          <div className="space-y-3 pt-4 border-t border-slate-800/80">
            <h3 className="text-sm font-bold text-slate-200">
              {t.defense.firewallBundleTitle}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {(
                [
                  {
                    key: 'nginx',
                    title: 'Nginx / OpenResty Blocklist',
                    code: defenseState.globalFirewallBundle.nginxDenyList,
                  },
                  {
                    key: 'iptables',
                    title: 'Linux iptables Firewall Script',
                    code: defenseState.globalFirewallBundle.iptablesScript,
                  },
                  {
                    key: 'cloudflare',
                    title: 'Local edge deny expression',
                    code: defenseState.globalFirewallBundle.cloudflareWafExpr,
                  },
                  {
                    key: 'hosts',
                    title: 'DNS Sinkhole (/etc/hosts & Pi-hole)',
                    code: defenseState.globalFirewallBundle.dnsSinkholeHosts,
                  },
                ] as const
              ).map((item) => (
                <div
                  key={item.key}
                  className="p-3.5 rounded-xl bg-[#05070B] border border-slate-800 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{item.title}</span>
                    <button
                      type="button"
                      onClick={() => copyText(item.key, item.code)}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[11px] text-slate-200 cursor-pointer"
                    >
                      {copiedKey === item.key ? (
                        <Check className="w-3 h-3 text-emerald-400" aria-hidden="true" />
                      ) : (
                        <Copy className="w-3 h-3" aria-hidden="true" />
                      )}
                      <span>
                        {copiedKey === item.key ? t.defense.copiedBtn : t.defense.copyBtn}
                      </span>
                    </button>
                  </div>
                  <pre className="text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-28">
                    {item.code}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Feed Health Footer Strip */}
      <div className="px-4 sm:px-5 py-3 border-t border-slate-800/80 bg-slate-950/50 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
        <span className="font-medium text-slate-300">{t.tables.feedHealthTitle}:</span>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          {feedHealth.map((feed) => (
            <span key={feed.name} className="inline-flex items-center gap-1.5">
              <span
                className={
                  feed.status === 'online' ? 'text-emerald-400' : 'text-amber-400'
                }
              >
                {feed.name}
              </span>
              <span className="font-mono tabular-nums text-slate-400">
                ({feed.recordCount.toLocaleString('en-US')})
              </span>
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
