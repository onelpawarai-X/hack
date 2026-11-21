import { Crosshair, Globe2, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { CyberTranslations } from '../i18n/cyberTranslations';
import type { ThreatNode } from '../types/cyber';

interface AttackerInspectorProps {
  t: CyberTranslations;
  node: ThreatNode | null;
  isBlocked: boolean;
  onDefendIp: (ip: string, reason?: string) => void;
  onDeepScanIp: (ip: string) => void;
}

export function AttackerInspector({
  t,
  node,
  isBlocked,
  onDefendIp,
  onDeepScanIp,
}: AttackerInspectorProps) {
  if (!node) {
    return (
      <aside
        aria-label={t.inspectorTitle}
        className="soc-panel rounded-xl p-5 flex flex-col justify-center items-center text-center min-h-[300px]"
      >
        <Crosshair className="w-8 h-8 text-slate-600 mb-3" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-slate-200">{t.inspectorTitle}</h3>
        <p className="text-xs text-slate-400 mt-1.5 max-w-xs leading-relaxed">
          {t.inspectorEmpty}
        </p>
      </aside>
    );
  }

  const isDanger = node.severity === 'CRITICAL' || node.severity === 'HIGH';
  const isClean = node.severity === 'CLEAN';
  const isIpAddress = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(node.ip);

  return (
    <aside
      aria-label={t.inspectorTitle}
      className={`rounded-xl p-5 flex flex-col justify-between gap-4 ${
        isBlocked
          ? 'soc-panel-clean'
          : isDanger
            ? 'soc-panel-danger'
            : isClean
              ? 'soc-panel-clean'
              : 'soc-panel'
      }`}
    >
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-2 pb-3 border-b border-slate-800/80">
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-400">{t.inspectorTitle}</div>
            <h3 className="text-base sm:text-lg font-bold font-mono tabular-nums text-white mt-0.5 break-all">
              {node.ip}
              {node.port ? `:${node.port}` : ''}
            </h3>
            {isBlocked && (
              <div className="mt-1 inline-flex items-center gap-1.5 text-[11px] font-semibold text-emerald-400">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>{t.defendedBlockedBadge}</span>
              </div>
            )}
          </div>
          <span
            className={`inline-flex items-center gap-1 text-xs font-semibold shrink-0 ${
              isDanger
                ? 'text-red-400'
                : isClean
                  ? 'text-emerald-400'
                  : 'text-amber-300'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>{t.severityLabels[node.severity]}</span>
          </span>
        </div>

        <dl className="space-y-1.5 text-xs">
          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.tables.threatType}</dt>
            <dd
              className={`text-right font-medium ${
                isDanger ? 'text-red-300' : 'text-slate-100'
              }`}
            >
              {node.threatType}
            </dd>
          </div>

          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.locationLabel}</dt>
            <dd className="text-right text-slate-100 font-medium inline-flex items-center gap-1.5">
              <Globe2 className="w-3.5 h-3.5 text-slate-400 shrink-0" aria-hidden="true" />
              <span>
                {node.city}, {node.country} ({node.countryCode})
              </span>
            </dd>
          </div>

          {node.physicalAddress && (
            <div className="py-1.5 border-b border-slate-800/50 space-y-1">
              <dt className="text-slate-400">{t.addressLabel}</dt>
              <dd className="text-slate-100 leading-relaxed break-words">
                {node.physicalAddress}
              </dd>
            </div>
          )}

          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.coordsLabel}</dt>
            <dd className="text-right font-mono tabular-nums text-slate-200">
              {node.lat.toFixed(4)}, {node.lon.toFixed(4)}
            </dd>
          </div>

          {node.timezone && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.timezoneLabel}</dt>
              <dd className="text-right font-mono text-slate-300">{node.timezone}</dd>
            </div>
          )}

          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.asnLabel}</dt>
            <dd className="text-right font-mono text-slate-200 truncate max-w-[200px]">
              {node.asn}
            </dd>
          </div>

          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.ispLabel}</dt>
            <dd className="text-right text-slate-200 truncate max-w-[210px]">{node.isp}</dd>
          </div>

          {node.cidr && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.cidrLabel}</dt>
              <dd className="text-right font-mono text-slate-300">{node.cidr}</dd>
            </div>
          )}

          {node.abuseEmails && node.abuseEmails.length > 0 && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.abuseContactLabel}</dt>
              <dd className="text-right font-mono text-amber-300 truncate max-w-[210px]">
                {node.abuseEmails[0]}
              </dd>
            </div>
          )}

          {node.reverse && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.reverseDnsLabel}</dt>
              <dd className="text-right font-mono text-slate-300 truncate max-w-[200px]">
                {node.reverse}
              </dd>
            </div>
          )}

          <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
            <dt className="text-slate-400 shrink-0">{t.flagsLabel}</dt>
            <dd className="text-right text-slate-300">
              {node.isTorExit
                ? t.torExitDetected
                : node.isProxy
                  ? t.proxyDetected
                  : node.isHosting
                    ? t.hostingNode
                    : t.directOrigin}
            </dd>
          </div>

          {node.openPorts && node.openPorts.length > 0 && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.openPortsLabel}</dt>
              <dd className="text-right font-mono text-amber-300">
                {node.openPorts.slice(0, 12).join(', ')}
              </dd>
            </div>
          )}

          {node.knownVulns && node.knownVulns.length > 0 && (
            <div className="flex justify-between gap-3 py-1 border-b border-slate-800/50">
              <dt className="text-slate-400 shrink-0">{t.knownVulnsLabel}</dt>
              <dd className="text-right font-mono text-red-300">
                {node.knownVulns.slice(0, 5).join(', ')}
              </dd>
            </div>
          )}

          <div className="flex justify-between gap-3 py-1">
            <dt className="text-slate-400 shrink-0">{t.feedSourceLabel}</dt>
            <dd className="text-right font-medium text-slate-200">{node.sourceFeed}</dd>
          </div>
        </dl>
      </div>

      {isIpAddress && (
        <div className="space-y-2">
          {!isBlocked && (
            <button
              type="button"
              onClick={() => onDefendIp(node.ip, node.threatType)}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors cursor-pointer"
            >
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              <span>{t.defendBlockIpBtn}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => onDeepScanIp(node.ip)}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold transition-colors cursor-pointer"
          >
            <Search className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{t.deepScanIpBtn}</span>
          </button>
        </div>
      )}
    </aside>
  );
}
