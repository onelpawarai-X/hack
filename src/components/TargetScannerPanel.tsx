import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Crosshair,
  ExternalLink,
  Globe,
  Loader2,
  Lock,
  Network,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { useState, type FormEvent } from 'react';
import type { CyberTranslations } from '../i18n/cyberTranslations';
import type { Language, TargetScanResult, ThreatNode } from '../types/cyber';
import { formatShortDate, formatUtcTimestamp } from '../utils/formatters';

interface TargetScannerPanelProps {
  t: CyberTranslations;
  lang: Language;
  scanResult: TargetScanResult | null;
  scanning: boolean;
  scanError: string | null;
  activatingShield?: boolean;
  shieldNotice?: string | null;
  onScanTarget: (target: string) => void;
  onFocusNodeOnMap: (node: ThreatNode) => void;
  onActivateWebsiteShield: (target: string) => void;
  onDefendIp: (ip: string, reason?: string) => void;
  samplePhishUrl?: string;
  sampleAttackerIp?: string;
}

export function TargetScannerPanel({
  t,
  lang,
  scanResult,
  scanning,
  scanError,
  activatingShield,
  shieldNotice,
  onScanTarget,
  onFocusNodeOnMap,
  onActivateWebsiteShield,
  onDefendIp,
  samplePhishUrl,
  sampleAttackerIp,
}: TargetScannerPanelProps) {
  const [input, setInput] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (input.trim().length >= 2) {
      onScanTarget(input.trim());
    }
  };

  const runProbe = (target: string) => {
    setInput(target);
    onScanTarget(target);
  };

  const isDanger =
    scanResult?.verdict === 'CRITICAL' || scanResult?.verdict === 'HIGH';
  const isElevated = scanResult?.verdict === 'ELEVATED';

  return (
    <section aria-label={t.scanner.title} className="soc-panel rounded-xl p-5 sm:p-6 space-y-5">
      <div>
        <h2 className="text-lg font-bold text-slate-50">{t.scanner.title}</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-4xl leading-relaxed">
          {t.scanner.subtitle}
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1 min-w-0">
          <label htmlFor="target-scanner-input" className="sr-only">
            {t.scanner.placeholder}
          </label>
          <Search
            className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
            aria-hidden="true"
          />
          <input
            id="target-scanner-input"
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={t.scanner.placeholder}
            className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-[#06090F] border border-slate-700/80 focus:border-red-500 focus:outline-none text-sm text-slate-100 placeholder:text-slate-500 font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={scanning || input.trim().length < 2}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          {scanning && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />}
          <span>{scanning ? t.scanner.scanningBtn : t.scanner.scanBtn}</span>
        </button>
      </form>

      {/* Live OSINT Test Probes */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400">{t.scanner.quickProbesLabel}:</span>
        {samplePhishUrl && (
          <button
            type="button"
            onClick={() => runProbe(samplePhishUrl)}
            className="px-2.5 py-1 rounded-md bg-red-950/60 border border-red-500/35 hover:border-red-400 text-red-300 transition-colors cursor-pointer whitespace-nowrap"
          >
            {t.scanner.probePhish}
          </button>
        )}
        {sampleAttackerIp && (
          <button
            type="button"
            onClick={() => runProbe(sampleAttackerIp)}
            className="px-2.5 py-1 rounded-md bg-red-950/60 border border-red-500/35 hover:border-red-400 text-red-300 transition-colors cursor-pointer whitespace-nowrap"
          >
            {t.scanner.probeAttackerIp}
          </button>
        )}
        <button
          type="button"
          onClick={() => runProbe('1.1.1.1')}
          className="px-2.5 py-1 rounded-md bg-[#06090F] border border-slate-700 hover:border-sky-400/60 text-sky-200 transition-colors cursor-pointer whitespace-nowrap"
        >
          {t.scanner.probeCleanIp}
        </button>
        <button
          type="button"
          onClick={() => runProbe('google.com')}
          className="px-2.5 py-1 rounded-md bg-[#06090F] border border-slate-700 hover:border-emerald-500/50 text-slate-300 transition-colors cursor-pointer whitespace-nowrap"
        >
          {t.scanner.probeCleanGoogle}
        </button>
        <button
          type="button"
          onClick={() => runProbe('CVE-2024-3094')}
          className="px-2.5 py-1 rounded-md bg-[#06090F] border border-slate-700 hover:border-amber-400/60 text-amber-200 transition-colors cursor-pointer whitespace-nowrap"
        >
          {t.scanner.probeCve}
        </button>
      </div>

      {scanError && (
        <div className="p-3.5 rounded-lg bg-red-950/50 border border-red-500/40 text-xs text-red-200">
          {scanError}
        </div>
      )}

      {shieldNotice && (
        <div className="p-3.5 rounded-lg bg-emerald-950/50 border border-emerald-500/40 text-xs text-emerald-200 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
          <span>{shieldNotice}</span>
        </div>
      )}

      {scanResult && (
        <div
          className={`rounded-xl p-5 space-y-5 ${
            isDanger
              ? 'soc-panel-danger'
              : isElevated
                ? 'bg-amber-950/25 border border-amber-500/35'
                : 'soc-panel-clean'
          }`}
        >
          {/* Verdict Header */}
          <div className="flex flex-wrap items-start justify-between gap-3 pb-4 border-b border-slate-800/80">
            <div className="space-y-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span
                  className={`inline-flex items-center gap-1.5 font-bold ${
                    isDanger
                      ? 'text-red-400'
                      : isElevated
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                  }`}
                >
                  {isDanger ? (
                    <ShieldAlert className="w-4 h-4" aria-hidden="true" />
                  ) : isElevated ? (
                    <AlertTriangle className="w-4 h-4" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
                  )}
                  <span>{t.severityLabels[scanResult.verdict]}</span>
                </span>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span className="font-mono text-slate-300 uppercase">
                  {scanResult.targetType}
                </span>
                <span aria-hidden="true" className="text-slate-600">
                  ·
                </span>
                <span className="font-mono tabular-nums text-slate-400">
                  {formatUtcTimestamp(scanResult.scannedAt, lang)}
                </span>
              </div>

              <h3 className="text-base font-bold font-mono text-white break-all">
                {scanResult.normalizedTarget}
              </h3>

              <ul className="space-y-1 pt-1 text-xs text-slate-200">
                {scanResult.verdictReasons.map((reason, i) => (
                  <li key={i}>• {reason}</li>
                ))}
              </ul>
            </div>

            {(scanResult.targetType === 'domain' || scanResult.targetType === 'url') && (
              <button
                type="button"
                disabled={activatingShield}
                onClick={() => onActivateWebsiteShield(scanResult.normalizedTarget)}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors shrink-0 cursor-pointer whitespace-nowrap"
              >
                <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                <span>{t.scanner.activateShieldBtn}</span>
              </button>
            )}
            {scanResult.targetType === 'ip' && (
              <button
                type="button"
                disabled={activatingShield}
                onClick={() =>
                  onDefendIp(
                    scanResult.normalizedTarget,
                    scanResult.verdictReasons[0] || 'Defender Scanner IP Block',
                  )
                }
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors shrink-0 cursor-pointer whitespace-nowrap"
              >
                <ShieldCheck className="w-4 h-4" aria-hidden="true" />
                <span>{t.scanner.defendIpActionBtn}</span>
              </button>
            )}
          </div>

          {/* MITRE CVE 5.2 Deep Records (when scanning CVE-* or when host exposes Shodan CVEs) */}
          {scanResult.cveDetails && scanResult.cveDetails.length > 0 && (
            <div className="space-y-3 pb-4 border-b border-slate-800/80 text-xs">
              <h4 className="font-semibold text-amber-300 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" aria-hidden="true" />
                <span>{t.scanner.cveDetailsTitle}</span>
              </h4>
              <div className="divide-y divide-slate-800/70">
                {scanResult.cveDetails.map((cve) => (
                  <div key={cve.cveId} className="py-3 first:pt-0 last:pb-0 space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-bold text-white text-sm">
                        {cve.cveId}
                      </span>
                      {cve.cvssScore !== undefined && (
                        <>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="font-mono font-bold text-red-400">
                            CVSS {cve.cvssScore} ({cve.cvssSeverity || 'SCORED'})
                          </span>
                        </>
                      )}
                      {cve.cwes.length > 0 && (
                        <>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="font-mono text-amber-300">
                            {cve.cwes.join(' · ')}
                          </span>
                        </>
                      )}
                      {cve.publishedDate && (
                        <>
                          <span aria-hidden="true" className="text-slate-600">
                            ·
                          </span>
                          <span className="font-mono tabular-nums text-slate-400">
                            {formatShortDate(cve.publishedDate)}
                          </span>
                        </>
                      )}
                    </div>
                    <div className="font-semibold text-slate-100">{cve.title}</div>
                    {cve.description && (
                      <p className="text-slate-300 leading-relaxed max-w-4xl">
                        {cve.description}
                      </p>
                    )}
                    {cve.affectedProducts.length > 0 && (
                      <div className="font-mono text-[11px] text-sky-300">
                        Affected: {cve.affectedProducts.join(' · ')}
                      </div>
                    )}
                    {cve.cvssVector && (
                      <div className="font-mono text-[11px] text-slate-400 break-all">
                        Vector: {cve.cvssVector}
                      </div>
                    )}
                    {cve.references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-3 pt-1">
                        {cve.references.slice(0, 3).map((refUrl) => (
                          <a
                            key={refUrl}
                            href={refUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-sky-300 hover:underline truncate max-w-[300px]"
                          >
                            <span>{new URL(refUrl).hostname}</span>
                            <ExternalLink className="w-3 h-3 shrink-0" aria-hidden="true" />
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 3-Column Deep Technical OSINT Dossier */}
          {scanResult.targetType !== 'cve' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 lg:gap-0 lg:divide-x divide-slate-800/80 text-xs">
              {/* Column 1: Geolocation + RIPEstat BGP Routing + Shodan Exposure */}
              <div className="lg:pr-5 space-y-4">
                <div className="space-y-2">
                  <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                    <span>{t.scanner.attributionTitle}</span>
                  </h4>
                  {scanResult.attribution.length > 0 ? (
                    <div className="divide-y divide-slate-800/70">
                      {scanResult.attribution.map((attr) => (
                        <div key={attr.ip} className="py-2.5 first:pt-0 space-y-1.5">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono font-semibold text-slate-100">
                              {attr.ip}
                            </span>
                            <button
                              type="button"
                              onClick={() => onFocusNodeOnMap(attr)}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#06090F] border border-sky-500/40 hover:border-sky-400 text-[11px] text-sky-300 cursor-pointer"
                            >
                              <Crosshair className="w-3 h-3" aria-hidden="true" />
                              <span>{t.scanner.focusOnMapBtn}</span>
                            </button>
                          </div>
                          <div className="text-slate-200 font-medium">
                            {attr.city}, {attr.country} ({attr.countryCode})
                          </div>
                          {attr.physicalAddress && (
                            <div className="text-slate-300 leading-relaxed">
                              {attr.physicalAddress}
                            </div>
                          )}
                          <div className="font-mono tabular-nums text-slate-400">
                            {attr.lat.toFixed(4)}, {attr.lon.toFixed(4)}
                            {attr.timezone ? ` · ${attr.timezone}` : ''}
                          </div>
                          <div className="text-slate-400 font-mono">
                            {attr.asn} · {attr.isp}
                          </div>
                          {attr.reverse && (
                            <div className="font-mono text-slate-400 truncate">
                              PTR: {attr.reverse}
                            </div>
                          )}
                          {attr.isTorExit && (
                            <div className="font-semibold text-red-400">
                              {t.torExitDetected}
                            </div>
                          )}
                          {attr.openPorts && attr.openPorts.length > 0 && (
                            <div className="font-mono text-amber-300">
                              {t.openPortsLabel}: {attr.openPorts.join(', ')}
                            </div>
                          )}
                          {attr.knownVulns && attr.knownVulns.length > 0 && (
                            <div className="font-mono text-red-300">
                              {t.knownVulnsLabel}: {attr.knownVulns.slice(0, 6).join(', ')}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-slate-500">—</p>
                  )}
                </div>

                {scanResult.bgpProfile && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-800/70">
                    <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-sky-400" aria-hidden="true" />
                      <span>{t.scanner.bgpTitle}</span>
                    </h4>
                    <div className="font-mono text-sky-300 font-semibold">
                      Prefix: {scanResult.bgpProfile.prefix}{' '}
                      <span className="text-emerald-400 font-normal">
                        ({scanResult.bgpProfile.announced ? 'Announced' : 'Unannounced'})
                      </span>
                    </div>
                    {scanResult.bgpProfile.asns.map((a) => (
                      <div key={a.asn} className="font-mono text-slate-300">
                        AS{a.asn} · {a.holder}
                      </div>
                    ))}
                    {scanResult.bgpProfile.rirBlock && (
                      <div className="text-slate-400">{scanResult.bgpProfile.rirBlock}</div>
                    )}
                  </div>
                )}
              </div>

              {/* Column 2: DNS, SPF/DMARC & RDAP Domain Lifecycle */}
              <div className="lg:px-5 space-y-4">
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-200">{t.scanner.dnsTitle}</h4>
                  <div className="font-mono text-slate-300 space-y-1">
                    {scanResult.dns.a.length > 0 && (
                      <div>A: {scanResult.dns.a.join(', ')}</div>
                    )}
                    {scanResult.dns.aaaa.length > 0 && (
                      <div className="truncate">AAAA: {scanResult.dns.aaaa.join(', ')}</div>
                    )}
                    {scanResult.dns.ns.length > 0 && (
                      <div className="truncate">NS: {scanResult.dns.ns.slice(0, 2).join(', ')}</div>
                    )}
                    {scanResult.dns.mx.length > 0 && (
                      <div className="truncate">MX: {scanResult.dns.mx.slice(0, 2).join(', ')}</div>
                    )}
                    {scanResult.dns.caa.length > 0 && (
                      <div className="truncate">CAA: {scanResult.dns.caa.slice(0, 2).join(', ')}</div>
                    )}
                    {(scanResult.targetType === 'domain' || scanResult.targetType === 'url') && (
                      <div
                        className={
                          scanResult.dns.emailSecurityStatus === 'protected'
                            ? 'text-emerald-400'
                            : scanResult.dns.emailSecurityStatus === 'weak'
                              ? 'text-amber-300'
                              : 'text-red-300'
                        }
                      >
                        {t.scanner.emailSecurityLabel}:{' '}
                        {scanResult.dns.emailSecurityStatus === 'protected'
                          ? t.scanner.emailProtected
                          : scanResult.dns.emailSecurityStatus === 'weak'
                            ? t.scanner.emailWeak
                            : t.scanner.emailMissing}
                      </div>
                    )}
                  </div>
                </div>

                {scanResult.rdapProfile && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-800/70">
                    <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                      <span>{t.scanner.rdapTitle}</span>
                    </h4>
                    <div className="space-y-1 text-slate-300">
                      {scanResult.rdapProfile.registrar && (
                        <div>
                          Registrar:{' '}
                          <span className="font-semibold text-white">
                            {scanResult.rdapProfile.registrar}
                          </span>
                        </div>
                      )}
                      {scanResult.rdapProfile.registrationDate && (
                        <div className="font-mono tabular-nums">
                          Created: {formatShortDate(scanResult.rdapProfile.registrationDate)}
                        </div>
                      )}
                      {scanResult.rdapProfile.expirationDate && (
                        <div className="font-mono tabular-nums">
                          Expires: {formatShortDate(scanResult.rdapProfile.expirationDate)}
                        </div>
                      )}
                      {typeof scanResult.rdapProfile.dnssecSigned === 'boolean' && (
                        <div className="font-mono">
                          DNSSEC: {scanResult.rdapProfile.dnssecSigned ? 'Signed' : 'Unsigned'}
                        </div>
                      )}
                      {scanResult.rdapProfile.abuseEmails.length > 0 && (
                        <div className="font-mono text-amber-300 truncate">
                          Abuse: {scanResult.rdapProfile.abuseEmails[0]}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {scanResult.tls && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-800/70">
                    <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                      <span>{t.scanner.tlsTitle}</span>
                    </h4>
                    <div
                      className={`font-semibold ${
                        scanResult.tls.valid ? 'text-emerald-400' : 'text-red-400'
                      }`}
                    >
                      {scanResult.tls.valid ? t.scanner.tlsValid : t.scanner.tlsInvalid}
                    </div>
                    {scanResult.tls.issuer && (
                      <div className="text-slate-300">Issuer: {scanResult.tls.issuer}</div>
                    )}
                    {scanResult.tls.protocol && (
                      <div className="font-mono text-slate-400">
                        {scanResult.tls.protocol}
                        {scanResult.tls.cipher ? ` · ${scanResult.tls.cipher}` : ''}
                        {typeof scanResult.tls.daysRemaining === 'number'
                          ? ` · ${scanResult.tls.daysRemaining} ${t.scanner.daysLeft}`
                          : ''}
                      </div>
                    )}
                    {typeof scanResult.tls.sanCount === 'number' && (
                      <div className="font-mono text-slate-400">
                        SAN Domains: {scanResult.tls.sanCount}
                      </div>
                    )}
                    {scanResult.tls.error && (
                      <div className="text-red-300">{scanResult.tls.error}</div>
                    )}
                  </div>
                )}
              </div>

              {/* Column 3: Threat Feeds, HTTP Headers & Wayback Machine Archive */}
              <div className="lg:pl-5 space-y-4">
                <div className="space-y-1.5">
                  <h4 className="font-semibold text-slate-200">{t.scanner.feedHitsTitle}</h4>
                  {scanResult.feedMatches.length > 0 ? (
                    <ul className="space-y-1 text-red-300">
                      {scanResult.feedMatches.map((m, idx) => (
                        <li key={idx}>
                          <span className="font-semibold">{m.feed}:</span> {m.detail}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-emerald-300/90">{t.scanner.noFeedHits}</p>
                  )}
                </div>

                {scanResult.httpAudit && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-800/70">
                    <h4 className="font-semibold text-slate-200">{t.scanner.httpTitle}</h4>
                    {scanResult.httpAudit.status && (
                      <div className="font-mono text-slate-300">
                        HTTP {scanResult.httpAudit.status}
                        {scanResult.httpAudit.server
                          ? ` · Server: ${scanResult.httpAudit.server}`
                          : ''}
                        {' · '}
                        {t.scanner.securityTxtLabel}:{' '}
                        {scanResult.httpAudit.securityTxtFound ? 'Yes' : 'No'}
                        {' · '}
                        {t.scanner.robotsTxtLabel}:{' '}
                        {scanResult.httpAudit.robotsTxtFound ? 'Yes' : 'No'}
                      </div>
                    )}
                    {scanResult.httpAudit.missingSecurityHeaders.length > 0 ? (
                      <div className="text-amber-300">
                        {t.scanner.missingHeaders}:{' '}
                        <span className="font-mono">
                          {scanResult.httpAudit.missingSecurityHeaders.join(', ')}
                        </span>
                      </div>
                    ) : scanResult.httpAudit.error ? (
                      <div className="text-slate-400">{scanResult.httpAudit.error}</div>
                    ) : (
                      <div className="text-emerald-300">{t.scanner.allHeadersPresent}</div>
                    )}
                    {scanResult.httpAudit.cookieIssues.length > 0 && (
                      <div className="text-amber-300">
                        {t.scanner.cookieIssuesLabel}:{' '}
                        <span className="font-mono">
                          {scanResult.httpAudit.cookieIssues.slice(0, 4).join(' · ')}
                        </span>
                      </div>
                    )}
                  </div>
                )}

                {scanResult.waybackProfile && (
                  <div className="space-y-1.5 pt-3 border-t border-slate-800/70">
                    <h4 className="font-semibold text-slate-200 flex items-center gap-1.5">
                      <Archive className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                      <span>{t.scanner.waybackTitle}</span>
                    </h4>
                    <div className="font-mono tabular-nums text-slate-300 space-y-0.5">
                      {scanResult.waybackProfile.firstSnapshot && (
                        <div>First Archived: {scanResult.waybackProfile.firstSnapshot}</div>
                      )}
                      {scanResult.waybackProfile.latestSnapshot && (
                        <div>Latest Snapshot: {scanResult.waybackProfile.latestSnapshot}</div>
                      )}
                    </div>
                    <a
                      href={scanResult.waybackProfile.archiveUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-[11px] text-sky-300 hover:underline"
                    >
                      <span>Open Wayback Machine</span>
                      <ExternalLink className="w-3 h-3" aria-hidden="true" />
                    </a>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Certificate Transparency Discovered Subdomains */}
          {scanResult.discoveredSubdomains && scanResult.discoveredSubdomains.length > 0 && (
            <div className="pt-4 border-t border-slate-800/80 space-y-2.5 text-xs">
              <h4 className="font-semibold text-slate-200">
                {t.scanner.subdomainsTitle} ({scanResult.discoveredSubdomains.length})
              </h4>
              <div className="max-h-40 overflow-y-auto grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-1.5">
                {scanResult.discoveredSubdomains.map((sub) => (
                  <button
                    key={sub}
                    type="button"
                    onClick={() => runProbe(sub)}
                    className="text-left px-2.5 py-1.5 rounded bg-[#06090F] border border-slate-800 hover:border-sky-500/50 font-mono text-[11px] text-sky-200 truncate transition-colors cursor-pointer"
                  >
                    {sub}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Actionable Defense Hardening Plan */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
            <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
              <span>{t.scanner.hardeningTitle}</span>
            </h4>
            {scanResult.hardeningRecommendations.length > 0 ? (
              <div className="divide-y divide-slate-800/70 text-xs">
                {scanResult.hardeningRecommendations.map((rec) => (
                  <div key={rec.id} className="py-2.5 first:pt-0 last:pb-0 space-y-1">
                    <div
                      className={`font-semibold ${
                        rec.severity === 'CRITICAL'
                          ? 'text-red-400'
                          : rec.severity === 'HIGH'
                            ? 'text-orange-300'
                            : 'text-amber-300'
                      }`}
                    >
                      {rec.severity} · {rec.title}
                    </div>
                    <p className="text-slate-300 leading-relaxed">{rec.remediation}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-emerald-300">{t.scanner.hardeningClean}</p>
            )}
          </div>

          {/* Web-Wide Breach & Incident Signals */}
          {scanResult.webBreachSignals.length > 0 && (
            <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
              <h4 className="text-xs font-semibold text-slate-300">
                {t.scanner.webSignalsTitle}
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanResult.webBreachSignals.map((sig) => (
                  <a
                    key={sig.id}
                    href={sig.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-3 rounded-lg bg-[#06090F] border border-slate-800 hover:border-slate-600 transition-colors flex items-start justify-between gap-2"
                  >
                    <div className="min-w-0 space-y-1">
                      <div className="text-xs font-medium text-slate-100 line-clamp-2">
                        {sig.title}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">
                        {sig.source}
                      </div>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-500 shrink-0 mt-0.5" aria-hidden="true" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
