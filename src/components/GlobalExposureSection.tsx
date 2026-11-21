import { Activity, AlertTriangle, Globe2, Loader2, RefreshCw, ShieldAlert } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import type { Language } from '../types/cyber';

interface ExposureSite {
  domain: string;
  source: 'urlscan' | 'phishing-feed' | 'protected-site';
  url: string;
  status?: number;
  country?: string;
  asn?: string;
  asnName?: string;
  title?: string;
  labels: string[];
  issues: string[];
  risk: number;
  verdict: 'critical' | 'high' | 'medium' | 'low';
  checkedAt: string;
  error?: string;
}

interface ExposureSnapshot {
  generatedAt: string;
  lastRunAt: string | null;
  running: boolean;
  sources: Array<{ name: string; status: 'online' | 'degraded'; detail: string }>;
  coverage: { discovered: number; probed: number; critical: number; high: number; medium: number; low: number };
  sites: ExposureSite[];
}

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

const VERDICT_STYLE: Record<ExposureSite['verdict'], string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-200',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-200',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
};

export function GlobalExposureSection({ lang }: { lang: Language }) {
  const [snapshot, setSnapshot] = useState<ExposureSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(refresh ? '/api/exposure/global/refresh' : '/api/exposure/global', {
        method: refresh ? 'POST' : 'GET',
        cache: 'no-store',
      });
      const payload = (await res.json()) as ExposureSnapshot & { error?: string };
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setSnapshot(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Exposure feed unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(false);
    const timer = window.setInterval(() => void load(false), 60_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const coverage = snapshot?.coverage;

  return (
    <section aria-label="Global web exposure" className="soc-panel rounded-xl p-4 sm:p-5 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L(lang, 'বিশ্বব্যাপী ওয়েব এক্সপোজার মনিটর', 'Global web exposure monitor')}
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">
            {L(
              lang,
              'পাবলিক urlscan.io স্ক্যান, লাইভ ফিশিং ফিড ও আমাদের সুরক্ষিত সাইটগুলো থেকে ডোমেইন নিয়ে একবার করে নিরাপদ HTTPS/DNS চেক করা হয়। কোনো এক্সপ্লয়েট বা পোর্ট স্ক্যান নয়।',
              'Domains discovered from public urlscan.io scans, live phishing feeds and our protected sites get one safe HTTPS/DNS check. No exploitation or port scanning.',
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load(true)}
          disabled={loading}
          className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-cyan-200 disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          {L(lang, 'এখন স্ক্যান', 'Scan now')}
        </button>
      </div>

      {error && <div className="rounded border border-red-500/30 bg-red-500/10 p-2 text-[10px] text-red-200">{error}</div>}

      {coverage && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {[
            { label: L(lang, 'আবিষ্কৃত', 'Discovered'), value: coverage.discovered, tone: 'text-slate-100' },
            { label: L(lang, 'চেক করা', 'Probed'), value: coverage.probed, tone: 'text-cyan-200' },
            { label: L(lang, 'ক্রিটিক্যাল', 'Critical'), value: coverage.critical, tone: 'text-red-300' },
            { label: L(lang, 'হাই', 'High'), value: coverage.high, tone: 'text-orange-300' },
            { label: L(lang, 'মিডিয়াম', 'Medium'), value: coverage.medium, tone: 'text-amber-300' },
            { label: L(lang, 'লো', 'Low'), value: coverage.low, tone: 'text-emerald-300' },
          ].map((item) => (
            <div key={item.label} className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
              <div className="text-[8px] uppercase tracking-wide text-slate-500">{item.label}</div>
              <div className={`text-lg font-bold ${item.tone}`}>{item.value}</div>
            </div>
          ))}
        </div>
      )}

      {snapshot && (
        <div className="flex flex-wrap gap-1">
          {snapshot.sources.map((source) => (
            <span
              key={source.name}
              title={source.detail}
              className={`rounded-full border px-1.5 py-0.5 text-[8px] ${
                source.status === 'online'
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                  : 'border-amber-500/40 bg-amber-500/10 text-amber-200'
              }`}
            >
              {source.name}: {source.detail}
            </span>
          ))}
          {snapshot.lastRunAt && (
            <span className="rounded-full border border-slate-700 px-1.5 py-0.5 text-[8px] text-slate-500">
              {L(lang, 'শেষ চেক', 'Last check')}: {new Date(snapshot.lastRunAt).toLocaleTimeString()}
            </span>
          )}
        </div>
      )}

      <div className="max-h-[420px] overflow-auto rounded-lg border border-slate-800">
        <table className="w-full min-w-[760px] text-left text-[10px]">
          <thead className="sticky top-0 bg-[#060b12] text-[8px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="p-2">{L(lang, 'ডোমেইন', 'Domain')}</th>
              <th className="p-2">{L(lang, 'রিস্ক', 'Risk')}</th>
              <th className="p-2">{L(lang, 'স্ট্যাটাস', 'Status')}</th>
              <th className="p-2">{L(lang, 'দেশ / ASN', 'Country / ASN')}</th>
              <th className="p-2">{L(lang, 'সমস্যা', 'Issues')}</th>
              <th className="p-2">{L(lang, 'সোর্স', 'Source')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 text-slate-300">
            {(snapshot?.sites ?? []).map((site) => (
              <tr key={`${site.domain}-${site.source}`} className="align-top hover:bg-slate-900/40">
                <td className="p-2">
                  <a href={site.url} target="_blank" rel="noreferrer" className="font-semibold text-cyan-300 underline decoration-dotted">
                    {site.domain}
                  </a>
                  {site.title && <div className="max-w-[220px] truncate text-[9px] text-slate-500">{site.title}</div>}
                </td>
                <td className="p-2">
                  <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase ${VERDICT_STYLE[site.verdict]}`}>
                    {site.verdict === 'critical' ? <ShieldAlert className="h-2.5 w-2.5" /> : <AlertTriangle className="h-2.5 w-2.5" />}
                    {site.risk}
                  </span>
                </td>
                <td className="p-2">
                  <span className="font-mono text-[9px]">{site.status ?? '—'}</span>
                  {site.error && <div className="max-w-[180px] text-[8px] text-red-300">{site.error}</div>}
                </td>
                <td className="p-2 text-[9px]">
                  <div>{site.country ?? '—'}</div>
                  <div className="max-w-[160px] truncate text-slate-500">{site.asnName ?? site.asn ?? ''}</div>
                </td>
                <td className="p-2">
                  <ul className="max-w-[280px] list-inside list-disc space-y-0.5 text-[9px] text-slate-400">
                    {site.issues.slice(0, 4).map((issue) => <li key={issue}>{issue}</li>)}
                  </ul>
                  {site.labels.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {site.labels.slice(0, 4).map((label) => (
                        <span key={label} className="rounded bg-red-500/10 px-1 text-[8px] text-red-300">{label}</span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="p-2 text-[8px] uppercase text-slate-500">{site.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!snapshot?.sites.length && (
          <div className="flex items-center gap-2 p-4 text-[10px] text-slate-500">
            <Activity className="h-3.5 w-3.5" />
            {L(lang, 'প্রথম অডিট চলছে… একটু পরে রিফ্রেশ করুন।', 'First audit is running… refresh in a moment.')}
          </div>
        )}
      </div>
    </section>
  );
}
