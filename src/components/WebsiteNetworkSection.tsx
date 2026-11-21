import { Activity, ExternalLink, Globe2, Loader2, RefreshCw, ShieldAlert, ShieldCheck, Users } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import type { AgentSiteSnapshot, Language } from '../types/cyber';

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

function timeAgo(iso: string, lang: Language): string {
  const diff = Math.max(0, Date.now() - Date.parse(iso));
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return L(lang, 'এখনই', 'just now');
  if (minutes < 60) return L(lang, `${minutes} মিনিট আগে`, `${minutes}m ago`);
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return L(lang, `${hours} ঘণ্টা আগে`, `${hours}h ago`);
  return L(lang, `${Math.floor(hours / 24)} দিন আগে`, `${Math.floor(hours / 24)}d ago`);
}

export function WebsiteNetworkSection({
  lang,
  onProtect,
  protecting,
  notice,
}: {
  lang: Language;
  onProtect: (site: string) => void;
  protecting: boolean;
  notice: string | null;
}) {
  const [snapshot, setSnapshot] = useState<AgentSiteSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/agent/sites', { cache: 'no-store' });
      const payload = (await res.json()) as AgentSiteSnapshot & { error?: string };
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setSnapshot(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Website registry unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const summary = snapshot?.summary;
  const sites = snapshot?.sites ?? [];

  return (
    <section aria-label="Website network" className="soc-panel rounded-xl p-4 sm:p-5 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-emerald-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L(lang, 'ওয়েবসাইট নেটওয়ার্ক', 'Website network')}
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">
            {L(
              lang,
              'যেসব সাইটে SentinelGlobe JavaScript এজেন্ট বসানো আছে, তারা এখানে স্বয়ংক্রিয়ভাবে দেখা যাবে। সাইটের লিংক, beacon, threat ও shield status এক জায়গায়।',
              'Every site running the SentinelGlobe JavaScript agent appears here automatically, with its link, beacon count, threats and shield status.',
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading}
          className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-emerald-200 disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          {L(lang, 'রিফ্রেশ', 'Refresh')}
        </button>
      </div>

      {error && <div className="rounded border border-red-500/30 bg-red-500/10 p-2 text-[10px] text-red-200">{error}</div>}
      {notice && (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-2 text-[10px] text-emerald-200">
          {notice}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          { label: L(lang, 'মোট সাইট', 'Total sites'), value: summary?.total ?? 0, icon: Globe2 },
          { label: L(lang, 'লাইভ', 'Live now'), value: summary?.online ?? 0, icon: Activity },
          { label: L(lang, 'সুরক্ষিত', 'Protected'), value: summary?.protected ?? 0, icon: ShieldCheck },
          { label: L(lang, 'থ্রেট', 'Threats'), value: summary?.threats ?? 0, icon: ShieldAlert },
        ].map((item) => (
          <div key={item.label} className="rounded-lg border border-white/10 bg-slate-950/40 p-2.5">
            <div className="flex items-center gap-1 text-[10px] text-slate-400">
              <item.icon className="h-3 w-3" />
              {item.label}
            </div>
            <div className="mt-1 text-lg font-bold text-slate-50">{item.value}</div>
          </div>
        ))}
      </div>

      {sites.length === 0 ? (
        <div className="rounded-lg border border-dashed border-white/15 p-4 text-center text-xs text-slate-400">
          <Users className="mx-auto mb-2 h-5 w-5 text-slate-500" />
          {L(
            lang,
            'এখনো কোনো সাইট এজেন্ট পাঠায়নি। নিচের ডান কোণে “সাইট এজেন্ট” থেকে snippet নিয়ে আপনার সাইটে বসান।',
            'No site has sent an agent beacon yet. Open “Site agent” at the bottom-right, copy the snippet and install it on your site.',
          )}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left text-xs">
            <thead className="text-[10px] uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-2 py-1.5">{L(lang, 'ওয়েবসাইট', 'Website')}</th>
                <th className="px-2 py-1.5">{L(lang, 'শেষ beacon', 'Last beacon')}</th>
                <th className="px-2 py-1.5">{L(lang, 'Beacon', 'Beacons')}</th>
                <th className="px-2 py-1.5">{L(lang, 'থ্রেট', 'Threats')}</th>
                <th className="px-2 py-1.5">{L(lang, 'স্ট্যাটাস', 'Status')}</th>
                <th className="px-2 py-1.5 text-right">{L(lang, 'সুরক্ষা', 'Protection')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {sites.map((site) => {
                const live = Date.now() - Date.parse(site.lastSeen) < 15 * 60_000;
                return (
                  <tr key={site.site} className="align-middle">
                    <td className="px-2 py-2">
                      <a
                        href={site.url || `https://${site.site}`}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 font-semibold text-cyan-200 hover:text-cyan-100"
                      >
                        {site.site}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                      <div className="text-[10px] text-slate-500">{site.url || '—'}</div>
                    </td>
                    <td className="px-2 py-2 text-slate-300">{timeAgo(site.lastSeen, lang)}</td>
                    <td className="px-2 py-2 text-slate-300">{site.beacons}</td>
                    <td className="px-2 py-2">
                      <span className={site.threats > 0 ? 'text-red-300' : 'text-slate-400'}>{site.threats}</span>
                    </td>
                    <td className="px-2 py-2">
                      <div className="flex flex-wrap gap-1">
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[10px] ${
                            live
                              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                              : 'border-slate-500/40 bg-slate-500/10 text-slate-300'
                          }`}
                        >
                          {live ? L(lang, 'লাইভ', 'live') : L(lang, 'অফলাইন', 'offline')}
                        </span>
                        {site.verified && (
                          <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-200">
                            {L(lang, 'যাচাইকৃত', 'verified')}
                          </span>
                        )}
                        {site.shield && (
                          <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-200">
                            {site.shield.status}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-2 py-2 text-right">
                      {site.shield ? (
                        <span className="inline-flex items-center gap-1 text-[10px] text-emerald-300">
                          <ShieldCheck className="h-3 w-3" />
                          {L(lang, 'সক্রিয়', 'active')}
                        </span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onProtect(site.site)}
                          disabled={protecting}
                          className="inline-flex items-center gap-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-200 disabled:opacity-50"
                        >
                          {protecting ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldCheck className="h-3 w-3" />}
                          {L(lang, 'সুরক্ষা দিন', 'Protect')}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
