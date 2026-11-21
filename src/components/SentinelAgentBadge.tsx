import { Check, Copy, Download, ShieldCheck, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { Language } from '../types/cyber';

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

export function SentinelAgentBadge({ lang }: { lang: Language }) {
  const [open, setOpen] = useState(false);
  const [site, setSite] = useState('');
  const [copied, setCopied] = useState(false);

  const origin = useMemo(() => (typeof window === 'undefined' ? '' : window.location.origin), []);
  const snippet = `<script src="${origin}/sentinel-agent.js" data-site="${site || 'your-domain.com'}" data-mode="protect" defer></script>`;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-label={L(lang, 'Sentinel এজেন্ট ডাউনলোড', 'Download Sentinel agent')}
        className="fixed bottom-5 right-5 z-[60] inline-flex items-center gap-2 rounded-full border border-cyan-400/50 bg-[#041018]/95 px-3.5 py-2.5 text-[11px] font-bold text-cyan-200 shadow-[0_0_25px_rgba(34,211,238,.35)] backdrop-blur transition hover:border-cyan-300 hover:text-cyan-100"
      >
        <ShieldCheck className="h-4 w-4" />
        {L(lang, 'সাইট এজেন্ট', 'Site agent')}
      </button>

      {open && (
        <div className="fixed bottom-20 right-5 z-[60] w-[min(92vw,420px)] rounded-xl border border-cyan-500/30 bg-[#04070d]/98 p-3 shadow-2xl backdrop-blur">
          <div className="mb-2 flex items-start justify-between gap-2">
            <div>
              <h3 className="flex items-center gap-1.5 text-[12px] font-bold text-cyan-200">
                <ShieldCheck className="h-4 w-4" /> {L(lang, 'SentinelGlobe সাইট এজেন্ট', 'SentinelGlobe site agent')}
              </h3>
              <p className="mt-0.5 text-[9px] leading-relaxed text-slate-400">
                {L(
                  lang,
                  'এই ফাইলটি আপনার সাইটে যোগ করুন। ক্লায়েন্ট-সাইড টেম্পারিং, ইনজেক্টেড স্ক্রিপ্ট, ক্লিকজ্যাকিং ও ফর্ম হাইজ্যাক ডিটেক্ট করে আমাদের কন্ট্রোল প্লেনে রিপোর্ট করবে।',
                  'Add this file to your site. It detects client-side tampering, injected scripts, clickjacking and form hijacking, then reports to our control plane.',
                )}
              </p>
            </div>
            <button type="button" onClick={() => setOpen(false)} className="rounded p-1 text-slate-500 hover:text-slate-200">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          <a
            href="/sentinel-agent.js"
            download="sentinel-agent.js"
            className="mb-2 inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-[11px] font-semibold text-cyan-200 hover:bg-cyan-500/20"
          >
            <Download className="h-3.5 w-3.5" />
            {L(lang, 'sentinel-agent.js ডাউনলোড', 'Download sentinel-agent.js')}
          </a>

          <a
            href="/api/agent/download"
            download="sentinelglobe-site-agent.zip"
            className="mb-2 inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-[11px] font-semibold text-emerald-200 hover:bg-emerald-500/20"
          >
            <Download className="h-3.5 w-3.5" />
            {L(lang, 'ZIP + README ডাউনলোড', 'Download ZIP + README')}
          </a>

          <label className="mb-1 block text-[9px] uppercase tracking-wide text-slate-500">
            {L(lang, 'আপনার ডোমেইন', 'Your domain')}
          </label>
          <input
            value={site}
            onChange={(event) => setSite(event.target.value)}
            placeholder="example.com"
            className="mb-2 w-full rounded-lg border border-slate-700 bg-[#02060c] px-2 py-1.5 text-[11px] text-slate-100 outline-none focus:border-cyan-500/60"
          />

          <pre className="mb-2 max-h-24 overflow-auto rounded-lg border border-slate-800 bg-black/50 p-2 text-[9px] leading-relaxed text-emerald-300">
            {snippet}
          </pre>

          <button
            type="button"
            onClick={() => void copy()}
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-[10px] font-semibold text-slate-200 hover:border-slate-500"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? L(lang, 'কপি হয়েছে', 'Copied') : L(lang, 'স্নিপেট কপি করুন', 'Copy snippet')}
          </button>

          <p className="mt-2 text-[8px] leading-relaxed text-amber-300/80">
            {L(
              lang,
              'সতর্কতা: ক্লায়েন্ট-সাইড এজেন্ট একা ১০০% সুরক্ষা দিতে পারে না। সার্ভার-সাইড WAF/ফায়ারওয়াল ও আমাদের সেন্সর একসাথে ব্যবহার করুন।',
              'Warning: a client-side agent alone cannot provide 100% protection. Pair it with server-side WAF/firewall and our sensor.',
            )}
          </p>
        </div>
      )}
    </>
  );
}
