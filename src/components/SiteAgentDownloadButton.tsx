import { Download } from 'lucide-react';
import type { Language } from '../types/cyber';

const LABEL = {
  bn: 'সাইট এজেন্ট ডাউনলোড',
  en: 'Download site agent',
} as const;

export function SiteAgentDownloadButton({
  lang,
  floating = false,
}: {
  lang: Language;
  floating?: boolean;
}) {
  return (
    <a
      href="/api/agent/download"
      download="sentinelglobe-site-agent.zip"
      title={
        lang === 'bn'
          ? 'আপনার ওয়েবসাইটে বসানোর এজেন্ট + README ডাউনলোড করুন'
          : 'Download the website agent and README'
      }
      className={`inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 sm:px-3 py-1.5 sm:py-2 text-[11px] sm:text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-500/20 ${
        floating ? 'fixed right-3 top-3 z-50 shadow-lg backdrop-blur-md sm:right-5 sm:top-5' : 'shrink-0'
      }`}
    >
      <Download className="h-3.5 w-3.5" aria-hidden="true" />
      <span className={floating ? '' : 'hidden sm:inline'}>{LABEL[lang]}</span>
    </a>
  );
}
