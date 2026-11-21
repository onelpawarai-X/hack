import { Activity } from 'lucide-react';
import type { LabTranslations } from '../i18n/labTranslations';
import type { ScanProgressPayload } from '../types/realtime';

interface ScanProgressBarProps {
  t: LabTranslations;
  progress: ScanProgressPayload | null;
  scanning: boolean;
}

export function ScanProgressBar({ t, progress, scanning }: ScanProgressBarProps) {
  const percent = Math.min(100, Math.max(0, progress?.percent ?? 0));
  const done = percent >= 100 && !scanning;
  const label = progress?.label ?? (scanning ? t.progressScanning : t.progressIdle);

  return (
    <section aria-label={t.progressTitle} className="soc-panel rounded-xl p-4 space-y-2.5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
          <Activity className={`w-4 h-4 ${scanning ? 'text-cyan-400 animate-pulse' : 'text-slate-500'}`} aria-hidden="true" />
          {t.progressTitle}
        </div>
        <div className="text-[11px] font-mono tabular-nums text-slate-400">
          {done ? t.progressDone : `${percent}%`}
        </div>
      </div>

      <div
        className="h-2 w-full rounded-full bg-[#06090F] border border-slate-800 overflow-hidden"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={t.progressTitle}
      >
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            done
              ? 'bg-emerald-500'
              : 'bg-gradient-to-r from-cyan-500 via-sky-400 to-emerald-400'
          } ${scanning ? 'shadow-[0_0_12px_rgba(34,211,238,0.55)]' : ''}`}
          style={{ width: `${percent}%` }}
        />
      </div>

      <div className="text-[11px] text-slate-400 truncate">{label}</div>
    </section>
  );
}
