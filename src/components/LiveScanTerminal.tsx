import { Terminal, Trash2 } from 'lucide-react';
import { useEffect, useRef } from 'react';
import type { LabTranslations } from '../i18n/labTranslations';
import type { ScanLogEvent, ScanLogLevel } from '../types/realtime';

interface LiveScanTerminalProps {
  t: LabTranslations;
  logs: ScanLogEvent[];
  connected: boolean;
  scanning: boolean;
  onClear: () => void;
}

const LEVEL_STYLES: Record<ScanLogLevel, { text: string; prefix: string }> = {
  info: { text: 'text-slate-300', prefix: 'text-sky-400' },
  success: { text: 'text-emerald-300', prefix: 'text-emerald-400' },
  warn: { text: 'text-amber-200', prefix: 'text-amber-400' },
  error: { text: 'text-red-300', prefix: 'text-red-400' },
  debug: { text: 'text-cyan-300', prefix: 'text-cyan-400' },
};

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toISOString().slice(11, 19);
}

export function LiveScanTerminal({ t, logs, connected, scanning, onClear }: LiveScanTerminalProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = scrollRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [logs.length]);

  return (
    <section aria-label={t.terminalTitle} className="soc-panel rounded-xl overflow-hidden">
      <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-slate-800/80">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            <h2 className="text-sm font-bold text-slate-50">{t.terminalTitle}</h2>
            <span
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-semibold ${
                connected
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-red-500/10 border-red-500/30 text-red-300'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-400' : 'bg-red-400'}`} />
              {connected ? t.terminalConnected : t.terminalDisconnected}
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5 truncate">{t.terminalSubtitle}</p>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#06090F] border border-slate-700 text-slate-300 text-[11px] font-semibold hover:border-slate-500 transition-colors cursor-pointer shrink-0"
        >
          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
          {t.terminalClear}
        </button>
      </div>

      <div
        ref={scrollRef}
        className="h-72 overflow-y-auto bg-[#04060A] px-3 py-2 font-mono text-[11px] leading-relaxed"
        aria-live="polite"
        aria-atomic="false"
      >
        {logs.length === 0 ? (
          <div className="h-full grid place-items-center text-center text-slate-500 px-6">
            <div>
              <Terminal className="w-6 h-6 mx-auto mb-2 text-slate-600" aria-hidden="true" />
              <div>{t.terminalEmpty}</div>
              {scanning && <div className="mt-1 text-cyan-400 animate-pulse">{t.terminalWaiting}</div>}
            </div>
          </div>
        ) : (
          logs.map((log) => {
            const style = LEVEL_STYLES[log.level];
            return (
              <div key={log.id} className="flex gap-2 py-0.5">
                <span className="text-slate-600 shrink-0 tabular-nums">{formatTime(log.ts)}</span>
                <span className={`${style.prefix} shrink-0 uppercase`}>
                  {log.level === 'warn' ? 'WARN' : log.level === 'error' ? 'ERR' : log.level === 'success' ? 'OK' : log.level.toUpperCase()}
                </span>
                {log.moduleId && (
                  <span className="text-slate-500 shrink-0">[{log.moduleId}]</span>
                )}
                <span className={`${style.text} break-words min-w-0`}>{log.message}</span>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
