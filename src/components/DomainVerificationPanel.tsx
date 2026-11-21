import { BadgeCheck, Copy, Globe2, Loader2, ShieldQuestion } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { LabTranslations } from '../i18n/labTranslations';
import type { DomainVerificationStatus } from '../types/cyber';

interface DomainVerificationPanelProps {
  t: LabTranslations;
  defaultDomain?: string;
  onVerified?: (domain: string) => void;
}

export function DomainVerificationPanel({
  t,
  defaultDomain,
  onVerified,
}: DomainVerificationPanelProps) {
  const [domain, setDomain] = useState(defaultDomain ?? '');
  const [method, setMethod] = useState<'dns-txt' | 'http-file'>('dns-txt');
  const [status, setStatus] = useState<DomainVerificationStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (defaultDomain && defaultDomain.length >= 3) {
      setDomain(defaultDomain);
    }
  }, [defaultDomain]);

  const loadStatus = useCallback(async (value: string) => {
    if (value.trim().length < 3) return;
    try {
      const res = await fetch(
        `/api/verify-ownership/status?target=${encodeURIComponent(value.trim())}`,
      );
      if (res.ok) {
        setStatus((await res.json()) as DomainVerificationStatus);
      }
    } catch {
      // status panel is best-effort
    }
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (domain.trim().length < 3) {
      setStatus(null);
      return;
    }
    debounceRef.current = setTimeout(() => void loadStatus(domain), 500);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [domain, loadStatus]);

  const handleVerify = async () => {
    if (domain.trim().length < 3) return;
    setChecking(true);
    setError(null);
    try {
      const res = await fetch('/api/verify-ownership/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: domain.trim(), method }),
      });
      const payload = (await res.json()) as DomainVerificationStatus & { error?: string; details?: string };
      setStatus(payload);
      if (payload.verified) {
        onVerified?.(payload.domain);
      } else {
        setError(payload.error ?? 'Verification failed.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed.');
    } finally {
      setChecking(false);
    }
  };

  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      // clipboard may be blocked
    }
  };

  const verified = Boolean(status?.verified);

  return (
    <section aria-label={t.verifyTitle} className="soc-panel rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            {verified ? (
              <BadgeCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            ) : (
              <ShieldQuestion className="w-4 h-4 text-amber-400" aria-hidden="true" />
            )}
            <h2 className="text-sm font-bold text-slate-50">{t.verifyTitle}</h2>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5 max-w-2xl">{t.verifySubtitle}</p>
        </div>
        <span
          className={`px-2 py-0.5 rounded-full border text-[10px] font-semibold whitespace-nowrap ${
            verified
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          }`}
        >
          {verified ? t.verifyVerified : t.verifyPending}
        </span>
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Globe2 className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" aria-hidden="true" />
          <input
            type="text"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            placeholder={t.verifyDomainPlaceholder}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[#06090F] border border-slate-700 focus:border-cyan-500 focus:outline-none text-xs text-slate-100 placeholder:text-slate-500 font-mono"
          />
        </div>
        <select
          value={method}
          onChange={(event) => setMethod(event.target.value === 'http-file' ? 'http-file' : 'dns-txt')}
          className="px-3 py-2 rounded-lg bg-[#06090F] border border-slate-700 focus:border-cyan-500 focus:outline-none text-xs text-slate-200 cursor-pointer"
        >
          <option value="dns-txt">{t.verifyMethodDns}</option>
          <option value="http-file">{t.verifyMethodHttp}</option>
        </select>
        <button
          type="button"
          onClick={() => void handleVerify()}
          disabled={checking || domain.trim().length < 3}
          className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors cursor-pointer whitespace-nowrap"
        >
          {checking && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />}
          {checking ? t.verifyChecking : t.verifyCheckBtn}
        </button>
      </div>

      {error && (
        <div className="text-[11px] text-red-300 bg-red-950/40 border border-red-500/30 rounded-lg px-3 py-2">
          {error}
        </div>
      )}

      {status && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
          <div className="rounded-lg bg-[#06090F] border border-slate-800 p-2.5 space-y-1.5">
            <div className="text-slate-400">{t.verifyTxtHost}</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-cyan-200 break-all">{status.txtRecordHost}</code>
              <button
                type="button"
                onClick={() => void copy('txtHost', status.txtRecordHost)}
                className="text-slate-400 hover:text-cyan-300 cursor-pointer shrink-0"
                aria-label="Copy TXT host"
              >
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>
            <div className="text-slate-400 pt-1">{t.verifyTxtValue}</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-emerald-200 break-all">{status.txtRecordValue}</code>
              <button
                type="button"
                onClick={() => void copy('txtValue', status.txtRecordValue)}
                className="text-slate-400 hover:text-emerald-300 cursor-pointer shrink-0"
                aria-label="Copy TXT value"
              >
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>

          <div className="rounded-lg bg-[#06090F] border border-slate-800 p-2.5 space-y-1.5">
            <div className="text-slate-400">{t.verifyHttpPath}</div>
            <code className="block text-cyan-200 break-all">{status.httpFilePath}</code>
            <div className="text-slate-400 pt-1">{t.verifyHttpContent}</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-emerald-200 break-all">{status.httpFileContent}</code>
              <button
                type="button"
                onClick={() => void copy('httpContent', status.httpFileContent)}
                className="text-slate-400 hover:text-emerald-300 cursor-pointer shrink-0"
                aria-label="Copy HTTP file content"
              >
                <Copy className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="text-[10px] text-slate-500 flex items-center gap-2">
        <span>{t.verifyHint}</span>
        {copied && <span className="text-emerald-400">copied</span>}
      </div>
    </section>
  );
}
