import {
  AlertTriangle,
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  ShieldCheck,
} from 'lucide-react';
import { useState } from 'react';
import { useAuth } from '../hooks/useAuth.tsx';
import { SiteAgentDownloadButton } from './SiteAgentDownloadButton';

type Lang = 'bn' | 'en';

const OPERATOR_USERNAME = 'zyraxon';

const COPY = {
  bn: {
    brand: 'SentinelGlobe',
    badge: 'সিকিউর অপারেটর অ্যাক্সেস',
    setupTitle: 'প্রথমবার অ্যাডমিন সেটআপ',
    setupSubtitle:
      'এই ড্যাশবোর্ডে ডিফেন্স কন্ট্রোল, স্ক্যানিং ও ইন্টিগ্রেশন আছে। শক্তিশালী একটি পাসওয়ার্ড দিয়ে অ্যাক্সেস লক করুন।',
    loginTitle: 'অপারেটর সাইন ইন',
    loginSubtitle: 'ডিফেন্স কন্ট্রোল ও লাইভ থ্রেট ডেটা দেখতে সাইন ইন করুন।',
    username: 'ইউজারনেম',
    password: 'পাসওয়ার্ড',
    confirm: 'পাসওয়ার্ড নিশ্চিত করুন',
    setupBtn: 'অ্যাডমিন তৈরি করুন',
    loginBtn: 'সাইন ইন',
    sso: 'OIDC SSO দিয়ে সাইন ইন',
    ssoHint: 'SSO কনফিগার করা আছে',
    noSso: 'SSO কনফিগার করা নেই',
    mismatch: 'দুটি পাসওয়ার্ড মিলছে না।',
    short: 'পাসওয়ার্ড অন্তত ৭ অক্ষরের হতে হবে।',
    localOnly: 'লোকাল অ্যাডমিন',
    secure: 'HttpOnly সেশন · scrypt হ্যাশ · রেট লিমিটেড লগইন',
    warning:
      'এটি একটি নিরাপত্তা কনসোল। অননুমোদিত অ্যাক্সেস বা স্ক্যানিং আইনত নিষিদ্ধ।',
    show: 'দেখান',
    hide: 'লুকান',
    loading: 'সেশন যাচাই হচ্ছে…',
  },
  en: {
    brand: 'SentinelGlobe',
    badge: 'Secure operator access',
    setupTitle: 'First-run admin setup',
    setupSubtitle:
      'This dashboard controls defense, scanning and integrations. Lock it with a strong password.',
    loginTitle: 'Operator sign in',
    loginSubtitle: 'Sign in to view defense controls and live threat data.',
    username: 'Username',
    password: 'Password',
    confirm: 'Confirm password',
    setupBtn: 'Create admin',
    loginBtn: 'Sign in',
    sso: 'Sign in with OIDC SSO',
    ssoHint: 'SSO is configured',
    noSso: 'SSO is not configured',
    mismatch: 'The passwords do not match.',
    short: 'Password must be at least 7 characters.',
    localOnly: 'Local admin',
    secure: 'HttpOnly session · scrypt hash · rate-limited login',
    warning: 'This is a security console. Unauthorized access or scanning is illegal.',
    show: 'Show',
    hide: 'Hide',
    loading: 'Verifying session…',
  },
} as const;

const L = (lang: Lang, bn: string, en: string) => (lang === 'bn' ? bn : en);

function AuthScreen({ lang, onLang }: { lang: Lang; onLang: (lang: Lang) => void }) {
  const { status, error, login, setup, clearError } = useAuth();
  const copy = COPY[lang];
  const setupMode = Boolean(status?.setupRequired);
  const username = OPERATOR_USERNAME;
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLocalError(null);
    clearError();
    if (password.length < 7) {
      setLocalError(copy.short);
      return;
    }
    if (setupMode && password !== confirm) {
      setLocalError(copy.mismatch);
      return;
    }
    setBusy(true);
    try {
      if (setupMode) {
        await setup(username || 'admin', password);
      } else {
        await login(username, password);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden flex items-center justify-center px-4 py-10">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_15%_0%,rgba(239,68,68,0.14),transparent_38%),radial-gradient(circle_at_85%_100%,rgba(34,211,238,0.10),transparent_42%)]" />
      <div className="absolute inset-0 pointer-events-none opacity-[0.14] [background-image:linear-gradient(rgba(148,163,184,0.18)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.18)_1px,transparent_1px)] [background-size:44px_44px]" />
      <SiteAgentDownloadButton lang={lang} floating />

      <div className="relative w-full max-w-5xl grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        <div className="hidden lg:flex flex-col justify-between rounded-2xl border border-red-500/20 bg-[#0B101B]/85 p-8 shadow-[0_0_60px_rgba(239,68,68,0.08)]">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-[11px] font-semibold text-red-200">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              {copy.badge}
            </div>
            <h1 className="mt-6 text-4xl font-extrabold tracking-tight text-white font-display">
              {copy.brand}
            </h1>
            <p className="mt-3 text-sm leading-relaxed text-slate-400">
              {copy.setupSubtitle}
            </p>
          </div>

          <div className="space-y-3 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              {copy.secure}
            </div>
            <div className="flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              JA3 · TLSH · ASN / subnet detection
            </div>
            <div className="flex items-center gap-2">
              <LockKeyhole className="w-4 h-4 text-fuchsia-400" />
              Local firewall · SMTP · Offline intel
            </div>
          </div>

          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-[11px] leading-relaxed text-amber-200/80 flex gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            {copy.warning}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-[#0B101B]/95 p-6 sm:p-8 shadow-2xl">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-xl bg-red-500/10 border border-red-500/30 grid place-items-center">
                <ShieldCheck className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="text-sm font-bold text-white">{copy.brand}</div>
                <div className="text-[10px] text-slate-500">{copy.badge}</div>
              </div>
            </div>
            <div className="inline-flex items-center p-0.5 rounded-lg bg-[#06090F] border border-slate-800">
              {(['bn', 'en'] as Lang[]).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => onLang(value)}
                  className={`px-2 py-1 rounded-md text-[10px] font-semibold cursor-pointer ${
                    lang === value ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-200'
                  }`}
                >
                  {value === 'bn' ? 'বাংলা' : 'English'}
                </button>
              ))}
            </div>
          </div>

          <h2 className="mt-6 text-xl font-bold text-white">
            {setupMode ? copy.setupTitle : copy.loginTitle}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            {setupMode ? copy.setupSubtitle : copy.loginSubtitle}
          </p>

          <form onSubmit={(event) => void submit(event)} className="mt-5 space-y-3">
            <label className="block">
              <span className="text-[11px] font-semibold text-slate-300">{copy.username}</span>
              <input
                value={username}
                readOnly
                aria-readonly="true"
                autoComplete="username"
                className="mt-1 w-full cursor-not-allowed rounded-lg border border-slate-800 bg-[#080B12] px-3 py-2.5 text-sm text-slate-400 focus:outline-none"
              />
            </label>

            <label className="block">
              <span className="text-[11px] font-semibold text-slate-300">{copy.password}</span>
              <div className="relative mt-1">
                <input
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  data-lpignore="true"
                  className="w-full rounded-lg bg-[#04060A] border border-slate-700 px-3 py-2.5 pr-20 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
                  placeholder={L(lang, 'পাসওয়ার্ড লিখুন', 'Enter password')}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  {showPassword ? copy.hide : copy.show}
                </button>
              </div>
            </label>

            {setupMode && (
              <label className="block">
                <span className="text-[11px] font-semibold text-slate-300">{copy.confirm}</span>
                <input
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  className="mt-1 w-full rounded-lg bg-[#04060A] border border-slate-700 px-3 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
                  placeholder="••••••••"
                />
              </label>
            )}

            {(localError || error) && (
              <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-[11px] text-red-200">
                {localError || error}
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-60 px-4 py-2.5 text-sm font-bold text-white transition-colors cursor-pointer"
            >
              {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
              {setupMode ? copy.setupBtn : copy.loginBtn}
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="mt-4 pt-4 border-t border-slate-800">
            {status?.ssoEnabled ? (
              <a
                href="/api/auth/oidc/start"
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 transition-colors"
              >
                <LockKeyhole className="w-4 h-4" />
                {copy.sso}
              </a>
            ) : (
              <div className="text-[10px] text-slate-500 text-center">{copy.noSso}</div>
            )}
          </div>

          <div className="mt-4 text-[10px] text-slate-500 text-center">{copy.localOnly}</div>
        </div>
      </div>
    </div>
  );
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { status, loading } = useAuth();
  const [lang, setLang] = useState<Lang>('bn');

  if (loading || !status) {
    return (
      <div className="min-h-screen relative grid place-items-center bg-[#06090F] text-slate-300">
        <SiteAgentDownloadButton lang={lang} floating />
        <div className="inline-flex items-center gap-2 text-xs">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          {COPY[lang].loading}
        </div>
      </div>
    );
  }

  if (!status.authenticated) {
    return <AuthScreen lang={lang} onLang={setLang} />;
  }

  return <>{children}</>;
}
