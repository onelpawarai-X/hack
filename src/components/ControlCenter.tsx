import {
  Activity,
  BellRing,
  Check,
  Clock,
  Cloud,
  Copy,
  Database,
  Download,
  Eye,
  Fingerprint,
  Globe,
  HardDrive,
  KeyRound,
  Loader2,
  LockKeyhole,
  LogOut,
  Mail,
  Network,
  Plus,
  Radio,
  RefreshCw,
  RotateCw,
  Send,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  TestTube2,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useControlCenter } from '../hooks/useControlCenter.ts';
import type { AlertChannel, DetectionConfig } from '../types/controlCenter.ts';
import type { Language, ThreatSeverity } from '../types/cyber.ts';

type Tab = 'overview' | 'sensors' | 'waf' | 'integrations' | 'data' | 'detection';

interface ControlCenterProps {
  open: boolean;
  onClose: () => void;
  lang: Language;
  user: { username: string; role: string } | null;
  onLogout: () => void;
  autoDefense: boolean;
  onToggleAutoDefense: (enabled: boolean) => void;
}

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function timeAgo(iso: string | undefined, lang: Language): string {
  if (!iso) return L(lang, 'কখনো না', 'never');
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return L(lang, `${diff} সেকেন্ড আগে`, `${diff}s ago`);
  if (diff < 3600) return L(lang, `${Math.floor(diff / 60)} মিনিট আগে`, `${Math.floor(diff / 60)}m ago`);
  if (diff < 86400) return L(lang, `${Math.floor(diff / 3600)} ঘণ্টা আগে`, `${Math.floor(diff / 3600)}h ago`);
  return L(lang, `${Math.floor(diff / 86400)} দিন আগে`, `${Math.floor(diff / 86400)}d ago`);
}

function statusDot(ok: boolean): string {
  return ok ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]' : 'bg-slate-600';
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-[#06090F]/75 p-4 ${className}`}>
      {children}
    </div>
  );
}

function SectionTitle({
  icon,
  title,
  subtitle,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
}) {
  return (
    <div className="flex items-start gap-2 mb-3">
      <span className="mt-0.5 text-cyan-400">{icon}</span>
      <div>
        <h3 className="text-sm font-bold text-slate-100">{title}</h3>
        {subtitle && <p className="text-[10px] text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  );
}

function Stat({ label, value, tone = 'text-slate-100' }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-[#04060A] px-3 py-2.5">
      <div className="text-[10px] text-slate-500">{label}</div>
      <div className={`text-lg font-bold font-mono tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`inline-flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold transition-colors cursor-pointer disabled:opacity-50 ${
        checked
          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
          : 'border-slate-700 bg-[#04060A] text-slate-400'
      }`}
    >
      <span className={`relative w-7 h-3.5 rounded-full ${checked ? 'bg-emerald-500/70' : 'bg-slate-700'}`}>
        <span
          className={`absolute top-0.5 left-0.5 w-2.5 h-2.5 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-3.5' : ''
          }`}
        />
      </span>
      {label}
    </button>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="text-[10px] font-semibold text-slate-400">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        type={type}
        className="mt-1 w-full rounded-lg bg-[#04060A] border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
      />
    </label>
  );
}

function CopyButton({ text, lang }: { text: string; lang: Language }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          setCopied(false);
        }
      }}
      className="inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-[9px] text-slate-300 hover:border-cyan-500/40 cursor-pointer"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? L(lang, 'কপি হয়েছে', 'Copied') : L(lang, 'কপি', 'Copy')}
    </button>
  );
}

function ActionButton({
  children,
  onClick,
  disabled,
  tone = 'cyan',
  icon,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  tone?: 'cyan' | 'red' | 'emerald' | 'slate' | 'fuchsia';
  icon?: React.ReactNode;
}) {
  const tones = {
    cyan: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200 hover:bg-cyan-500/20',
    red: 'border-red-500/40 bg-red-500/10 text-red-200 hover:bg-red-500/20',
    emerald: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20',
    slate: 'border-slate-700 bg-[#04060A] text-slate-300 hover:border-slate-500',
    fuchsia: 'border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-200 hover:bg-fuchsia-500/20',
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold transition-colors cursor-pointer disabled:opacity-50 ${tones[tone]}`}
    >
      {icon}
      {children}
    </button>
  );
}

function DetectionCards({ config, lang }: { config: DetectionConfig | null; lang: Language }) {
  if (!config) return null;
  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
      <Stat label={L(lang, 'আইপি রেট লিমিট / মিনিট', 'IP rate limit / min')} value={String(config.ipRateLimit)} tone="text-cyan-300" />
      <Stat label={L(lang, 'সাবনেট /24 লিমিট', 'Subnet /24 limit')} value={String(config.subnetRateLimit)} tone="text-orange-300" />
      <Stat label={L(lang, 'ASN লিমিট', 'ASN limit')} value={String(config.asnRateLimit)} tone="text-fuchsia-300" />
      <Stat label={L(lang, 'অটো-ব্লক থ্রেশহোল্ড', 'Auto-block threshold')} value={String(config.autoBlockAfter)} tone="text-red-300" />
      <Stat label={L(lang, 'টারপিট ডিলে', 'Tarpit delay')} value={`${config.tarpitMs} ms`} tone="text-amber-300" />
      <Stat label={L(lang, 'উইন্ডো', 'Window')} value={`${config.windowSeconds}s`} tone="text-slate-200" />
    </div>
  );
}

export function ControlCenter({
  open,
  onClose,
  lang,
  user,
  onLogout,
  autoDefense,
  onToggleAutoDefense,
}: ControlCenterProps) {
  const cc = useControlCenter(lang);
  const [tab, setTab] = useState<Tab>('overview');
  const [sensorForm, setSensorForm] = useState({ id: 'vps-fra-1', name: 'Frankfurt sensor', region: 'eu-central' });
  const [agentForm, setAgentForm] = useState({ id: 'vps-fra-1', region: 'eu-central' });
  const [wafIp, setWafIp] = useState('');
  const [slackUrl, setSlackUrl] = useState('');
  const [tgToken, setTgToken] = useState('');
  const [tgChat, setTgChat] = useState('');
  const [siemUrl, setSiemUrl] = useState('');
  const [policy, setPolicy] = useState<{ minSeverity: ThreatSeverity; notifyOnBlock: boolean }>({
    minSeverity: 'HIGH',
    notifyOnBlock: true,
  });
  const [smtpForm, setSmtpForm] = useState({
    host: '',
    port: '587',
    secure: false,
    user: '',
    pass: '',
    from: '',
    autoSend: false,
  });
  const [smtpTestTo, setSmtpTestTo] = useState('');
  const [pruneDays, setPruneDays] = useState('30');
  const [abuseIp, setAbuseIp] = useState('');
  const [abuseTo, setAbuseTo] = useState('');

  useEffect(() => {
    const integration = cc.data.integrations;
    if (integration) {
      setPolicy({
        minSeverity: integration.minSeverity,
        notifyOnBlock: integration.notifyOnBlock,
      });
      if (!smtpForm.host && integration.smtp.host) {
        setSmtpForm({
          host: integration.smtp.host,
          port: String(integration.smtp.port ?? 587),
          secure: Boolean(integration.smtp.secure),
          user: '',
          pass: '',
          from: integration.smtp.from ?? '',
          autoSend: integration.smtp.autoSend,
        });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cc.data.integrations]);

  if (!open) return null;

  const tabs: Array<{ id: Tab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: L(lang, 'ওভারভিউ', 'Overview'), icon: <Activity className="w-3.5 h-3.5" /> },
    { id: 'sensors', label: L(lang, 'সেন্সর', 'Sensors'), icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'waf', label: 'WAF', icon: <Cloud className="w-3.5 h-3.5" /> },
    { id: 'integrations', label: L(lang, 'ইন্টিগ্রেশন', 'Integrations'), icon: <BellRing className="w-3.5 h-3.5" /> },
    { id: 'data', label: L(lang, 'ডেটা', 'Data'), icon: <Database className="w-3.5 h-3.5" /> },
    { id: 'detection', label: L(lang, 'ডিটেকশন', 'Detection'), icon: <Fingerprint className="w-3.5 h-3.5" /> },
  ];

  const onlineSensors = cc.data.sensors?.nodes.filter((node) => node.status === 'online').length ?? 0;
  const wafReady = cc.data.wafProviders.filter((provider) => provider.configured).length;
  const alertsReady =
    (cc.data.integrations?.integrations.filter((integration) => integration.configured).length ?? 0) +
    (cc.data.integrations?.smtp.configured ? 1 : 0);

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-2 sm:p-5">
      <div className="w-full max-w-6xl max-h-[94vh] flex flex-col rounded-2xl border border-slate-700 bg-[#080C14] shadow-2xl overflow-hidden">
        <div className="flex items-start justify-between gap-3 px-4 sm:px-6 py-3 border-b border-slate-800 bg-[#06090F]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 grid place-items-center">
              <SlidersHorizontal className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                {L(lang, 'সেন্টিনেল কন্ট্রোল সেন্টার', 'Sentinel Control Center')}
              </h2>
              <p className="text-[10px] text-slate-500">
                {L(
                  lang,
                  'অথ, WAF, সেন্সর, অ্যালার্ট, SMTP ও ইভেন্ট স্টোর — সব এক জায়গায়।',
                  'Auth, WAF, sensors, alerts, SMTP and the event store in one place.',
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void cc.refresh()}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1.5 text-[10px] text-slate-300 hover:border-cyan-500/40 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${cc.loading ? 'animate-spin' : ''}`} />
              {L(lang, 'রিফ্রেশ', 'Refresh')}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 p-1.5 text-slate-400 hover:text-white cursor-pointer"
              aria-label={L(lang, 'বন্ধ', 'Close')}
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex gap-1 overflow-x-auto px-3 sm:px-5 py-2 border-b border-slate-800 bg-[#06090F]">
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-[10px] font-semibold transition-colors cursor-pointer ${
                tab === item.id
                  ? 'bg-cyan-500/15 border border-cyan-500/40 text-cyan-200'
                  : 'border border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-5">
          {cc.notice && (
            <div
              className={`rounded-lg border px-3 py-2 text-[11px] flex items-start justify-between gap-3 ${
                cc.notice.kind === 'ok'
                  ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-200'
                  : 'border-red-500/40 bg-red-950/40 text-red-200'
              }`}
            >
              <span>{cc.notice.text}</span>
              <button type="button" onClick={cc.clearNotice} className="shrink-0 cursor-pointer">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {tab === 'overview' && (
            <div className="space-y-5">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                <Stat label={L(lang, 'সংরক্ষিত ইভেন্ট', 'Stored events')} value={(cc.data.dbStats?.events ?? 0).toLocaleString('en-US')} tone="text-cyan-300" />
                <Stat label={L(lang, 'অনলাইন সেন্সর', 'Online sensors')} value={String(onlineSensors)} tone="text-emerald-300" />
                <Stat label={L(lang, 'WAF রেডি', 'WAF ready')} value={`${wafReady}/${cc.data.wafProviders.length}`} tone="text-orange-300" />
                <Stat label={L(lang, 'অ্যালার্ট চ্যানেল', 'Alert channels')} value={String(alertsReady)} tone="text-fuchsia-300" />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <SectionTitle
                    icon={<ShieldCheck className="w-4 h-4" />}
                    title={L(lang, 'অপারেটর সেশন', 'Operator session')}
                    subtitle={L(lang, 'লোকাল scrypt অ্যাডমিন + ঐচ্ছিক OIDC SSO', 'Local scrypt admin + optional OIDC SSO')}
                  />
                  <div className="space-y-2 text-[11px] text-slate-300">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">{L(lang, 'ইউজার', 'User')}</span>
                      <span className="font-mono text-slate-100">{user?.username ?? '—'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">{L(lang, 'রোল', 'Role')}</span>
                      <span className="text-slate-200">{user?.role ?? '—'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">SSO</span>
                      <span className={cc.data.system?.auth.ssoEnabled ? 'text-emerald-300' : 'text-slate-500'}>
                        {cc.data.system?.auth.ssoEnabled ? L(lang, 'কনফিগার্ড', 'Configured') : L(lang, 'নেই', 'Not configured')}
                      </span>
                    </div>
                  </div>
                  <div className="mt-3">
                    <ActionButton tone="red" icon={<LogOut className="w-3.5 h-3.5" />} onClick={onLogout}>
                      {L(lang, 'সাইন আউট', 'Sign out')}
                    </ActionButton>
                  </div>
                </Card>

                <Card>
                  <SectionTitle
                    icon={<Server className="w-4 h-4" />}
                    title={L(lang, 'সিস্টেম', 'System')}
                    subtitle={L(lang, 'রানটাইম ও ডেটাবেস স্বাস্থ্য', 'Runtime and database health')}
                  />
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-2">
                      <div className="text-[9px] text-slate-500">Node</div>
                      <div className="font-mono text-slate-200">{cc.data.system?.node ?? '—'}</div>
                    </div>
                    <div className="rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-2">
                      <div className="text-[9px] text-slate-500">{L(lang, 'আপটাইম', 'Uptime')}</div>
                      <div className="font-mono text-slate-200">
                        {cc.data.system ? `${Math.floor(cc.data.system.uptimeSeconds / 60)}m` : '—'}
                      </div>
                    </div>
                    <div className="rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-2">
                      <div className="text-[9px] text-slate-500">RSS</div>
                      <div className="font-mono text-slate-200">{formatBytes(cc.data.system?.memory.rss ?? 0)}</div>
                    </div>
                    <div className="rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-2">
                      <div className="text-[9px] text-slate-500">DB</div>
                      <div className="font-mono text-slate-200">{formatBytes(cc.data.dbStats?.sizeBytes ?? 0)}</div>
                    </div>
                  </div>
                </Card>
              </div>

              <Card>
                <SectionTitle
                  icon={<Zap className="w-4 h-4" />}
                  title={L(lang, 'দ্রুত অ্যাকশন', 'Quick actions')}
                  subtitle={L(lang, 'সব অ্যাকশন আসল API-তে যায়', 'Every action calls a real API')}
                />
                <div className="flex flex-wrap gap-2">
                  <ActionButton icon={<Cloud className="w-3.5 h-3.5" />} onClick={() => void cc.syncWaf()} disabled={cc.busy}>
                    {L(lang, 'এজ ব্লকলিস্ট সিঙ্ক', 'Sync edge blocklist')}
                  </ActionButton>
                  <ActionButton tone="emerald" icon={<Terminal className="w-3.5 h-3.5" />} onClick={() => setTab('sensors')}>
                    {L(lang, 'এজেন্ট কমান্ড', 'Agent command')}
                  </ActionButton>
                  <ActionButton tone="fuchsia" icon={<BellRing className="w-3.5 h-3.5" />} onClick={() => setTab('integrations')}>
                    {L(lang, 'অ্যালার্ট টেস্ট', 'Test alerts')}
                  </ActionButton>
                  <ActionButton tone="slate" icon={<Download className="w-3.5 h-3.5" />} onClick={() => setTab('data')}>
                    {L(lang, 'ডেটা এক্সপোর্ট', 'Export data')}
                  </ActionButton>
                </div>
              </Card>
            </div>
          )}

          {tab === 'sensors' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SectionTitle
                  icon={<Network className="w-4 h-4" />}
                  title={L(lang, 'ডিস্ট্রিবিউটেড হানিপট নেটওয়ার্ক', 'Distributed honeypot network')}
                  subtitle={L(lang, 'একাধিক VPS/রিজিয়ন থেকে আসল রিকোয়েস্ট ইনজেস্ট করুন।', 'Ingest real requests from multiple VPS regions.')}
                />
                <Toggle
                  checked={cc.data.sensors?.autoBlock ?? true}
                  onChange={(value) => void cc.setSensorAutoBlock(value)}
                  label={L(lang, 'সেন্সর অটো-ব্লক', 'Sensor auto-block')}
                  disabled={cc.busy}
                />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <SectionTitle icon={<KeyRound className="w-4 h-4" />} title={L(lang, 'ইনজেস্ট টোকেন', 'Ingest token')} />
                  <div className="flex items-center gap-2">
                    <code className="flex-1 min-w-0 truncate rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-1.5 text-[10px] font-mono text-cyan-200">
                      {cc.token ?? cc.data.sensors?.tokenPreview ?? '—'}
                    </code>
                    <ActionButton tone="slate" icon={<Eye className="w-3.5 h-3.5" />} onClick={() => void cc.revealToken()}>
                      {L(lang, 'দেখান', 'Reveal')}
                    </ActionButton>
                    {cc.token && <CopyButton text={cc.token} lang={lang} />}
                  </div>
                  <p className="mt-2 text-[10px] text-slate-500">
                    {L(
                      lang,
                      'টোকেন শুধু সেন্সর এজেন্টের জন্য। রোটেট করলে সব এজেন্ট আপডেট করতে হবে।',
                      'This token is only for sensor agents. Rotating it requires updating every agent.',
                    )}
                  </p>
                  <div className="mt-2 flex gap-2">
                    <ActionButton
                      tone="red"
                      icon={<RotateCw className="w-3.5 h-3.5" />}
                      onClick={() => {
                        const ok = window.confirm(
                          lang === 'bn'
                            ? 'টোকেন রোটেট করলে সব পুরোনো সেন্সর এজেন্ট বন্ধ হয়ে যাবে। চালিয়ে যাবেন?'
                            : 'Rotating the token immediately stops every existing sensor agent. Continue?',
                        );
                        if (ok) void cc.rotateToken();
                      }}
                      disabled={cc.busy}
                    >
                      {L(lang, 'টোকেন রোটেট', 'Rotate token')}
                    </ActionButton>
                  </div>
                </Card>

                <Card>
                  <SectionTitle icon={<Globe className="w-4 h-4" />} title={L(lang, 'ইনজেস্ট এন্ডপয়েন্ট', 'Ingest endpoint')} />
                  <div className="flex items-center gap-2">
                    <code className="flex-1 min-w-0 truncate rounded-lg bg-[#04060A] border border-slate-800 px-2.5 py-1.5 text-[10px] font-mono text-slate-300">
                      {cc.data.sensors?.ingestUrl ?? '—'}
                    </code>
                    {cc.data.sensors?.ingestUrl && <CopyButton text={cc.data.sensors.ingestUrl} lang={lang} />}
                  </div>
                  <p className="mt-2 text-[10px] text-slate-500">
                    {L(lang, 'হেডার: ', 'Header: ')}
                    <code className="text-cyan-300">X-Sentinel-Sensor-Token</code>
                  </p>
                </Card>
              </div>

              <Card>
                <SectionTitle
                  icon={<Terminal className="w-4 h-4" />}
                  title={L(lang, 'VPS এজেন্ট কমান্ড', 'VPS agent command')}
                  subtitle={L(lang, 'VPS-এ রিপো ক্লোন করে এই কমান্ড চালান।', 'Clone the repo on the VPS and run this command.')}
                />
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <Field label={L(lang, 'সেন্সর আইডি', 'Sensor id')} value={agentForm.id} onChange={(value) => setAgentForm((prev) => ({ ...prev, id: value }))} />
                  <Field label={L(lang, 'রিজিয়ন', 'Region')} value={agentForm.region} onChange={(value) => setAgentForm((prev) => ({ ...prev, region: value }))} />
                </div>
                <div className="mt-2 flex gap-2">
                  <ActionButton tone="emerald" icon={<Terminal className="w-3.5 h-3.5" />} onClick={() => void cc.loadAgentCommand(agentForm.id, agentForm.region)}>
                    {L(lang, 'কমান্ড তৈরি', 'Generate command')}
                  </ActionButton>
                  {cc.agentCommand && <CopyButton text={cc.agentCommand} lang={lang} />}
                </div>
                {cc.agentCommand && (
                  <pre className="mt-2 max-h-32 overflow-auto rounded-lg bg-[#04060A] border border-slate-800 p-2.5 text-[10px] leading-relaxed text-emerald-200 whitespace-pre-wrap">
                    {cc.agentCommand}
                  </pre>
                )}
              </Card>

              <Card>
                <SectionTitle icon={<Plus className="w-4 h-4" />} title={L(lang, 'সেন্সর রেজিস্টার', 'Register a sensor')} />
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <Field label={L(lang, 'আইডি', 'Id')} value={sensorForm.id} onChange={(value) => setSensorForm((prev) => ({ ...prev, id: value }))} />
                  <Field label={L(lang, 'নাম', 'Name')} value={sensorForm.name} onChange={(value) => setSensorForm((prev) => ({ ...prev, name: value }))} />
                  <Field label={L(lang, 'রিজিয়ন', 'Region')} value={sensorForm.region} onChange={(value) => setSensorForm((prev) => ({ ...prev, region: value }))} />
                </div>
                <div className="mt-2">
                  <ActionButton tone="cyan" icon={<Plus className="w-3.5 h-3.5" />} onClick={() => void cc.addSensor(sensorForm)} disabled={cc.busy}>
                    {L(lang, 'সেন্সর যোগ করুন', 'Add sensor')}
                  </ActionButton>
                </div>
              </Card>

              <Card>
                <SectionTitle icon={<Radio className="w-4 h-4" />} title={L(lang, 'সেন্সর নোড', 'Sensor nodes')} />
                {!cc.data.sensors || cc.data.sensors.nodes.length === 0 ? (
                  <div className="text-[11px] text-slate-500">{L(lang, 'এখনো কোনো সেন্সর নেই।', 'No sensors yet.')}</div>
                ) : (
                  <div className="space-y-2">
                    {cc.data.sensors.nodes.map((node) => (
                      <div key={node.id} className="rounded-lg border border-slate-800 bg-[#04060A] p-2.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${statusDot(node.status === 'online')}`} />
                          <span className="font-mono text-[11px] text-slate-100">{node.id}</span>
                          <span className="text-[10px] text-slate-400">{node.name}</span>
                          {node.region && <span className="text-[9px] text-slate-500">{node.region}</span>}
                          <span className={`ml-auto text-[9px] font-semibold ${node.status === 'online' ? 'text-emerald-300' : node.status === 'stale' ? 'text-amber-300' : 'text-slate-500'}`}>
                            {node.status}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-3 text-[9px] text-slate-500">
                          <span>{L(lang, 'সর্বশেষ', 'Last seen')}: {timeAgo(node.lastSeenAt, lang)}</span>
                          <span>{L(lang, 'ইভেন্ট', 'Events')}: {node.eventCount}</span>
                          {node.url && <span className="truncate max-w-[180px]">{node.url}</span>}
                          <div className="ml-auto flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => void cc.setSensorEnabled(node.id, !node.enabled)}
                              className={node.enabled ? 'text-amber-300 hover:text-amber-200 cursor-pointer' : 'text-emerald-300 hover:text-emerald-200 cursor-pointer'}
                            >
                              {node.enabled ? L(lang, 'বন্ধ', 'Disable') : L(lang, 'চালু', 'Enable')}
                            </button>
                            <button
                              type="button"
                              onClick={() => setAgentForm({ id: node.id, region: node.region ?? '' })}
                              className="text-cyan-300 hover:text-cyan-200 cursor-pointer"
                            >
                              {L(lang, 'কমান্ডে ব্যবহার', 'Use in command')}
                            </button>
                            <button
                              type="button"
                              onClick={() => void cc.removeSensor(node.id)}
                              className="inline-flex items-center gap-1 text-red-300 hover:text-red-200 cursor-pointer"
                            >
                              <Trash2 className="w-3 h-3" />
                              {L(lang, 'সরান', 'Remove')}
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {tab === 'waf' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <SectionTitle
                  icon={<Cloud className="w-4 h-4" />}
                  title={L(lang, 'লোকাল এনফোর্সমেন্ট', 'Local enforcement')}
                  subtitle={L(lang, 'কোনো ক্লাউড API নেই। ব্লক লোকাল ডিফেন্স ইঞ্জিনে থাকে এবং nginx/nftables/iptables রুল হিসেবে এক্সপোর্ট হয়।', 'No cloud API. Blocks stay in the local defense engine and export as nginx/nftables/iptables rules.')}
                />
                <Toggle
                  checked={cc.data.wafAutoPush}
                  onChange={(value) => void cc.setWafAutoPush(value)}
                  label={L(lang, 'অটো-পুশ', 'Auto-push')}
                  disabled={cc.busy}
                />
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {cc.data.wafProviders.map((provider) => (
                  <Card key={provider.id}>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${statusDot(provider.configured)}`} />
                      <h3 className="text-sm font-bold text-slate-100">{provider.name}</h3>
                      <span className={`ml-auto text-[9px] font-semibold ${provider.configured ? 'text-emerald-300' : 'text-slate-500'}`}>
                        {provider.configured ? L(lang, 'কনফিগার্ড', 'Configured') : L(lang, 'নেই', 'Not configured')}
                      </span>
                    </div>
                    <p className="mt-1 text-[10px] text-slate-400">{provider.detail}</p>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {provider.env.map((name) => (
                        <code key={name} className="rounded bg-slate-800/70 border border-slate-700 px-1.5 py-0.5 text-[9px] text-slate-300">
                          {name}
                        </code>
                      ))}
                    </div>
                  </Card>
                ))}
              </div>

              <Card>
                <div className="flex flex-wrap items-end gap-2">
                  <div className="flex-1 min-w-[180px]">
                    <Field label={L(lang, 'একটি আইপি ব্লক করুন', 'Block a single IP')} value={wafIp} onChange={setWafIp} placeholder="203.0.113.10" />
                  </div>
                  <ActionButton tone="cyan" icon={<Send className="w-3.5 h-3.5" />} onClick={() => void cc.pushWafIp(wafIp.trim())} disabled={cc.busy || !wafIp.trim()}>
                    {L(lang, 'লোকাল ব্লক', 'Block locally')}
                  </ActionButton>
                  <ActionButton tone="emerald" icon={<Cloud className="w-3.5 h-3.5" />} onClick={() => void cc.syncWaf()} disabled={cc.busy}>
                    {L(lang, 'ফায়ারওয়াল বান্ডল তৈরি', 'Build firewall bundle')}
                  </ActionButton>
                </div>
              </Card>

              <Card>
                <SectionTitle icon={<Clock className="w-4 h-4" />} title={L(lang, 'এনফোর্সমেন্ট লগ', 'Enforcement log')} />
                {cc.data.wafLog.length === 0 ? (
                  <div className="text-[11px] text-slate-500">{L(lang, 'এখনো কোনো সিঙ্ক হয়নি।', 'No sync yet.')}</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-[10px]">
                      <thead className="text-slate-500">
                        <tr>
                          <th className="py-1 pr-2">Time</th>
                          <th className="py-1 pr-2">Provider</th>
                          <th className="py-1 pr-2">Action</th>
                          <th className="py-1 pr-2">IP</th>
                          <th className="py-1 pr-2">Status</th>
                          <th className="py-1">Detail</th>
                        </tr>
                      </thead>
                      <tbody className="text-slate-300">
                        {cc.data.wafLog.slice(0, 20).map((entry) => (
                          <tr key={entry.id} className="border-t border-slate-800/70">
                            <td className="py-1 pr-2 font-mono text-slate-500">{new Date(entry.ts).toLocaleTimeString()}</td>
                            <td className="py-1 pr-2">{entry.provider}</td>
                            <td className="py-1 pr-2">{entry.action}</td>
                            <td className="py-1 pr-2 font-mono">{entry.ip ?? '—'}</td>
                            <td className={`py-1 pr-2 font-semibold ${entry.status === 'ok' ? 'text-emerald-300' : 'text-red-300'}`}>{entry.status}</td>
                            <td className="py-1 truncate max-w-[260px] text-slate-500">{entry.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
          )}

          {tab === 'integrations' && (
            <div className="space-y-4">
              <SectionTitle
                icon={<BellRing className="w-4 h-4" />}
                title={L(lang, 'রিয়েল-টাইম অ্যালার্ট', 'Real-time alerts')}
                subtitle={L(lang, 'লোকাল ইভেন্ট লেজার + নিজের SMTP/Gmail। কোনো থার্ড-পার্টি API নেই।', 'Local event ledger + your own SMTP/Gmail. No third-party API.')}
              />

              <Card>
                <div className="flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 mt-0.5" />
                  <div>
                    <h3 className="text-xs font-bold text-slate-100">{L(lang, 'রিমোট API বন্ধ', 'Remote APIs disabled')}</h3>
                    <p className="mt-1 text-[10px] text-slate-400">
                      {L(lang, 'Slack, Telegram ও SIEM webhook ডেলিভারি বাদ দেওয়া হয়েছে। কোনো থার্ড-পার্টি API বা রেট লিমিট নেই। সব অ্যালার্ট লোকাল ইভেন্ট লেজারে থাকে; ইমেইল যায় শুধু আপনার নিজের SMTP/Gmail দিয়ে।', 'Slack, Telegram and SIEM webhook delivery are removed. No third-party API or rate limit. Alerts stay in the local event ledger; email goes only through your own SMTP/Gmail.')}
                    </p>
                  </div>
                </div>
              </Card>

              <Card>
                <SectionTitle icon={<SlidersHorizontal className="w-4 h-4" />} title={L(lang, 'অ্যালার্ট পলিসি', 'Alert policy')} />
                <div className="flex flex-wrap items-end gap-3">
                  <label className="block">
                    <span className="text-[10px] font-semibold text-slate-400">{L(lang, 'সর্বনিম্ন সিভিয়ারিটি', 'Minimum severity')}</span>
                    <select
                      value={policy.minSeverity}
                      onChange={(event) => setPolicy((prev) => ({ ...prev, minSeverity: event.target.value as ThreatSeverity }))}
                      className="mt-1 block rounded-lg bg-[#04060A] border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-100 focus:outline-none focus:border-cyan-500/60"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="ELEVATED">ELEVATED</option>
                      <option value="CLEAN">CLEAN</option>
                    </select>
                  </label>
                  <Toggle checked={policy.notifyOnBlock} onChange={(value) => setPolicy((prev) => ({ ...prev, notifyOnBlock: value }))} label={L(lang, 'ব্লক ইভেন্টে নোটিফাই', 'Notify on block')} />
                  <ActionButton tone="emerald" onClick={() => void cc.setPolicy(policy)} disabled={cc.busy}>
                    {L(lang, 'পলিসি সেভ', 'Save policy')}
                  </ActionButton>
                </div>
              </Card>

              <Card>
                <SectionTitle
                  icon={<Mail className="w-4 h-4" />}
                  title="SMTP / Gmail forensic report"
                  subtitle={L(lang, 'নিজের Gmail app password বা SMTP দিয়ে ফরেনসিক রিপোর্ট পাঠান। কোনো Gmail API নয়।', 'Send forensic reports through your own Gmail app password or SMTP. No Gmail API.')}
                />
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <Field label="SMTP host" value={smtpForm.host} onChange={(value) => setSmtpForm((prev) => ({ ...prev, host: value }))} placeholder="smtp.example.com" />
                  <Field label="Port" value={smtpForm.port} onChange={(value) => setSmtpForm((prev) => ({ ...prev, port: value }))} />
                  <Field label="From" value={smtpForm.from} onChange={(value) => setSmtpForm((prev) => ({ ...prev, from: value }))} placeholder="security@example.com" />
                  <Field label="User" value={smtpForm.user} onChange={(value) => setSmtpForm((prev) => ({ ...prev, user: value }))} />
                  <Field label="Password" value={smtpForm.pass} onChange={(value) => setSmtpForm((prev) => ({ ...prev, pass: value }))} type="password" />
                  <div className="flex items-end gap-2">
                    <Toggle checked={smtpForm.secure} onChange={(value) => setSmtpForm((prev) => ({ ...prev, secure: value }))} label="TLS" />
                    <Toggle checked={smtpForm.autoSend} onChange={(value) => setSmtpForm((prev) => ({ ...prev, autoSend: value }))} label={L(lang, 'অটো সেন্ড', 'Auto send')} />
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <ActionButton tone="slate" onClick={() => setSmtpForm((prev) => ({ ...prev, host: 'smtp.gmail.com', port: '465', secure: true }))} disabled={cc.busy}>
                    Gmail preset
                  </ActionButton>
                  <ActionButton tone="fuchsia" onClick={() => void cc.saveSmtp({ ...smtpForm, port: Number(smtpForm.port) })} disabled={cc.busy}>
                    {L(lang, 'SMTP সেভ', 'Save SMTP')}
                  </ActionButton>
                  <ActionButton tone="slate" onClick={() => void cc.deleteSmtp()} disabled={cc.busy}>
                    {L(lang, 'মুছুন', 'Clear')}
                  </ActionButton>
                </div>
                <div className="mt-3 flex flex-wrap items-end gap-2">
                  <div className="flex-1 min-w-[180px]">
                    <Field label={L(lang, 'টেস্ট ইমেইল', 'Test email')} value={smtpTestTo} onChange={setSmtpTestTo} placeholder="you@example.com" />
                  </div>
                  <ActionButton tone="emerald" icon={<TestTube2 className="w-3.5 h-3.5" />} onClick={() => void cc.testSmtp(smtpTestTo)} disabled={cc.busy || !smtpTestTo}>
                    {L(lang, 'টেস্ট পাঠান', 'Send test')}
                  </ActionButton>
                </div>
                <div className="mt-3 flex flex-wrap items-end gap-2">
                  <div className="flex-1 min-w-[180px]">
                    <Field label={L(lang, 'অ্যাবিউজ রিপোর্ট আইপি', 'Abuse report IP')} value={abuseIp} onChange={setAbuseIp} placeholder="203.0.113.10" />
                  </div>
                  <div className="flex-1 min-w-[180px]">
                    <Field label={L(lang, 'রিসিপিয়েন্ট (ঐচ্ছিক)', 'Recipients (optional)')} value={abuseTo} onChange={setAbuseTo} placeholder="abuse@example.com" />
                  </div>
                  <ActionButton tone="fuchsia" icon={<Mail className="w-3.5 h-3.5" />} onClick={() => void cc.sendAbuseEmail(abuseIp.trim(), abuseTo ? abuseTo.split(',').map((value) => value.trim()) : undefined)} disabled={cc.busy || !abuseIp}>
                    {L(lang, 'রিপোর্ট পাঠান', 'Send report')}
                  </ActionButton>
                </div>
              </Card>

              <Card>
                <SectionTitle icon={<Clock className="w-4 h-4" />} title={L(lang, 'ডেলিভারি লগ', 'Delivery log')} />
                {cc.data.deliveries.length === 0 ? (
                  <div className="text-[11px] text-slate-500">{L(lang, 'এখনো কোনো ডেলিভারি নেই।', 'No deliveries yet.')}</div>
                ) : (
                  <div className="space-y-1.5">
                    {cc.data.deliveries.slice(0, 20).map((delivery) => (
                      <div key={delivery.id} className="flex flex-wrap items-center gap-2 rounded border border-slate-800 bg-[#04060A] px-2 py-1.5 text-[9px]">
                        <span className={`w-1.5 h-1.5 rounded-full ${statusDot(delivery.status === 'sent')}`} />
                        <span className="font-mono text-slate-500">{new Date(delivery.ts).toLocaleTimeString()}</span>
                        <span className="text-cyan-300">{delivery.channel}</span>
                        <span className="text-slate-400">{delivery.target ?? '—'}</span>
                        <span className={`font-semibold ${delivery.status === 'sent' ? 'text-emerald-300' : 'text-red-300'}`}>{delivery.status}</span>
                        <span className="ml-auto truncate max-w-[40%] text-slate-500">{delivery.detail}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )}

          {tab === 'data' && (
            <div className="space-y-4">
              <SectionTitle
                icon={<Database className="w-4 h-4" />}
                title={L(lang, 'SQLite ইভেন্ট স্টোর', 'SQLite event store')}
                subtitle={L(lang, 'WAL মোডে স্থায়ী স্টোর। সার্ভার রিস্টার্টেও ইভেন্ট থাকে।', 'Persistent WAL store. Events survive a server restart.')}
              />
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                <Stat label={L(lang, 'ইভেন্ট', 'Events')} value={(cc.data.dbStats?.events ?? 0).toLocaleString('en-US')} tone="text-cyan-300" />
                <Stat label={L(lang, 'সেন্সর', 'Sensors')} value={String(cc.data.dbStats?.sensors ?? 0)} tone="text-emerald-300" />
                <Stat label={L(lang, 'ডেলিভারি', 'Deliveries')} value={String(cc.data.dbStats?.deliveries ?? 0)} tone="text-fuchsia-300" />
                <Stat label={L(lang, 'WAF সিঙ্ক', 'WAF syncs')} value={String(cc.data.dbStats?.wafSyncs ?? 0)} tone="text-orange-300" />
              </div>

              <Card>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="rounded bg-[#04060A] border border-slate-800 px-2 py-1 text-[9px] text-slate-400 font-mono">
                    {cc.data.dbStats?.path ?? '—'} · {formatBytes(cc.data.dbStats?.sizeBytes ?? 0)}
                  </code>
                  <a href="/api/data/export?format=json" className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-cyan-200 hover:bg-cyan-500/20">
                    <Download className="w-3.5 h-3.5" /> JSON
                  </a>
                  <a href="/api/data/export?format=csv" className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-emerald-200 hover:bg-emerald-500/20">
                    <Download className="w-3.5 h-3.5" /> CSV
                  </a>
                </div>
                <div className="mt-3 flex flex-wrap items-end gap-2">
                  <div className="w-32">
                    <Field label={L(lang, 'রিটেনশন (দিন)', 'Retention (days)')} value={pruneDays} onChange={setPruneDays} />
                  </div>
                  <ActionButton tone="red" icon={<Trash2 className="w-3.5 h-3.5" />} onClick={() => void cc.pruneData(Number(pruneDays))} disabled={cc.busy}>
                    {L(lang, 'পুরনো ইভেন্ট মুছুন', 'Prune old events')}
                  </ActionButton>
                </div>
              </Card>

              <Card>
                <SectionTitle
                  icon={<HardDrive className="w-4 h-4" />}
                  title={L(lang, 'রিসেন্ট ইভেন্ট (DB)', 'Recent events (DB)')}
                  subtitle={L(lang, 'মেমোরি স্ট্রিম নয় — SQLite থেকে পড়া।', 'Read from SQLite, not the in-memory stream.')}
                />
                <div className="text-[10px] text-slate-500">
                  {L(lang, 'সর্বশেষ ১০০০ ইভেন্ট JSON/CSV-তে এক্সপোর্ট করা যায়।', 'The latest 1,000 events can be exported as JSON or CSV.')}
                </div>
              </Card>
            </div>
          )}

          {tab === 'detection' && (
            <div className="space-y-4">
              <SectionTitle
                icon={<Fingerprint className="w-4 h-4" />}
                title={L(lang, 'ডিটেকশন ইঞ্জিন', 'Detection engine')}
                subtitle={L(lang, 'রিয়েল রিকোয়েস্ট ফিঙ্গারপ্রিন্ট, ASN/subnet রেট শিল্ড ও হানিপট ক্লাসিফায়ার।', 'Real request fingerprints, ASN/subnet rate shield and honeypot classifier.')}
              />
              <DetectionCards config={cc.data.detection} lang={lang} />

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <SectionTitle icon={<Fingerprint className="w-4 h-4" />} title="JA3 / JA4 / TLSH" />
                  <p className="text-[11px] leading-relaxed text-slate-400">
                    {L(
                      lang,
                      'JA3/JA4 সরাসরি TLS ClientHello থেকে গণনা করা হয়। SENTINEL_TLS_SENSOR_PORT সেট থাকলে র টিসিপি সেন্সর ClientHello পার্স করে JA3 hash ও JA4 প্রকাশ করে; এজ প্রক্সি হেডার (x-ja3-hash, cf-ja3-hash, x-ja4) থেকেও মান নেওয়া হয়। TLSH রিকোয়েস্ট বডি/ClientHello থেকে তৈরি হয়।',
                      'JA3/JA4 are computed directly from the TLS ClientHello. When SENTINEL_TLS_SENSOR_PORT is set, the raw TCP sensor parses ClientHello and emits a JA3 hash and JA4; edge proxy headers (x-ja3-hash, cf-ja3-hash, x-ja4) are also accepted. TLSH is built from the request body or ClientHello.',
                    )}
                  </p>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
                    <div className="rounded-lg border border-slate-800 bg-[#04060A] px-2 py-1.5">
                      <div className="text-slate-500">{L(lang, 'TLS সেন্সর', 'TLS sensor')}</div>
                      <div className={cc.data.system?.tlsSensor?.listening ? 'text-emerald-300 font-semibold' : 'text-slate-400'}>
                        {cc.data.system?.tlsSensor?.listening
                          ? `${L(lang, 'চালু', 'listening')} :${cc.data.system.tlsSensor.port}`
                          : cc.data.system?.tlsSensor?.enabled
                            ? L(lang, 'বন্ধ / ত্রুটি', 'stopped / error')
                            : L(lang, 'নিষ্ক্রিয়', 'disabled')}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-[#04060A] px-2 py-1.5">
                      <div className="text-slate-500">{L(lang, 'ফিঙ্গারপ্রিন্ট', 'Fingerprints')}</div>
                      <div className="text-cyan-300 font-semibold">{cc.data.system?.tlsSensor?.fingerprints ?? 0}</div>
                    </div>
                  </div>
                  {cc.data.system?.tlsSensor?.lastError && (
                    <div className="mt-1 text-[9px] text-red-300">{cc.data.system.tlsSensor.lastError}</div>
                  )}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {cc.data.detection?.ja3Headers.map((name) => (
                      <code key={name} className="rounded bg-slate-800/70 border border-slate-700 px-1.5 py-0.5 text-[9px] text-slate-300">{name}</code>
                    ))}
                    {cc.data.detection?.ja4Headers.map((name) => (
                      <code key={name} className="rounded bg-slate-800/70 border border-slate-700 px-1.5 py-0.5 text-[9px] text-slate-300">{name}</code>
                    ))}
                  </div>
                </Card>

                <Card>
                  <SectionTitle icon={<ShieldCheck className="w-4 h-4" />} title={L(lang, 'অটো ডিফেন্স', 'Auto defense')} />
                  <p className="text-[11px] leading-relaxed text-slate-400">
                    {L(
                      lang,
                      'হানিপট, SQLi, RCE ও DDoS ইভেন্টে সোর্স সাথে সাথে ব্লক হয়। সাবনেট ও ASN লিমিট একই সাথে কাজ করে।',
                      'Honeypot, SQLi, RCE and DDoS events block the source immediately. Subnet and ASN limits work together.',
                    )}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Toggle checked={autoDefense} onChange={onToggleAutoDefense} label={L(lang, 'অটো ডিফেন্স', 'Auto defense')} />
                    <Toggle
                      checked={cc.data.sensors?.autoBlock ?? true}
                      onChange={(value) => void cc.setSensorAutoBlock(value)}
                      label={L(lang, 'সেন্সর অটো-ব্লক', 'Sensor auto-block')}
                    />
                  </div>
                </Card>
              </div>

              <Card>
                <SectionTitle icon={<LockKeyhole className="w-4 h-4" />} title={L(lang, 'সেফ আইপি', 'Safe IPs')} />
                <div className="flex flex-wrap gap-1">
                  {(cc.data.detection?.safeIps ?? []).length === 0 ? (
                    <span className="text-[11px] text-slate-500">{L(lang, 'কোনো সেফ আইপি নেই।', 'No safe IPs.')}</span>
                  ) : (
                    cc.data.detection?.safeIps.map((ip) => (
                      <code key={ip} className="rounded bg-slate-800/70 border border-slate-700 px-1.5 py-0.5 text-[9px] font-mono text-slate-300">{ip}</code>
                    ))
                  )}
                </div>
                <p className="mt-2 text-[10px] text-slate-500">
                  {L(lang, 'ডিফেন্স গ্রিড প্যানেল থেকে সেফ আইপি যোগ/সরান করা যায়।', 'Add or remove safe IPs from the Defense Grid panel.')}
                </p>
              </Card>
            </div>
          )}
        </div>

        {cc.loading && !cc.data.system && (
          <div className="px-4 py-2 text-[10px] text-slate-500 inline-flex items-center gap-2 border-t border-slate-800">
            <Loader2 className="w-3 h-3 animate-spin" /> {L(lang, 'লোড হচ্ছে…', 'Loading…')}
          </div>
        )}
      </div>
    </div>
  );
}
