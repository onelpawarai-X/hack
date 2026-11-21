import {
  Activity,
  Bug,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  FileText,
  Globe2,
  Layers,
  Loader2,
  Network,
  Play,
  RefreshCw,
  RotateCw,
  Server,
  Shield,
  ShieldAlert,
  Square,
  Terminal,
  Wifi,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Language } from '../types/cyber';
import type {
  SecurityStackSnapshot,
  SecurityToolDefinition,
  SecurityToolId,
  SecurityToolStatus,
} from '../types/securityStack';

interface SecurityStackPanelProps {
  lang: Language;
}

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

function statusColor(state: SecurityToolStatus['state']): string {
  if (state === 'running') return 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]';
  if (state === 'host-managed') return 'bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)]';
  if (state === 'stopped') return 'bg-amber-400';
  if (state === 'error') return 'bg-red-500';
  return 'bg-slate-600';
}

function categoryIcon(category: SecurityToolDefinition['category']) {
  if (category === 'nids') return <Network className="h-4 w-4" />;
  if (category === 'hids-siem') return <Database className="h-4 w-4" />;
  if (category === 'log-response') return <ShieldAlert className="h-4 w-4" />;
  if (category === 'honeypot') return <Bug className="h-4 w-4" />;
  if (category === 'deception') return <Globe2 className="h-4 w-4" />;
  return <Layers className="h-4 w-4" />;
}

function ToolCard({
  tool,
  status,
  lang,
  busy,
  onAction,
  onLogs,
  onConfig,
}: {
  tool: SecurityToolDefinition;
  status?: SecurityToolStatus;
  lang: Language;
  busy: string | null;
  onAction: (id: SecurityToolId, action: 'start' | 'stop' | 'restart') => void;
  onLogs: (id: SecurityToolId) => void;
  onConfig: (id: SecurityToolId) => void;
}) {
  const state = status?.state ?? 'unavailable';
  return (
    <div className="rounded-xl border border-slate-800 bg-[#06090F]/80 p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 min-w-0">
          <span className="mt-0.5 text-cyan-400">{categoryIcon(tool.category)}</span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100">{tool.name}</h3>
              <span className={`h-2 w-2 rounded-full ${statusColor(state)}`} />
            </div>
            <p className="text-[10px] text-slate-500 mt-0.5">
              {tool.deployment.toUpperCase()} · {tool.category}
            </p>
          </div>
        </div>
        <span className="shrink-0 rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[9px] font-mono text-slate-400">
          {state}
        </span>
      </div>

      <p className="text-[11px] leading-relaxed text-slate-400">{tool.description}</p>

      <div className="flex flex-wrap gap-1">
        {tool.capabilities.slice(0, 4).map((capability) => (
          <span
            key={capability}
            className="rounded-md border border-slate-800 bg-slate-950/70 px-1.5 py-0.5 text-[9px] text-slate-400"
          >
            {capability}
          </span>
        ))}
      </div>

      <div className="rounded-lg border border-slate-800/80 bg-[#04060A] p-2 text-[10px] font-mono text-slate-500 space-y-1">
        <div className="truncate">
          <span className="text-slate-600">image</span> {tool.image ?? 'host appliance'}
        </div>
        <div>
          <span className="text-slate-600">ingest</span> /api/security-stack/ingest/{tool.id}
        </div>
        {status?.detail && <div className="text-slate-500 leading-relaxed">{status.detail}</div>}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        {tool.deployment !== 'appliance' && (
          <>
            <button
              type="button"
              disabled={busy === `${tool.id}:start`}
              onClick={() => onAction(tool.id, 'start')}
              className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
            >
              {busy === `${tool.id}:start` ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
              {L(lang, 'চালু', 'Start')}
            </button>
            <button
              type="button"
              disabled={busy === `${tool.id}:stop`}
              onClick={() => onAction(tool.id, 'stop')}
              className="inline-flex items-center gap-1 rounded-lg border border-red-500/40 bg-red-500/10 px-2 py-1 text-[10px] font-semibold text-red-200 hover:bg-red-500/20 disabled:opacity-50"
            >
              {busy === `${tool.id}:stop` ? <Loader2 className="h-3 w-3 animate-spin" /> : <Square className="h-3 w-3" />}
              {L(lang, 'বন্ধ', 'Stop')}
            </button>
            <button
              type="button"
              disabled={busy === `${tool.id}:restart`}
              onClick={() => onAction(tool.id, 'restart')}
              className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-[10px] font-semibold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
            >
              {busy === `${tool.id}:restart` ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCw className="h-3 w-3" />}
              {L(lang, 'রিস্টার্ট', 'Restart')}
            </button>
          </>
        )}
        <button
          type="button"
          onClick={() => onLogs(tool.id)}
          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300 hover:border-slate-500"
        >
          <Terminal className="h-3 w-3" />
          {L(lang, 'লগ', 'Logs')}
        </button>
        <button
          type="button"
          onClick={() => onConfig(tool.id)}
          className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300 hover:border-slate-500"
        >
          <FileText className="h-3 w-3" />
          {L(lang, 'কনফিগ', 'Config')}
        </button>
        <a
          href={tool.docsUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 rounded-lg border border-slate-800 px-2 py-1 text-[10px] font-semibold text-slate-500 hover:text-slate-300"
        >
          {L(lang, 'ডকস', 'Docs')}
        </a>
      </div>
    </div>
  );
}

export function SecurityStackPanel({ lang }: SecurityStackPanelProps) {
  const [snapshot, setSnapshot] = useState<SecurityStackSnapshot | null>(null);
  const [catalog, setCatalog] = useState<SecurityToolDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<SecurityToolId | null>(null);
  const [panel, setPanel] = useState<{ title: string; body: string } | null>(null);
  const [stackAction, setStackAction] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [stackRes, catalogRes] = await Promise.all([
        fetch('/api/security-stack', { cache: 'no-store' }),
        fetch('/api/security-stack/tools', { cache: 'no-store' }),
      ]);
      if (!stackRes.ok) throw new Error(`HTTP ${stackRes.status}`);
      setSnapshot((await stackRes.json()) as SecurityStackSnapshot);
      if (catalogRes.ok) {
        const payload = (await catalogRes.json()) as { tools?: SecurityToolDefinition[] };
        setCatalog(payload.tools ?? []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Security stack unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 20_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const toolsById = useMemo(() => {
    const map = new Map<SecurityToolId, SecurityToolStatus>();
    for (const tool of snapshot?.tools ?? []) map.set(tool.id, tool);
    return map;
  }, [snapshot]);

  const definitions = useMemo(() => {
    const groups: Record<string, SecurityToolDefinition[]> = {
      nids: [],
      'hids-siem': [],
      'log-response': [],
      honeypot: [],
      deception: [],
      platform: [],
    };
    const tools =
      catalog.length > 0
        ? catalog
        : (snapshot?.tools ?? []).map((tool) => ({
            id: tool.id,
            name: tool.name,
            category: tool.category,
            deployment: tool.deployment,
            description: '',
            capabilities: [],
            image: tool.image,
            profiles: [],
            defaultPorts: tool.ports,
            upstreamRepo: '',
            docsUrl: '',
            ingestFormats: [],
            privileged: false,
          }));
    for (const tool of tools) {
      groups[tool.category]?.push(tool);
    }
    return groups;
  }, [catalog, snapshot]);

  const runStackAction = async (kind: 'install-docker' | 'start-docker' | 'start-all') => {
    setStackAction(kind);
    setError(null);
    try {
      const res = await fetch(`/api/security-stack/${kind}`, { method: 'POST' });
      const payload = (await res.json()) as { detail?: string; error?: string };
      if (!res.ok) throw new Error(payload.detail || payload.error || `HTTP ${res.status}`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setStackAction(null);
    }
  };

  const action = async (id: SecurityToolId, kind: 'start' | 'stop' | 'restart') => {
    setBusy(`${id}:${kind}`);
    try {
      const res = await fetch(`/api/security-stack/${id}/${kind}`, { method: 'POST' });
      const payload = (await res.json()) as { ok?: boolean; detail?: string; error?: string };
      if (!res.ok || payload.ok === false) throw new Error(payload.detail || payload.error || 'Action failed');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setBusy(null);
    }
  };

  const showLogs = async (id: SecurityToolId) => {
    setBusy(`${id}:logs`);
    try {
      const res = await fetch(`/api/security-stack/${id}/logs?tail=120`);
      const payload = (await res.json()) as { lines?: string[]; error?: string };
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setPanel({ title: `${id} logs`, body: (payload.lines ?? []).join('\n') || 'No logs.' });
      setExpanded(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Logs unavailable');
    } finally {
      setBusy(null);
    }
  };

  const showConfig = async (id: SecurityToolId) => {
    setBusy(`${id}:config`);
    try {
      const res = await fetch(`/api/security-stack/${id}/config`);
      const payload = (await res.json()) as { files?: Array<{ path: string; content: string }>; error?: string };
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      const body = (payload.files ?? [])
        .map((file) => `# ${file.path}\n${file.content}`)
        .join('\n\n---\n\n');
      setPanel({ title: `${id} generated config`, body: body || 'No config files.' });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Config unavailable');
    } finally {
      setBusy(null);
    }
  };

  const summary = snapshot?.summary;

  return (
    <section aria-label="Security Stack" className="soc-panel rounded-xl p-4 sm:p-5 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L(lang, 'সিকিউরিটি স্ট্যাক ও হানিপট ফ্লিট', 'Security Stack & Honeypot Fleet')}
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">
            {L(
              lang,
              'Suricata, Zeek, Wazuh, Fail2Ban, Cowrie, T-Pot, OpenCanary, HFish, Conpot , Beelzebub — সব বাস্তব টুল, বাস্তব কনফিগ, বাস্তব লগ ইনজেস্ট।',
              'Suricata, Zeek, Wazuh, Fail2Ban, Cowrie, T-Pot, OpenCanary, HFish, Conpot , Beelzebub — real tools, real configs, real log ingest. Docker ও চলমান টুলগুলো প্রতি ৩০ সেকেন্ডে অটো-চেক হয়; নিচের বাটনগুলো শুধু ম্যানুয়াল ফলব্যাক।',
            )}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${
              snapshot?.docker.available
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                : snapshot?.docker.cliInstalled
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-200'
                  : 'border-red-500/40 bg-red-500/10 text-red-300'
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                snapshot?.docker.available
                  ? 'bg-emerald-400'
                  : snapshot?.docker.cliInstalled
                    ? 'bg-amber-400'
                    : 'bg-red-500'
              }`}
            />
            Docker{' '}
            {snapshot?.docker.available
              ? snapshot.docker.version ?? 'ready'
              : snapshot?.docker.cliInstalled
                ? 'daemon stopped'
                : 'not installed'}
          </span>
          <span className="inline-flex items-center gap-1 rounded-full border border-cyan-500/30 bg-cyan-500/5 px-2 py-0.5 text-[9px] font-semibold text-cyan-300">
            <RefreshCw className="h-2.5 w-2.5" /> {L(lang, 'অটো', 'AUTO')}
          </span>
          <button
            type="button"
            onClick={() => void runStackAction('start-docker')}
            disabled={stackAction !== null || Boolean(snapshot?.docker.available)}
            title={L(lang, 'স্বয়ংক্রিয়ভাবে চলে; এটি শুধু ম্যানুয়াল ফলব্যাক।', 'Runs automatically; this is only a manual fallback.')}
            className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2 py-1 text-[10px] font-semibold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
          >
            {stackAction === 'start-docker' ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
            {snapshot?.docker.available
              ? L(lang, 'Docker চলছে', 'Docker running')
              : L(lang, 'Docker চালু', 'Start Docker')}
          </button>
          <button
            type="button"
            onClick={() => void runStackAction('install-docker')}
            disabled={stackAction !== null}
            className="inline-flex items-center gap-1 rounded-lg border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[10px] font-semibold text-amber-200 hover:bg-amber-500/20 disabled:opacity-50"
          >
            {stackAction === 'install-docker' ? <Loader2 className="h-3 w-3 animate-spin" /> : <Server className="h-3 w-3" />}
            {L(lang, 'Docker সেটআপ', 'Setup Docker')}
          </button>
          <button
            type="button"
            onClick={() => void runStackAction('start-all')}
            disabled={stackAction !== null}
            className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
          >
            {stackAction === 'start-all' ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
            {L(lang, 'সব চালু (ব্যাকআপ)', 'Start all (fallback)')}
          </button>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300 hover:border-slate-500 disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
            {L(lang, 'রিফ্রেশ', 'Refresh')}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          {error}
        </div>
      )}

      {snapshot && !snapshot.docker.available && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 px-3 py-2 text-[11px] leading-relaxed text-amber-100">
          <div className="font-semibold">
            {L(lang, 'Docker চালু নেই — কন্টেইনার টুলগুলো এখনো চলেনি', 'Docker is not running — container tools are not running')}
          </div>
          <div className="mt-0.5 text-amber-200/80">{snapshot.docker.detail}</div>
          {snapshot.docker.hint && (
            <div className="mt-1 font-mono text-[10px] text-amber-200/70">{snapshot.docker.hint}</div>
          )}
        </div>
      )}

      {snapshot?.docker.available && (summary?.running ?? 0) === 0 && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 px-3 py-2 text-[11px] leading-relaxed text-cyan-100">
          {L(
            lang,
            'Docker প্রস্তুত, কিন্তু কোনো কন্টেইনার এখনো চালু নেই। নিচের Start বাটন চাপুন।',
            'Docker is ready, but no containers are running. Press Start below.',
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        {[
          [L(lang, 'মোট টুল', 'Tools'), summary?.total ?? 0],
          [L(lang, 'চালু', 'Running'), summary?.running ?? 0],
          [L(lang, 'হানিপট', 'Honeypots'), summary?.honeypots ?? 0],
          [L(lang, 'ডিটেক্টর', 'Detectors'), summary?.detectors ?? 0],
          [L(lang, 'ইনজেস্টেড', 'Ingested'), summary?.ingestedEvents ?? 0],
          [L(lang, 'অটো-ব্লক', 'Auto-blocked'), summary?.blockedByStack ?? 0],
        ].map(([label, value]) => (
          <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#04060A] px-3 py-2">
            <div className="text-[9px] text-slate-500">{label}</div>
            <div className="font-mono text-lg font-bold tabular-nums text-slate-100">{String(value)}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-[10px] text-cyan-200">
        <Wifi className="h-3.5 w-3.5" />
        <span>
          {L(lang, 'ইনজেস্ট এন্ডপয়েন্ট:', 'Ingest endpoint:')}{' '}
          <code className="font-mono">/api/security-stack/ingest/&lt;tool&gt;</code>
        </span>
        <span className="text-cyan-300/60">·</span>
        <span>
          {L(lang, 'টোকেন:', 'Token:')}{' '}
          <code className="font-mono">
            {snapshot?.ingest.tokenConfigured
              ? L(lang, 'কনফিগার করা আছে', 'configured')
              : L(lang, 'সেট করা নেই (auth required)', 'not set (auth required)')}
          </code>
        </span>
      </div>

      {loading && !snapshot ? (
        <div className="flex items-center gap-2 py-8 text-xs text-slate-400">
          <Loader2 className="h-4 w-4 animate-spin" />
          {L(lang, 'স্ট্যাক স্টেটাস লোড হচ্ছে...', 'Loading stack status...')}
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(definitions).map(([category, tools]) =>
            tools.length === 0 ? null : (
              <div key={category} className="space-y-2">
                <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  {categoryIcon(category as SecurityToolDefinition['category'])}
                  {category}
                </div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {tools.map((tool) => (
                    <ToolCard
                      key={tool.id}
                      tool={tool}
                      status={toolsById.get(tool.id)}
                      lang={lang}
                      busy={busy}
                      onAction={(id, kind) => void action(id, kind)}
                      onLogs={(id) => void showLogs(id)}
                      onConfig={(id) => void showConfig(id)}
                    />
                  ))}
                </div>
              </div>
            ),
          )}
        </div>
      )}


      {panel && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true">
          <div className="flex max-h-[85vh] w-full max-w-4xl flex-col rounded-xl border border-slate-700 bg-[#06090F]">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2.5">
              <h3 className="text-sm font-bold text-slate-100">{panel.title}</h3>
              <button
                type="button"
                onClick={() => setPanel(null)}
                className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-slate-500"
              >
                {L(lang, 'বন্ধ', 'Close')}
              </button>
            </div>
            <pre className="overflow-auto p-4 text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">
              {panel.body}
            </pre>
          </div>
        </div>
      )}
    </section>
  );
}
