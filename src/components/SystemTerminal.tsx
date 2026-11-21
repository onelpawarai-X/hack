import { ChevronRight, Loader2, RotateCcw, SquareTerminal, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { io, type Socket } from 'socket.io-client';
import type { Language } from '../types/cyber';
import type { ClientToServerEvents, ServerToClientEvents, TerminalOutputPayload } from '../types/realtime';

const L = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

interface OutputLine {
  id: number;
  stream: TerminalOutputPayload['stream'];
  data: string;
}

const QUICK_COMMANDS = [
  'docker ps',
  'docker compose -f security-stack/docker-compose.yml ps',
  'docker --version',
  'ls -la',
  'df -h',
  'free -h',
];

export function SystemTerminal({ lang }: { lang: Language }) {
  const [connected, setConnected] = useState(false);
  const [running, setRunning] = useState(false);
  const [command, setCommand] = useState('');
  const [cwd, setCwd] = useState('');
  const [lines, setLines] = useState<OutputLine[]>([]);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const socketRef = useRef<Socket<ServerToClientEvents, ClientToServerEvents> | null>(null);
  const outputRef = useRef<HTMLDivElement | null>(null);
  const nextId = useRef(0);

  const append = useCallback((payload: TerminalOutputPayload) => {
    setLines((previous) => {
      const next = [...previous, { id: nextId.current++, stream: payload.stream, data: payload.data }];
      return next.length > 800 ? next.slice(-800) : next;
    });
  }, []);

  useEffect(() => {
    const socket: Socket<ServerToClientEvents, ClientToServerEvents> = io({
      path: '/socket.io',
      transports: ['websocket', 'polling'],
    });
    socketRef.current = socket;
    socket.on('connect', () => {
      setConnected(true);
      append({
        stream: 'system',
        data: L(
          lang,
          'Sentinel টার্মিনাল সংযুক্ত। কমান্ড লিখে Enter চাপুন।\n',
          'Sentinel terminal connected. Type a command and press Enter.\n',
        ),
      });
    });
    socket.on('disconnect', () => {
      setConnected(false);
      setRunning(false);
      append({ stream: 'system', data: L(lang, '\n[সংযোগ বিচ্ছিন্ন]\n', '\n[disconnected]\n') });
    });
    socket.on('connect_error', (error) => {
      setConnected(false);
      setRunning(false);
      append({ stream: 'stderr', data: `[connect] ${error.message}\n` });
    });
    socket.on('terminal:output', append);
    socket.on('terminal:exit', (payload) => {
      setRunning(false);
      setCwd(payload.cwd);
      if (payload.code !== 0 && payload.code !== null) {
        append({ stream: 'system', data: `[exit ${payload.code}]\n` });
      }
    });
    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
    // The terminal socket should survive language changes without reconnecting.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const element = outputRef.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [lines]);

  const run = useCallback(
    (raw: string) => {
      const value = raw.trim();
      if (!value) return;
      if (value === 'clear') {
        setLines([]);
        return;
      }
      const socket = socketRef.current;
      if (!socket || !socket.connected) {
        append({ stream: 'stderr', data: '[terminal] not connected\n' });
        return;
      }
      setHistory((previous) => [...previous.filter((item) => item !== value).slice(-49), value]);
      setHistoryIndex(-1);
      setRunning(true);
      socket.emit('terminal:exec', { command: value }, (result) => {
        if (!result.ok) {
          append({ stream: 'stderr', data: `[terminal] ${result.error ?? 'command rejected'}\n` });
          setRunning(false);
        } else if (result.cwd) {
          setCwd(result.cwd);
        }
      });
    },
    [append],
  );

  const submit = () => {
    const value = command;
    setCommand('');
    run(value);
  };

  const reconnect = () => {
    socketRef.current?.disconnect();
    socketRef.current?.connect();
  };

  return (
    <section
      id="system-terminal"
      aria-label="System terminal"
      className="scroll-mt-24 soc-panel rounded-xl p-4 sm:p-5 space-y-3"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <SquareTerminal className="h-4 w-4 text-emerald-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L(lang, 'সিস্টেম টার্মিনাল', 'System terminal')}
            </h2>
            <span
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-semibold ${
                connected
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                  : 'border-red-500/40 bg-red-500/10 text-red-300'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400' : 'bg-red-500'}`} />
              {connected ? 'connected' : 'offline'}
            </span>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">
            {L(
              lang,
              'এটি হোস্টের আসল শেল। Docker, systemctl, ফাইল, প্রসেস — সব কমান্ড এখানে চলে। `docker` কমান্ডে permission সমস্যা হলে টার্মিনাল স্বয়ংক্রিয়ভাবে passwordless sudo ব্যবহার করে।',
              'This is a real host shell. Docker, systemctl, files and processes run here. If a docker command hits a permission error, the terminal automatically retries with passwordless sudo.',
            )}
          </p>
          <p className="mt-1 font-mono text-[10px] text-cyan-300/80">
            cwd: {cwd || '...'}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={reconnect}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300 hover:border-slate-500"
          >
            <RotateCcw className="h-3 w-3" /> {L(lang, 'রিকানেক্ট', 'Reconnect')}
          </button>
          <button
            type="button"
            onClick={() => setLines([])}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-semibold text-slate-300 hover:border-slate-500"
          >
            <Trash2 className="h-3 w-3" /> {L(lang, 'ক্লিয়ার', 'Clear')}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1">
        {QUICK_COMMANDS.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => run(item)}
            disabled={!connected || running}
            className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[9px] text-slate-300 hover:border-emerald-500/50 hover:text-emerald-200 disabled:opacity-50"
          >
            {item}
          </button>
        ))}
      </div>

      <div
        ref={outputRef}
        className="h-[360px] overflow-auto rounded-lg border border-slate-800 bg-[#02060C] p-3 font-mono text-[11px] leading-relaxed"
      >
        {lines.length === 0 ? (
          <p className="text-slate-600">{L(lang, 'আউটপুট এখানে দেখা যাবে…', 'Output appears here…')}</p>
        ) : (
          lines.map((line) => (
            <span
              key={line.id}
              className={
                line.stream === 'stderr'
                  ? 'whitespace-pre-wrap text-red-300'
                  : line.stream === 'system'
                    ? 'whitespace-pre-wrap text-cyan-300'
                    : 'whitespace-pre-wrap text-slate-200'
              }
            >
              {line.data}
            </span>
          ))
        )}
      </div>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
        className="flex items-center gap-2 rounded-lg border border-slate-700 bg-[#04060A] px-2 py-1.5"
      >
        <ChevronRight className="h-4 w-4 shrink-0 text-emerald-400" />
        <input
          value={command}
          onChange={(event) => setCommand(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'ArrowUp') {
              event.preventDefault();
              const nextIndex = Math.min(history.length - 1, historyIndex + 1);
              if (nextIndex >= 0) {
                setHistoryIndex(nextIndex);
                setCommand(history[history.length - 1 - nextIndex] ?? '');
              }
            } else if (event.key === 'ArrowDown') {
              event.preventDefault();
              const nextIndex = historyIndex - 1;
              setHistoryIndex(nextIndex);
              setCommand(nextIndex < 0 ? '' : history[history.length - 1 - nextIndex] ?? '');
            }
          }}
          placeholder={L(lang, 'যেমন: docker ps', 'e.g. docker ps')}
          spellCheck={false}
          autoComplete="off"
          className="min-w-0 flex-1 bg-transparent font-mono text-[11px] text-slate-100 outline-none placeholder:text-slate-600"
        />
        <button
          type="submit"
          disabled={!connected || running || !command.trim()}
          className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-semibold text-emerald-200 disabled:opacity-50"
        >
          {running ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
          {L(lang, 'চালান', 'Run')}
        </button>
      </form>
    </section>
  );
}
