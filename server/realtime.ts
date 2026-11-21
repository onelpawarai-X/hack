import { spawn } from 'node:child_process';
import { resolve4 } from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import type { Server as HttpServer } from 'node:http';
import { Server } from 'socket.io';
import type { ScanModuleId, TargetScanResult } from '../src/types/cyber.ts';
import type {
  ClientToServerEvents,
  ScanGeoPayload,
  ScanGeoPoint,
  ScanLogEvent,
  ScannerOrigin,
  ServerToClientEvents,
} from '../src/types/realtime.ts';
import { sessionFromCookie } from './auth.ts';
import { scanTargetOrWeb, traceAttackerIp } from './scanner.ts';
import { isValidIpv4 } from './threatRules.ts';

const ORIGIN_TTL_MS = 10 * 60 * 1000;
const TERMINAL_ROOT = path.resolve(process.cwd(), 'data', 'terminal');
const TERMINAL_BIN = path.join(TERMINAL_ROOT, 'bin');
const TERMINAL_TIMEOUT_MS = 120_000;
const TERMINAL_RATE_LIMIT = 60;
const TERMINAL_RATE_WINDOW_MS = 60_000;

function ensureTerminalBin(): void {
  fs.mkdirSync(TERMINAL_BIN, { recursive: true });
  const wrapper = path.join(TERMINAL_BIN, 'docker');
  const realDocker =
    (process.env.PATH ?? '')
      .split(':')
      .filter((directory) => directory && path.resolve(directory) !== path.resolve(TERMINAL_BIN))
      .map((directory) => path.join(directory, 'docker'))
      .find((candidate) => fs.existsSync(candidate)) ?? '/usr/bin/docker';
  const body = `#!/bin/sh
DOCKER_BIN="${realDocker}"
if [ ! -x "$DOCKER_BIN" ]; then
  echo "docker: command not found at $DOCKER_BIN" >&2
  exit 127
fi
ERR="$(mktemp)"
"$DOCKER_BIN" "$@" 2>"$ERR"
CODE=$?
if [ "$CODE" -ne 0 ] && grep -qi "permission denied" "$ERR"; then
  rm -f "$ERR"
  exec sudo -n "$DOCKER_BIN" "$@"
fi
cat "$ERR" >&2
rm -f "$ERR"
exit "$CODE"
`;
  try {
    if (!fs.existsSync(wrapper) || fs.readFileSync(wrapper, 'utf8') !== body) {
      fs.writeFileSync(wrapper, body, { mode: 0o755 });
    }
    fs.chmodSync(wrapper, 0o755);
  } catch {
    // Terminal still works without the Docker fallback wrapper.
  }
}
const SOCKET_SCAN_LIMIT = 6;
const SOCKET_SCAN_WINDOW_MS = 60_000;

let cachedOrigin: ScannerOrigin | null = null;
let originFetchedAt = 0;

async function fetchPublicIp(): Promise<string | null> {
  const { discoverPublicIp } = await import('./publicIp.ts');
  return discoverPublicIp();
}

export async function resolveScannerOrigin(): Promise<ScannerOrigin | null> {
  if (cachedOrigin && Date.now() - originFetchedAt < ORIGIN_TTL_MS) {
    return cachedOrigin;
  }
  const ip = await fetchPublicIp();
  if (!ip) return null;
  const node = await traceAttackerIp(ip);
  if (!node) return null;
  cachedOrigin = {
    ip,
    lat: node.lat,
    lon: node.lon,
    city: node.city,
    country: node.country,
    asn: node.asn,
    isp: node.isp,
    resolvedAt: new Date().toISOString(),
  };
  originFetchedAt = Date.now();
  return cachedOrigin;
}

export function buildScanGeo(
  report: TargetScanResult,
  origin: ScannerOrigin | null,
): ScanGeoPayload {
  const points: ScanGeoPoint[] = [];
  const seen = new Set<string>();

  for (const node of report.attribution) {
    if (!Number.isFinite(node.lat) || !Number.isFinite(node.lon)) continue;
    if (node.lat === 0 && node.lon === 0) continue;
    const key = `${node.ip}:${node.lat.toFixed(3)}:${node.lon.toFixed(3)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    points.push({
      ip: node.ip,
      label: `${node.city || 'Unknown'}, ${node.country || 'Unknown'}`,
      lat: node.lat,
      lon: node.lon,
      severity: node.severity,
      role: 'target',
      city: node.city,
      country: node.country,
    });
  }

  return {
    target: report.normalizedTarget,
    points,
    scanner: origin
      ? {
          ip: origin.ip,
          lat: origin.lat,
          lon: origin.lon,
          city: origin.city,
          country: origin.country,
        }
      : null,
  };
}

export async function resolveTargetGeoHint(rawTarget: string): Promise<ScanGeoPoint | null> {
  let host = rawTarget.trim();
  try {
    const url = new URL(/^https?:\/\//i.test(host) ? host : `https://${host}`);
    host = url.hostname;
  } catch {
    host = host.split('/')[0];
  }
  if (!host) return null;

  let ip: string | null = isValidIpv4(host) ? host : null;
  if (!ip) {
    const resolved = await resolve4(host).catch(() => [] as string[]);
    ip = resolved[0] ?? null;
  }
  if (!ip) return null;

  const node = await traceAttackerIp(ip);
  if (!node) return null;

  return {
    ip,
    label: `${node.city || 'Unknown'}, ${node.country || 'Unknown'}`,
    lat: node.lat,
    lon: node.lon,
    severity: node.severity,
    role: 'target',
    city: node.city,
    country: node.country,
  };
}

function makeLog(level: ScanLogEvent['level'], message: string): ScanLogEvent {
  return {
    id: `log-${Date.now()}-${Math.round(Math.random() * 1e6)}`,
    ts: new Date().toISOString(),
    level,
    moduleId: 'socket',
    message,
  };
}

export function attachRealtime(httpServer: HttpServer) {
  const io = new Server<ClientToServerEvents, ServerToClientEvents>(httpServer, {
    cors: { origin: true, credentials: false },
    path: '/socket.io',
    maxHttpBufferSize: 1e6,
  });

  const windows = new Map<string, { count: number; startedAt: number }>();
  const terminals = new Map<
    string,
    { cwd: string; running: boolean; count: number; startedAt: number; child?: ReturnType<typeof spawn> }
  >();
  ensureTerminalBin();

  io.use((socket, next) => {
    const user = sessionFromCookie(socket.handshake.headers.cookie);
    if (!user) {
      next(new Error('Authentication required'));
      return;
    }
    socket.data.user = user;
    next();
  });

  io.on('connection', (socket) => {
    socket.emit('scan:log', makeLog('success', 'Realtime scanning channel connected'));
    void resolveScannerOrigin().then((origin) => {
      socket.emit('server:ready', {
        at: new Date().toISOString(),
        scannerOrigin: origin,
      });
    });

    terminals.set(socket.id, {
      cwd: process.cwd(),
      running: false,
      count: 0,
      startedAt: Date.now(),
    });

    socket.on('terminal:exec', (payload, ack) => {
      if (process.env.SENTINEL_TERMINAL_DISABLED === 'true') {
        ack?.({ ok: false, error: 'Terminal is disabled by SENTINEL_TERMINAL_DISABLED.' });
        return;
      }
      const command = String(payload?.command ?? '').replace(/\u0000/g, '').trim();
      if (!command) {
        ack?.({ ok: false, error: 'Empty command.' });
        return;
      }
      if (command.length > 4000) {
        ack?.({ ok: false, error: 'Command is too long (max 4000 chars).' });
        return;
      }
      const state = terminals.get(socket.id) ?? {
        cwd: process.cwd(),
        running: false,
        count: 0,
        startedAt: Date.now(),
      };
      terminals.set(socket.id, state);
      if (state.running) {
        ack?.({ ok: false, error: 'A command is already running. Wait for it to finish.' });
        return;
      }
      const now = Date.now();
      if (now - state.startedAt > TERMINAL_RATE_WINDOW_MS) {
        state.count = 0;
        state.startedAt = now;
      }
      if (state.count >= TERMINAL_RATE_LIMIT) {
        ack?.({ ok: false, error: 'Terminal rate limit reached. Wait a minute.' });
        return;
      }
      state.count += 1;

      const cdMatch = command.match(/^cd(?:\s+(.*))?$/);
      if (cdMatch) {
        const rawTarget = (cdMatch[1] ?? '').trim().replace(/^['"]|['"]$/g, '');
        const target = rawTarget || process.env.HOME || state.cwd;
        const next = path.resolve(state.cwd, target);
        try {
          if (!fs.statSync(next).isDirectory()) throw new Error('not a directory');
          state.cwd = next;
          socket.emit('terminal:output', { stream: 'system', data: `cwd: ${state.cwd}\n` });
          socket.emit('terminal:exit', { code: 0, cwd: state.cwd });
          ack?.({ ok: true, cwd: state.cwd });
        } catch {
          socket.emit('terminal:output', {
            stream: 'stderr',
            data: `cd: no such directory: ${rawTarget || target}\n`,
          });
          socket.emit('terminal:exit', { code: 1, cwd: state.cwd });
          ack?.({ ok: false, cwd: state.cwd, error: 'No such directory.' });
        }
        return;
      }

      state.running = true;
      socket.emit('terminal:output', { stream: 'system', data: `\n$ ${command}\n` });
      const child = spawn('/bin/bash', ['-c', command], {
        cwd: state.cwd,
        env: {
          ...process.env,
          PATH: `${TERMINAL_BIN}:${process.env.PATH ?? ''}`,
          TERM: 'xterm-256color',
          PS1: '',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      state.child = child;
      let finished = false;
      const finish = (code: number | null) => {
        if (finished) return;
        finished = true;
        state.running = false;
        state.child = undefined;
        socket.emit('terminal:exit', { code, cwd: state.cwd });
      };
      const timer = setTimeout(() => {
        socket.emit('terminal:output', {
          stream: 'stderr',
          data: `\n[sentinel] command timed out after ${TERMINAL_TIMEOUT_MS / 1000}s\n`,
        });
        child.kill('SIGTERM');
      }, TERMINAL_TIMEOUT_MS);
      child.stdout?.on('data', (chunk: Buffer) => {
        socket.emit('terminal:output', { stream: 'stdout', data: chunk.toString('utf8') });
      });
      child.stderr?.on('data', (chunk: Buffer) => {
        socket.emit('terminal:output', { stream: 'stderr', data: chunk.toString('utf8') });
      });
      child.on('error', (error) => {
        clearTimeout(timer);
        socket.emit('terminal:output', {
          stream: 'stderr',
          data: `[sentinel] ${error.message}\n`,
        });
        finish(null);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        finish(code);
      });
      ack?.({ ok: true, cwd: state.cwd });
    });

    socket.on('disconnect', () => {
      const state = terminals.get(socket.id);
      state?.child?.kill('SIGTERM');
      terminals.delete(socket.id);
    });

    socket.on('scanner:origin', (ack) => {
      void resolveScannerOrigin().then((origin) => ack?.(origin));
    });

    socket.on('scan:start', async (payload, ack) => {
      const target = String(payload?.target ?? '').trim();
      if (target.length < 2) {
        ack?.({ ok: false, error: 'Target must be at least 2 characters.' });
        socket.emit('scan:error', { target, error: 'Invalid scan target.' });
        return;
      }

      const now = Date.now();
      const window = windows.get(socket.id);
      if (!window || now - window.startedAt > SOCKET_SCAN_WINDOW_MS) {
        windows.set(socket.id, { count: 1, startedAt: now });
      } else if (window.count >= SOCKET_SCAN_LIMIT) {
        ack?.({ ok: false, error: 'Rate limit reached. Wait a minute before scanning again.' });
        socket.emit(
          'scan:error',
          { target, error: 'Rate limit reached. Wait a minute before scanning again.' },
        );
        return;
      } else {
        window.count += 1;
      }

      const modules = Array.isArray(payload?.modules)
        ? (payload.modules as ScanModuleId[])
        : undefined;

      const scanId = `${Date.now()}-${Math.random()}`;
      socket.data.scanId = scanId;
      const isCurrentScan = () => socket.data.scanId === scanId;

      ack?.({ ok: true });
      socket.emit('scan:log', makeLog('info', `Scan requested for ${target}`));

      // Plot the target as soon as DNS + geolocation resolve, before deep modules finish
      void (async () => {
        const [hint, origin] = await Promise.all([
          resolveTargetGeoHint(target),
          resolveScannerOrigin(),
        ]);
        if (!isCurrentScan() || !hint) return;
        socket.emit('scan:geo', {
          target,
          points: [hint],
          scanner: origin
            ? {
                ip: origin.ip,
                lat: origin.lat,
                lon: origin.lon,
                city: origin.city,
                country: origin.country,
              }
            : null,
        });
      })();

      try {
        const report = await scanTargetOrWeb(
          target,
          modules,
          (event) => {
            if (isCurrentScan()) socket.emit('scan:progress', event);
          },
          (event) => {
            if (isCurrentScan()) socket.emit('scan:log', event);
          },
        );
        if (!isCurrentScan()) return;
        const origin = await resolveScannerOrigin();
        const geo = buildScanGeo(report, origin);
        socket.emit('scan:geo', geo);
        socket.emit('scan:result', {
          target: report.normalizedTarget,
          report,
          geo,
        });
        socket.emit(
          'scan:log',
          makeLog(
            report.verdict === 'CRITICAL' || report.verdict === 'HIGH' ? 'error' : 'success',
            `Scan complete · verdict ${report.verdict}`,
          ),
        );
      } catch (err) {
        if (!isCurrentScan()) return;
        socket.emit('scan:error', {
          target,
          error: err instanceof Error ? err.message : 'Scan failed',
        });
      }
    });

    socket.on('disconnect', () => {
      windows.delete(socket.id);
    });
  });

  return io;
}
