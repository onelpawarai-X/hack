import { resolve4 } from 'node:dns/promises';
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
