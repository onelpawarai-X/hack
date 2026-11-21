import { useCallback, useEffect, useRef, useState } from 'react';
import { io, type Socket } from 'socket.io-client';
import type { ScanModuleId, TargetScanResult } from '../types/cyber';
import type {
  ClientToServerEvents,
  ScanGeoPayload,
  ScanLogEvent,
  ScanProgressPayload,
  ScannerOrigin,
  ServerToClientEvents,
} from '../types/realtime';

const MAX_LOGS = 500;

export interface ScanSocketState {
  connected: boolean;
  logs: ScanLogEvent[];
  progress: ScanProgressPayload | null;
  geo: ScanGeoPayload | null;
  result: TargetScanResult | null;
  error: string | null;
  scanning: boolean;
  scannerOrigin: ScannerOrigin | null;
  startScan: (target: string, modules?: ScanModuleId[]) => boolean;
  clearLogs: () => void;
  resetResult: () => void;
}

function makeLocalLog(level: ScanLogEvent['level'], message: string): ScanLogEvent {
  return {
    id: `local-${Date.now()}-${Math.round(Math.random() * 1e6)}`,
    ts: new Date().toISOString(),
    level,
    moduleId: 'socket',
    message,
  };
}

export function useScanSocket(): ScanSocketState {
  const socketRef = useRef<Socket<ServerToClientEvents, ClientToServerEvents> | null>(null);
  const [connected, setConnected] = useState(false);
  const [logs, setLogs] = useState<ScanLogEvent[]>([]);
  const [progress, setProgress] = useState<ScanProgressPayload | null>(null);
  const [geo, setGeo] = useState<ScanGeoPayload | null>(null);
  const [result, setResult] = useState<TargetScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scannerOrigin, setScannerOrigin] = useState<ScannerOrigin | null>(null);

  const appendLog = useCallback((event: ScanLogEvent) => {
    setLogs((prev) => [...prev.slice(-(MAX_LOGS - 1)), event]);
  }, []);

  useEffect(() => {
    const socket: Socket<ServerToClientEvents, ClientToServerEvents> = io({
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      setConnected(true);
      appendLog(makeLocalLog('success', 'Realtime scanning channel connected'));
    });
    socket.on('disconnect', (reason) => {
      setConnected(false);
      appendLog(makeLocalLog('warn', `Realtime channel disconnected (${reason})`));
      setScanning(false);
    });
    socket.on('connect_error', (err) => {
      setConnected(false);
      appendLog(makeLocalLog('error', `Realtime channel error: ${err.message}`));
    });
    socket.on('server:ready', (payload) => {
      if (payload.scannerOrigin) setScannerOrigin(payload.scannerOrigin);
    });
    socket.on('scan:log', (event) => appendLog(event));
    socket.on('scan:progress', (payload) => setProgress(payload));
    socket.on('scan:geo', (payload) => setGeo(payload));
    socket.on('scan:result', (payload) => {
      setResult(payload.report);
      setGeo(payload.geo);
      setScanning(false);
    });
    socket.on('scan:error', (payload) => {
      setError(payload.error);
      setScanning(false);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [appendLog]);

  const startScan = useCallback((target: string, modules?: ScanModuleId[]) => {
    const socket = socketRef.current;
    if (!socket || !socket.connected) {
      return false;
    }
    setScanning(true);
    setError(null);
    setResult(null);
    setGeo(null);
    setLogs([]);
    setProgress({
      type: 'progress',
      moduleId: 'init',
      label: 'Initializing modular scan pipeline...',
      percent: 2,
      completedModules: [],
    });
    socket.emit('scan:start', { target, modules }, (ack) => {
      if (!ack?.ok) {
        setError(ack?.error ?? 'Scan could not be started');
        setScanning(false);
      }
    });
    return true;
  }, []);

  const clearLogs = useCallback(() => setLogs([]), []);
  const resetResult = useCallback(() => {
    setResult(null);
    setGeo(null);
    setError(null);
    setProgress(null);
  }, []);

  return {
    connected,
    logs,
    progress,
    geo,
    result,
    error,
    scanning,
    scannerOrigin,
    startScan,
    clearLogs,
    resetResult,
  };
}
