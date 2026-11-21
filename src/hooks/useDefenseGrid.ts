import { useCallback, useEffect, useRef, useState } from 'react';
import { io, type Socket } from 'socket.io-client';
import type { AttackEvent, DefenseGridSnapshot } from '../types/defenseGrid.ts';
import type { DefenseAlertPayload, ServerToClientEvents, ClientToServerEvents } from '../types/realtime.ts';

interface DefenseGridState {
  snapshot: DefenseGridSnapshot | null;
  loading: boolean;
  connected: boolean;
  latestAlert: AttackEvent | null;
  report: string | null;
  busy: boolean;
  refresh: () => Promise<void>;
  setAutoDefense: (enabled: boolean) => Promise<void>;
  addSafeIp: (ip: string) => Promise<void>;
  reportIp: (ip: string) => Promise<void>;
  clearReport: () => void;
  clearStream: () => Promise<void>;
}

export function useDefenseGrid(): DefenseGridState {
  const [snapshot, setSnapshot] = useState<DefenseGridSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [latestAlert, setLatestAlert] = useState<AttackEvent | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const socketRef = useRef<Socket<ServerToClientEvents, ClientToServerEvents> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/defense/grid');
      if (res.ok) {
        setSnapshot((await res.json()) as DefenseGridSnapshot);
      }
    } catch {
      // keep last snapshot
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 15_000);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const socket: Socket<ServerToClientEvents, ClientToServerEvents> = io({
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1500,
      reconnectionDelayMax: 8000,
    });
    socketRef.current = socket;

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('attack:event', (event) => {
      setSnapshot((prev) => {
        if (!prev) return prev;
        const events = [event, ...prev.events].slice(0, 250);
        const blocked = event.action === 'blocked';
        return {
          ...prev,
          events,
          stats: {
            ...prev.stats,
            totalEvents: prev.stats.totalEvents + 1,
            blocked: prev.stats.blocked + (blocked ? 1 : 0),
            eventsLastMinute: prev.stats.eventsLastMinute + 1,
          },
        };
      });
    });
    socket.on('defense:alert', (payload: DefenseAlertPayload) => {
      setLatestAlert(payload.event);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, []);

  const setAutoDefense = useCallback(async (enabled: boolean) => {
    setBusy(true);
    try {
      await fetch('/api/defense/grid/auto', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      setSnapshot((prev) =>
        prev
          ? { ...prev, stats: { ...prev.stats, autoDefenseEnabled: enabled } }
          : prev,
      );
    } finally {
      setBusy(false);
    }
  }, []);

  const addSafeIp = useCallback(
    async (ip: string) => {
      setBusy(true);
      try {
        await fetch('/api/defense/grid/safe-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip }),
        });
        await refresh();
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const reportIp = useCallback(async (ip: string) => {
    setBusy(true);
    try {
      const res = await fetch('/api/defense/grid/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      const payload = (await res.json()) as { report?: string; error?: string };
      setReport(payload.report ?? payload.error ?? 'Report generation failed.');
    } catch (err) {
      setReport(err instanceof Error ? err.message : 'Report generation failed.');
    } finally {
      setBusy(false);
    }
  }, []);

  const clearStream = useCallback(async () => {
    setBusy(true);
    try {
      await fetch('/api/defense/grid/clear', { method: 'POST' });
      await refresh();
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  return {
    snapshot,
    loading,
    connected,
    latestAlert,
    report,
    busy,
    refresh,
    setAutoDefense,
    addSafeIp,
    reportIp,
    clearReport: () => setReport(null),
    clearStream,
  };
}
