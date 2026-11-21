import { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  AlertChannel,
  ControlCenterData,
  DeliveryEntry,
  DetectionConfig,
  IntegrationSnapshot,
  SensorOverview,
  WafActionResult,
  WafProvider,
  WafSyncEntry,
} from '../types/controlCenter.ts';
import type { ThreatSeverity } from '../types/cyber.ts';

type Notice = { kind: 'ok' | 'error'; text: string } | null;

async function readJson<T>(res: Response): Promise<T> {
  const payload = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(payload.error || `Request failed (HTTP ${res.status})`);
  return payload;
}

type Lang = 'bn' | 'en';

export function useControlCenter(lang: Lang = 'bn') {
  const msg = (bn: string, en: string) => (lang === 'bn' ? bn : en);
  const [data, setData] = useState<ControlCenterData>({
    sensors: null,
    wafProviders: [],
    wafAutoPush: true,
    wafLog: [],
    integrations: null,
    deliveries: [],
    dbStats: null,
    system: null,
    detection: null,
  });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [token, setToken] = useState<string | null>(null);
  const [agentCommand, setAgentCommand] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [sensors, waf, wafLog, integrations, deliveries, dbStats, system, detection] =
        await Promise.all([
          fetch('/api/sensors').then((res) => readJson<SensorOverview>(res)),
          fetch('/api/waf').then((res) => readJson<{ providers: WafProvider[]; autoPush: boolean }>(res)),
          fetch('/api/waf/log').then((res) => readJson<{ log: WafSyncEntry[] }>(res)),
          fetch('/api/integrations').then((res) => readJson<IntegrationSnapshot>(res)),
          fetch('/api/deliveries').then((res) => readJson<{ deliveries: DeliveryEntry[] }>(res)),
          fetch('/api/data/stats').then((res) => readJson<ControlCenterData['dbStats']>(res)),
          fetch('/api/system').then((res) => readJson<ControlCenterData['system']>(res)),
          fetch('/api/detection/config').then((res) => readJson<DetectionConfig>(res)),
        ]);
      setData({
        sensors,
        wafProviders: waf.providers,
        wafAutoPush: waf.autoPush !== false,
        wafLog: wafLog.log,
        integrations,
        deliveries: deliveries.deliveries,
        dbStats,
        system,
        detection,
      });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof Error ? err.message : msg('রিফ্রেশ ব্যর্থ হয়েছে।', 'Refresh failed') });
    } finally {
      setLoading(false);
    }
  }, [lang]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 30_000);
    return () => clearInterval(timer);
  }, [refresh]);

  const run = useCallback(
    async <T,>(action: () => Promise<T>, success: string): Promise<T | null> => {
      setBusy(true);
      setNotice(null);
      try {
        const result = await action();
        setNotice({ kind: 'ok', text: success });
        await refresh();
        return result;
      } catch (err) {
        setNotice({ kind: 'error', text: err instanceof Error ? err.message : msg('অ্যাকশন ব্যর্থ হয়েছে।', 'Action failed') });
        return null;
      } finally {
        setBusy(false);
      }
    },
    [refresh, lang],
  );

  const addSensor = useCallback(
    (input: { id: string; name: string; region?: string; url?: string }) =>
      run(async () => {
        await fetch('/api/sensors', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
        }).then((res) => readJson(res));
      }, msg('সেন্সর রেজিস্টার হয়েছে।', 'Sensor registered.')),
    [run, lang],
  );

  const setSensorEnabled = useCallback(
    (id: string, enabled: boolean) =>
      run(async () => {
        await fetch(`/api/sensors/${encodeURIComponent(id)}/enabled`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled }),
        }).then((res) => readJson(res));
      }, enabled ? msg('সেন্সর চালু হয়েছে।', 'Sensor enabled.') : msg('সেন্সর বন্ধ হয়েছে।', 'Sensor disabled.')),
    [run, lang],
  );

  const removeSensor = useCallback(
    (id: string) =>
      run(async () => {
        await fetch(`/api/sensors/${encodeURIComponent(id)}`, { method: 'DELETE' }).then((res) =>
          readJson(res),
        );
      }, msg('সেন্সর সরানো হয়েছে।', 'Sensor removed.')),
    [run, lang],
  );

  const rotateToken = useCallback(
    () =>
      run(async () => {
        const result = await fetch('/api/sensors/rotate-token', { method: 'POST' }).then((res) =>
          readJson<{ token: string }>(res),
        );
        setToken(result.token);
        return result;
      }, msg('সেন্সর ইনজেস্ট টোকেন রোটেট হয়েছে। সব এজেন্ট আপডেট করুন।', 'Sensor ingest token rotated. Update every agent.')),
    [run, lang],
  );

  const revealToken = useCallback(async () => {
    try {
      const result = await fetch('/api/sensors/token').then((res) => readJson<{ token: string }>(res));
      setToken(result.token);
      return result.token;
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof Error ? err.message : msg('টোকেন পড়া যায়নি।', 'Token read failed') });
      return null;
    }
  }, [lang]);

  const loadAgentCommand = useCallback(async (id: string, region: string) => {
    try {
      const result = await fetch(
        `/api/sensors/agent-command?id=${encodeURIComponent(id)}&region=${encodeURIComponent(region)}`,
      ).then((res) => readJson<{ command: string }>(res));
      setAgentCommand(result.command);
      return result.command;
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof Error ? err.message : msg('কমান্ড তৈরি ব্যর্থ হয়েছে।', 'Command failed') });
      return null;
    }
  }, [lang]);

  const setSensorAutoBlock = useCallback(
    (enabled: boolean) =>
      run(async () => {
        await fetch('/api/sensors/auto', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled }),
        }).then((res) => readJson(res));
      }, enabled ? msg('সেন্সর অটো-ব্লক চালু হয়েছে।', 'Sensor auto-block enabled.') : msg('সেন্সর অটো-ব্লক বন্ধ হয়েছে।', 'Sensor auto-block disabled.')),
    [run, lang],
  );

  const setWafAutoPush = useCallback(
    (enabled: boolean) =>
      run(async () => {
        await fetch('/api/waf/auto', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled }),
        }).then((res) => readJson(res));
      }, enabled ? msg('WAF অটো-পুশ চালু হয়েছে।', 'WAF auto-push enabled.') : msg('WAF অটো-পুশ বন্ধ হয়েছে।', 'WAF auto-push disabled.')),
    [run, lang],
  );

  const syncWaf = useCallback(
    () =>
      run(async () => {
        const result = await fetch('/api/waf/sync', { method: 'POST' }).then((res) =>
          readJson<{ results: WafActionResult[]; synced: number }>(res),
        );
        return result;
      }, msg('এজ ব্লকলিস্ট সিঙ্ক অনুরোধ পাঠানো হয়েছে।', 'Edge blocklist sync requested.')),
    [run, lang],
  );

  const pushWafIp = useCallback(
    (ip: string) =>
      run(async () => {
        await fetch('/api/waf/push', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip }),
        }).then((res) => readJson(res));
      }, msg(`কনফিগার করা এজ প্রোভাইডারে ${ip} পুশ করা হয়েছে।`, `Pushed ${ip} to configured edge providers.`)),
    [run, lang],
  );

  const removeWafIp = useCallback(
    (ip: string) =>
      run(async () => {
        await fetch(`/api/waf/ip/${encodeURIComponent(ip)}`, { method: 'DELETE' }).then((res) =>
          readJson(res),
        );
      }, msg(`এজ প্রোভাইডার থেকে ${ip} সরানো হয়েছে।`, `Removed ${ip} from edge providers.`)),
    [run, lang],
  );

  const saveIntegration = useCallback(
    (channel: AlertChannel, payload: Record<string, unknown>) =>
      run(async () => {
        await fetch(`/api/integrations/${channel}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        }).then((res) => readJson(res));
      }, msg('ইন্টিগ্রেশন সেভ হয়েছে।', 'Integration saved.')),
    [run, lang],
  );

  const deleteIntegration = useCallback(
    (channel: AlertChannel) =>
      run(async () => {
        await fetch(`/api/integrations/${channel}`, { method: 'DELETE' }).then((res) => readJson(res));
      }, msg('ইন্টিগ্রেশন সরানো হয়েছে।', 'Integration removed.')),
    [run, lang],
  );

  const testIntegration = useCallback(
    (channel: AlertChannel) =>
      run(async () => {
        const result = await fetch(`/api/integrations/${channel}/test`, { method: 'POST' }).then(
          (res) => readJson<{ ok: boolean; detail: string }>(res),
        );
        if (!result.ok) throw new Error(result.detail);
        return result;
      }, msg('টেস্ট অ্যালার্ট ডেলিভার হয়েছে।', 'Test alert delivered.')),
    [run, lang],
  );

  const setPolicy = useCallback(
    (policy: { minSeverity?: ThreatSeverity; notifyOnBlock?: boolean }) =>
      run(async () => {
        await fetch('/api/integrations/policy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(policy),
        }).then((res) => readJson(res));
      }, msg('অ্যালার্ট পলিসি আপডেট হয়েছে।', 'Alert policy updated.')),
    [run, lang],
  );

  const pruneData = useCallback(
    (days: number) =>
      run(async () => {
        const result = await fetch('/api/data/prune', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ days }),
        }).then((res) => readJson<{ deleted: number }>(res));
        return result;
      }, msg('পুরোনো ইভেন্ট প্রুন হয়েছে।', 'Old events pruned.')),
    [run, lang],
  );

  return useMemo(
    () => ({
      data,
      loading,
      busy,
      notice,
      token,
      agentCommand,
      refresh,
      addSensor,
      removeSensor,
    setSensorEnabled,
      rotateToken,
      revealToken,
      loadAgentCommand,
      setSensorAutoBlock,
      syncWaf,
    setWafAutoPush,
      pushWafIp,
      removeWafIp,
      saveIntegration,
      deleteIntegration,
      testIntegration,
      setPolicy,
      pruneData,
      clearNotice: () => setNotice(null),
    }),
    [
      data,
      loading,
      busy,
      notice,
      token,
      agentCommand,
      refresh,
      addSensor,
      removeSensor,
      rotateToken,
      revealToken,
      loadAgentCommand,
      setSensorAutoBlock,
      syncWaf,
      pushWafIp,
      removeWafIp,
      saveIntegration,
      deleteIntegration,
      testIntegration,
      setPolicy,
      pruneData,
    ],
  );
}
