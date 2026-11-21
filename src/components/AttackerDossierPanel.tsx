import Hls from 'hls.js';
import { Download, FileText, Globe2, MapPin, ShieldAlert, ShieldBan, Video } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { Language, ThreatActorExternalIntel } from '../types/cyber';

interface DossierEvent {
  ts: string;
  method: string;
  path: string;
  category: string;
  severity: string;
  action: string;
  detail: string;
  userAgent?: string;
  ja3?: string;
  tlsh?: string;
}

interface Dossier {
  ip: string;
  generatedAt: string;
  risk: { score: number; severity: string; factors: string[] };
  asn: { asn?: string; prefix?: string; registry?: string; holder?: string };
  geo: { country?: string; countryCode?: string; region?: string; city?: string; lat?: number; lon?: number; timezone?: string };
  reverseDns?: string;
  whois: { orgName?: string; handle?: string; cidr?: string; abuseEmails: string[]; server?: string };
  observedAttacks: {
    count: number;
    firstSeen?: string;
    lastSeen?: string;
    categories: Record<string, number>;
    severities: Record<string, number>;
    events: DossierEvent[];
  };
  externalIntel: ThreatActorExternalIntel;
  evidence: Array<{ id: string; type: string; value: string; source: string; confidence: string; detail: string }>;
  forensic: { sha256: string; sources: string[]; limitations: string[]; chainOfCustody: string };
  reportText: string;
  defended?: boolean;
}

interface PublicCamera {
  id: string;
  name: string;
  lat: number;
  lon: number;
  url: string;
  protocol: 'hls' | 'mjpeg' | 'iframe' | 'link';
  city?: string;
  country?: string;
  source: string;
  attribution?: string;
  distanceKm?: number;
}

interface OsmCamera {
  id: string;
  name: string;
  lat: number;
  lon: number;
  distanceKm: number;
  kind: string;
  operator?: string;
  zone?: string;
  mount?: string;
  direction?: string;
  description?: string;
  osmUrl: string;
  streamUrl?: string;
  protocol?: PublicCamera['protocol'];
  source: 'OpenStreetMap';
  attribution: string;
}

interface AttackerDossierPanelProps {
  lang: Language;
  initialIp?: string;
  onBlocked?: () => void;
}

function L(lang: Language, bn: string, en: string): string {
  return lang === 'bn' ? bn : en;
}

function CameraPlayer({ camera, lang }: { camera: PublicCamera; lang: Language }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setFailed(false);
    const video = videoRef.current;
    if (!video) return;
    if (camera.protocol === 'hls' && Hls.isSupported()) {
      const hls = new Hls({ enableWorker: true, lowLatencyMode: true });
      hls.loadSource(camera.url);
      hls.attachMedia(video);
      hls.on(Hls.Events.ERROR, () => setFailed(true));
      return () => hls.destroy();
    }
    video.src = camera.url;
    return undefined;
  }, [camera]);

  if (camera.protocol === 'iframe') {
    return (
      <iframe
        title={camera.name}
        src={camera.url}
        className="h-56 w-full rounded-lg border border-slate-800 bg-black"
        referrerPolicy="no-referrer"
        sandbox="allow-scripts allow-same-origin"
      />
    );
  }
  if (camera.protocol === 'link') {
    return (
      <a
        href={camera.url}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-[11px] font-semibold text-cyan-200"
      >
        <Video className="h-3.5 w-3.5" />
        {L(lang, 'পাবলিক ফিড খুলুন', 'Open public feed')}
      </a>
    );
  }
  return (
    <div className="space-y-1">
      <video
        ref={videoRef}
        controls
        muted
        playsInline
        className="h-56 w-full rounded-lg border border-slate-800 bg-black"
        onError={() => setFailed(true)}
      />
      {failed && (
        <p className="text-[9px] text-amber-300">
          {L(lang, 'স্ট্রিম লোড হয়নি। ফিডটি হয়তো বন্ধ বা CORS-ব্লকড।', 'Stream did not load. The feed may be offline or CORS-blocked.')}
        </p>
      )}
    </div>
  );
}

export function AttackerDossierPanel({ lang, initialIp, onBlocked }: AttackerDossierPanelProps) {
  const [ip, setIp] = useState(initialIp ?? '');
  const [dossier, setDossier] = useState<Dossier | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blockStatus, setBlockStatus] = useState<string | null>(null);
  const [cameras, setCameras] = useState<PublicCamera[]>([]);
  const [osmCameras, setOsmCameras] = useState<OsmCamera[]>([]);
  const [osmStatus, setOsmStatus] = useState<string | null>(null);
  const [selectedCamera, setSelectedCamera] = useState<PublicCamera | null>(null);
  const [cameraStatus, setCameraStatus] = useState<string | null>(null);
  const [shields, setShields] = useState<Array<{ id: string; host: string }>>([]);
  const [targetShieldId, setTargetShieldId] = useState('');
  const [cameraForm, setCameraForm] = useState({
    name: '',
    url: '',
    protocol: 'hls' as PublicCamera['protocol'],
    lat: '',
    lon: '',
  });

  useEffect(() => {
    if (initialIp && !ip) setIp(initialIp);
  }, [initialIp, ip]);

  useEffect(() => {
    fetch('/api/defense/state', { cache: 'no-store' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!data?.protectedShields) return;
        setShields(data.protectedShields);
        if (!targetShieldId && data.protectedShields[0]?.id) {
          setTargetShieldId(data.protectedShields[0].id);
        }
      })
      .catch(() => undefined);
  }, [targetShieldId]);

  const load = async (target = ip) => {
    const clean = target.trim();
    if (!clean) return;
    setLoading(true);
    setError(null);
    setBlockStatus(null);
    setSelectedCamera(null);
    setOsmCameras([]);
    setOsmStatus(null);
    try {
      const res = await fetch(`/api/attacker/${encodeURIComponent(clean)}`);
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setDossier(payload as Dossier);
      setIp(clean);
      const lat = payload.geo?.lat;
      const lon = payload.geo?.lon;
      if (Number.isFinite(lat) && Number.isFinite(lon)) {
        setCameraForm((prev) => ({ ...prev, lat: String(lat), lon: String(lon) }));
        setOsmStatus(L(lang, 'ওপেনস্ট্রিটম্যাপে আশপাশের সার্ভেইল্যান্স খোঁজা হচ্ছে…', 'Querying OpenStreetMap surveillance nearby…'));
        const [camRes, osmRes] = await Promise.all([
          fetch(`/api/cameras/nearby?lat=${lat}&lon=${lon}&radius=15`),
          fetch(`/api/cameras/osm-nearby?lat=${lat}&lon=${lon}&radius=0.5`),
        ]);
        if (camRes.ok) {
          const camPayload = await camRes.json();
          setCameras(Array.isArray(camPayload.cameras) ? camPayload.cameras : []);
        }
        const osmPayload = await osmRes.json().catch(() => null);
        if (osmRes.ok && osmPayload?.ok) {
          setOsmCameras(Array.isArray(osmPayload.cameras) ? osmPayload.cameras : []);
          setOsmStatus(null);
        } else {
          setOsmStatus(
            osmPayload?.error ||
              L(lang, 'ওএসএম কোয়েরি ব্যর্থ হয়েছে।', 'OpenStreetMap query failed.'),
          );
        }
      }
    } catch (err) {
      setDossier(null);
      setError(err instanceof Error ? err.message : 'Dossier failed');
    } finally {
      setLoading(false);
    }
  };

  const block = async () => {
    if (!dossier) return;
    setBlockStatus(null);
    try {
      const res = await fetch('/api/defense/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: dossier.ip,
          reason: `Forensic dossier risk ${dossier.risk.score}/100`,
          assetId: targetShieldId || undefined,
        }),
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setBlockStatus(
        targetShieldId
          ? L(lang, 'সুরক্ষিত সাইটের জন্য ব্লক রুল তৈরি হয়েছে।', 'Block rule generated for the protected site.')
          : L(lang, 'কন্ট্রোল প্লেনে ব্লক হয়েছে।', 'Blocked in the control plane.'),
      );
      onBlocked?.();
    } catch (err) {
      setBlockStatus(err instanceof Error ? err.message : 'Block failed');
    }
  };

  const addCamera = async () => {
    setCameraStatus(null);
    try {
      const res = await fetch('/api/cameras', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...cameraForm,
          lat: Number(cameraForm.lat),
          lon: Number(cameraForm.lon),
          source: 'operator-import',
        }),
      });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.error || `HTTP ${res.status}`);
      setCameraStatus(L(lang, 'পাবলিক ক্যামেরা যোগ হয়েছে।', 'Public camera added.'));
      setCameraForm((prev) => ({ ...prev, name: '', url: '' }));
      if (dossier) {
        const camRes = await fetch(`/api/cameras/nearby?lat=${dossier.geo.lat}&lon=${dossier.geo.lon}&radius=15`);
        if (camRes.ok) setCameras((await camRes.json()).cameras ?? []);
      }
    } catch (err) {
      setCameraStatus(err instanceof Error ? err.message : 'Camera add failed');
    }
  };

  const download = (format: string) => {
    if (!dossier) return;
    window.open(`/api/attacker/${encodeURIComponent(dossier.ip)}/report?format=${format}`, '_blank', 'noopener');
  };

  return (
    <section className="soc-panel rounded-xl p-4 space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-red-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L(lang, 'ফরেনসিক অ্যাটাকার ডসিয়ার', 'Forensic attacker dossier')}
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-[11px] text-slate-400">
            {L(
              lang,
              'অফলাইন GeoIP, Team Cymru DNS, RIR WHOIS, লোকাল সেন্সর ও IOC — কোনো রেট-লিমিটেড API নেই। আইপি কখনো ব্যক্তির নাম নয়; শুধু নেটওয়ার্ক-প্রমাণ।',
              'Offline GeoIP, Team Cymru DNS, RIR WHOIS, local sensor and IOC — no rate-limited API. An IP is never a person; this is network evidence only.',
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            value={ip}
            onChange={(event) => setIp(event.target.value)}
            placeholder="8.8.8.8"
            className="w-44 rounded-lg border border-slate-700 bg-[#04060A] px-2.5 py-1.5 font-mono text-[11px] text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading || !ip.trim()}
            className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-[11px] font-semibold text-cyan-200 disabled:opacity-40"
          >
            {loading ? L(lang, 'স্ক্যান...', 'Scanning...') : L(lang, 'ডসিয়ার তৈরি', 'Build dossier')}
          </button>
        </div>
      </div>

      {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-2 text-[11px] text-red-200">{error}</div>}

      {dossier && (
        <>
          <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-2.5">
              <div className="text-[9px] uppercase text-slate-500">Risk</div>
              <div className="font-mono text-lg font-bold text-red-300">{dossier.risk.score}/100</div>
              <div className="text-[9px] text-slate-400">{dossier.risk.severity}</div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-2.5">
              <div className="text-[9px] uppercase text-slate-500">ASN / prefix</div>
              <div className="font-mono text-[11px] text-slate-100">{dossier.asn.asn ?? '—'}</div>
              <div className="text-[9px] text-slate-400">{dossier.asn.prefix ?? '—'}</div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-2.5">
              <div className="text-[9px] uppercase text-slate-500">Network location</div>
              <div className="text-[11px] text-slate-100">{dossier.geo.city || 'Unknown'}, {dossier.geo.country || 'Unknown'}</div>
              <div className="font-mono text-[9px] text-slate-500">{dossier.geo.lat}, {dossier.geo.lon}</div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-2.5">
              <div className="text-[9px] uppercase text-slate-500">Observed events</div>
              <div className="font-mono text-lg font-bold text-amber-300">{dossier.observedAttacks.count}</div>
              <div className="text-[9px] text-slate-400">{dossier.observedAttacks.lastSeen ? new Date(dossier.observedAttacks.lastSeen).toLocaleString() : 'none'}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-3">
              <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-bold text-cyan-300">
                <Globe2 className="h-3.5 w-3.5" /> {L(lang, 'নেটওয়ার্ক প্রমাণ', 'Network evidence')}
              </h3>
              <dl className="space-y-1 text-[10px]">
                {[
                  ['Organisation', dossier.whois.orgName || dossier.asn.holder || 'unknown'],
                  ['Reverse DNS', dossier.reverseDns || 'none'],
                  ['CIDR', dossier.whois.cidr || dossier.asn.prefix || 'unknown'],
                  ['RIR', dossier.asn.registry || 'unknown'],
                  ['Abuse', dossier.whois.abuseEmails.join(', ') || 'not published'],
                  ['SHA-256', dossier.forensic.sha256],
                ].map(([label, value]) => (
                  <div key={label} className="flex gap-2">
                    <dt className="w-24 shrink-0 text-slate-500">{label}</dt>
                    <dd className="break-all text-slate-200">{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {['txt', 'json', 'html', 'eml'].map((format) => (
                  <button
                    key={format}
                    type="button"
                    onClick={() => download(format)}
                    className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-[9px] font-semibold text-slate-300 hover:border-cyan-500/50"
                  >
                    <Download className="h-3 w-3" /> {format.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-3">
              <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-bold text-amber-300">
                <FileText className="h-3.5 w-3.5" /> {L(lang, 'রিস্ক ফ্যাক্টর', 'Risk factors')}
              </h3>
              <ul className="space-y-1 text-[10px] text-slate-300">
                {dossier.risk.factors.map((factor) => <li key={factor}>• {factor}</li>)}
              </ul>
              <div className="mt-3 space-y-1.5">
                {shields.length > 0 && (
                  <select
                    value={targetShieldId}
                    onChange={(event) => setTargetShieldId(event.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-[#02060c] px-2 py-1.5 text-[10px] text-slate-100"
                  >
                    {shields.map((shield) => (
                      <option key={shield.id} value={shield.id}>
                        {L(lang, 'ব্লক করুন:', 'Block at:')} {shield.host}
                      </option>
                    ))}
                    <option value="">{L(lang, 'শুধু কন্ট্রোল প্লেন', 'Control plane only')}</option>
                  </select>
                )}
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => void block()}
                    className="inline-flex items-center gap-1 rounded-lg border border-red-500/40 bg-red-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-red-200"
                  >
                    <ShieldBan className="h-3 w-3" /> {L(lang, 'লোকালি ব্লক', 'Block locally')}
                  </button>
                </div>
                {blockStatus && <p className="text-[9px] text-emerald-300">{blockStatus}</p>}
              </div>
            </div>
          </div>

          {dossier.externalIntel && (
            <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="flex items-center gap-1.5 text-[11px] font-bold text-cyan-200">
                  <Globe2 className="h-3.5 w-3.5" /> {L(lang, 'গ্লোবাল OSINT অডিট', 'Global OSINT audit')}
                </h3>
                <div className="flex flex-wrap gap-1">
                  {dossier.externalIntel.sources.map((source) => (
                    <span
                      key={source.name}
                      title={source.detail}
                      className={`rounded-full border px-1.5 py-0.5 text-[8px] ${
                        source.status === 'online'
                          ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                          : 'border-amber-500/40 bg-amber-500/10 text-amber-200'
                      }`}
                    >
                      {source.name}: {source.detail}
                    </span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                <div className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
                  <div className="text-[9px] uppercase text-slate-500">Shodan InternetDB</div>
                  {dossier.externalIntel.shodan ? (
                    <div className="mt-1 space-y-1 text-[10px] text-slate-300">
                      <div><span className="text-slate-500">ports:</span> {dossier.externalIntel.shodan.ports.join(', ') || 'none'}</div>
                      <div><span className="text-slate-500">hostnames:</span> {dossier.externalIntel.shodan.hostnames.join(', ') || 'none'}</div>
                      <div><span className="text-slate-500">tags:</span> {dossier.externalIntel.shodan.tags.join(', ') || 'none'}</div>
                      <div className={dossier.externalIntel.shodan.vulns.length ? 'text-red-300' : ''}>
                        <span className="text-slate-500">CVEs:</span> {dossier.externalIntel.shodan.vulns.join(', ') || 'none'}
                      </div>
                    </div>
                  ) : (
                    <p className="mt-1 text-[10px] text-slate-500">{L(lang, 'এই IP-এর জন্য Shodan রেকর্ড নেই।', 'No Shodan record for this IP.')}</p>
                  )}
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
                  <div className="text-[9px] uppercase text-slate-500">AlienVault OTX</div>
                  <div className="mt-1 text-[10px] text-slate-300">
                    <div><span className="text-slate-500">pulses:</span> {dossier.externalIntel.otx.pulseCount}</div>
                    <div><span className="text-slate-500">malware families:</span> {dossier.externalIntel.otx.malwareFamilies.join(', ') || 'none'}</div>
                    <div><span className="text-slate-500">tags:</span> {dossier.externalIntel.otx.tags.join(', ') || 'none'}</div>
                  </div>
                </div>
              </div>

              {dossier.externalIntel.otx.pulses.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
                  <div className="mb-1 text-[9px] uppercase text-slate-500">OTX pulses / campaigns</div>
                  <div className="max-h-48 space-y-1 overflow-y-auto">
                    {dossier.externalIntel.otx.pulses.map((pulse, index) => (
                      <div key={`${pulse.name}-${index}`} className="rounded border border-slate-800/70 p-1.5">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-semibold text-slate-200">{pulse.name}</span>
                          {pulse.adversary && <span className="rounded bg-red-500/10 px-1 text-[8px] text-red-300">{pulse.adversary}</span>}
                          {pulse.modified && <span className="ml-auto font-mono text-[8px] text-slate-500">{new Date(pulse.modified).toLocaleDateString()}</span>}
                        </div>
                        {pulse.description && <p className="mt-0.5 line-clamp-2 text-[9px] text-slate-400">{pulse.description}</p>}
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {[...pulse.tags, ...pulse.malwareFamilies].slice(0, 8).map((tag) => (
                            <span key={tag} className="rounded bg-slate-800 px-1 text-[8px] text-slate-300">{tag}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {dossier.externalIntel.otx.passiveDns.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
                  <div className="mb-1 text-[9px] uppercase text-slate-500">Passive DNS history</div>
                  <div className="max-h-40 overflow-y-auto">
                    <table className="w-full text-left text-[9px]">
                      <thead className="text-slate-500"><tr><th className="p-1">Hostname</th><th className="p-1">First</th><th className="p-1">Last</th><th className="p-1">Type</th></tr></thead>
                      <tbody className="text-slate-300">
                        {dossier.externalIntel.otx.passiveDns.slice(0, 25).map((record, index) => (
                          <tr key={`${record.hostname}-${index}`} className="border-t border-slate-800/60">
                            <td className="p-1 font-mono break-all">{record.hostname}</td>
                            <td className="p-1 text-slate-500">{record.first ? new Date(record.first).toLocaleDateString() : '—'}</td>
                            <td className="p-1 text-slate-500">{record.last ? new Date(record.last).toLocaleDateString() : '—'}</td>
                            <td className="p-1">{record.recordType ?? '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {dossier.externalIntel.otx.urls.length > 0 && (
                <div className="rounded-lg border border-slate-800 bg-[#02060c] p-2">
                  <div className="mb-1 text-[9px] uppercase text-slate-500">Historical URLs</div>
                  <div className="max-h-32 space-y-0.5 overflow-y-auto">
                    {dossier.externalIntel.otx.urls.slice(0, 15).map((url, index) => (
                      <div key={`${url.url}-${index}`} className="flex gap-2 text-[9px]">
                        <span className="shrink-0 font-mono text-slate-500">{url.date ? new Date(url.date).toLocaleDateString() : '—'}</span>
                        <a href={url.url} target="_blank" rel="noreferrer" className="truncate text-cyan-300 underline decoration-dotted">{url.url}</a>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {dossier.observedAttacks.events.length > 0 && (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-[9px]">
                <thead className="bg-slate-900/60 text-slate-500">
                  <tr>
                    <th className="p-1.5">Time</th>
                    <th className="p-1.5">Severity</th>
                    <th className="p-1.5">Category</th>
                    <th className="p-1.5">Request</th>
                    <th className="p-1.5">Detail</th>
                  </tr>
                </thead>
                <tbody className="text-slate-300">
                  {dossier.observedAttacks.events.slice(0, 12).map((event, index) => (
                    <tr key={`${event.ts}-${index}`} className="border-t border-slate-800/70">
                      <td className="p-1.5 font-mono text-slate-500">{new Date(event.ts).toLocaleString()}</td>
                      <td className="p-1.5">{event.severity}</td>
                      <td className="p-1.5">{event.category}</td>
                      <td className="p-1.5 font-mono">{event.method} {event.path}</td>
                      <td className="p-1.5">{event.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="rounded-lg border border-slate-800 bg-[#04060A] p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="flex items-center gap-1.5 text-[11px] font-bold text-emerald-300">
                <MapPin className="h-3.5 w-3.5" /> {L(lang, 'কাছের পাবলিক ক্যামেরা', 'Nearby public cameras')}
              </h3>
              <span className="text-[9px] text-slate-500">
                {L(lang, 'শুধু পাবলিক ও অনুমোদিত ফিড; ব্যক্তিকে ট্র্যাক করার জন্য নয়।', 'Public/authorized feeds only; not for tracking individuals.')}
              </span>
            </div>
            {cameras.length === 0 ? (
              <p className="mt-2 text-[10px] text-slate-500">
                {L(lang, '১৫ কিমি-তে কোনো নিবন্ধিত পাবলিক ক্যামেরা নেই। নিচে অনুমোদিত ফিড যোগ করুন।', 'No registered public camera within 15 km. Add an authorized feed below.')}
              </p>
            ) : (
              <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                {cameras.map((camera) => (
                  <div key={camera.id} className="rounded-lg border border-slate-800 p-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-semibold text-slate-200">{camera.name}</span>
                      <span className="ml-auto font-mono text-[9px] text-cyan-300">{camera.distanceKm?.toFixed(1)} km</span>
                    </div>
                    <div className="text-[9px] text-slate-500">{camera.city || '—'} {camera.country || ''} · {camera.protocol} · {camera.source}</div>
                    <button
                      type="button"
                      onClick={() => setSelectedCamera(camera)}
                      className="mt-1 inline-flex items-center gap-1 rounded border border-cyan-500/40 px-2 py-1 text-[9px] font-semibold text-cyan-200"
                    >
                      <Video className="h-3 w-3" /> {L(lang, 'ফিড দেখুন', 'View feed')}
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-[10px] font-bold text-cyan-200">
                  {L(lang, 'ওপেনস্ট্রিটম্যাপ সার্ভেইল্যান্স (৫০০ মিটার)', 'OpenStreetMap surveillance (500 m)')}
                  {osmCameras.length > 0 ? ` · ${osmCameras.length}` : ''}
                </h4>
                <a
                  href={`https://www.openstreetmap.org/#map=17/${dossier.geo.lat}/${dossier.geo.lon}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-[9px] text-cyan-300 underline decoration-dotted"
                >
                  {L(lang, 'ম্যাপে দেখুন', 'Open map')}
                </a>
              </div>
              <p className="mt-1 text-[9px] text-slate-500">
                {L(
                  lang,
                  'ওএসএম-এ ম্যাপ করা পাবলিক সার্ভেইল্যান্স নোড; ODbL ডেটা। ব্যক্তিগত বা আবাসিক ক্যামেরা নয়।',
                  'Public surveillance nodes mapped in OSM; ODbL data. Not private or residential cameras.',
                )}
              </p>
              {osmCameras.length === 0 ? (
                <p className="mt-2 text-[10px] text-slate-500">
                  {L(lang, '৫০০ মিটারের মধ্যে ওএসএম-এ কোনো সার্ভেইল্যান্স ম্যাপ করা নেই।', 'No surveillance mapped in OSM within 500 m.')}
                </p>
              ) : (
                <div className="mt-2 grid max-h-56 grid-cols-1 gap-1.5 overflow-y-auto md:grid-cols-2">
                  {osmCameras.map((camera) => (
                    <div key={camera.id} className="rounded border border-slate-800 bg-[#02060c] p-2">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[10px] font-semibold text-slate-200">{camera.name}</span>
                        <span className="ml-auto shrink-0 font-mono text-[9px] text-cyan-300">
                          {camera.distanceKm < 1
                            ? `${Math.round(camera.distanceKm * 1000)} m`
                            : `${camera.distanceKm.toFixed(1)} km`}
                        </span>
                      </div>
                      <div className="truncate text-[9px] text-slate-500">
                        {[camera.kind, camera.operator, camera.zone, camera.mount].filter(Boolean).join(' · ')}
                      </div>
                      <div className="mt-1 flex items-center gap-2">
                        <a
                          href={camera.osmUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[9px] text-cyan-300 underline decoration-dotted"
                        >
                          OSM
                        </a>
                        {camera.streamUrl && (
                          <button
                            type="button"
                            onClick={() =>
                              setSelectedCamera({
                                id: camera.id,
                                name: camera.name,
                                lat: camera.lat,
                                lon: camera.lon,
                                url: camera.streamUrl!,
                                protocol: camera.protocol ?? 'link',
                                city: camera.zone,
                                source: camera.source,
                                attribution: camera.attribution,
                              })
                            }
                            className="inline-flex items-center gap-1 rounded border border-cyan-500/40 px-1.5 py-0.5 text-[9px] font-semibold text-cyan-200"
                          >
                            <Video className="h-2.5 w-2.5" /> {L(lang, 'ফিড', 'Feed')}
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {osmStatus && <p className="mt-1 text-[9px] text-amber-300">{osmStatus}</p>}
            </div>
            {selectedCamera && (
              <div className="mt-3">
                <div className="mb-1 flex items-center justify-between text-[10px] text-slate-300">
                  <span>{selectedCamera.name}</span>
                  <button type="button" onClick={() => setSelectedCamera(null)} className="text-slate-500">✕</button>
                </div>
                <CameraPlayer camera={selectedCamera} lang={lang} />
                {selectedCamera.attribution && <p className="mt-1 text-[9px] text-slate-500">{selectedCamera.attribution}</p>}
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-1.5 md:grid-cols-5">
              <input value={cameraForm.name} onChange={(e) => setCameraForm((p) => ({ ...p, name: e.target.value }))} placeholder="Name" className="rounded border border-slate-700 bg-[#02060c] px-2 py-1 text-[9px] text-slate-100" />
              <input value={cameraForm.url} onChange={(e) => setCameraForm((p) => ({ ...p, url: e.target.value }))} placeholder="https://public-camera/stream.m3u8" className="rounded border border-slate-700 bg-[#02060c] px-2 py-1 text-[9px] text-slate-100 md:col-span-2" />
              <select value={cameraForm.protocol} onChange={(e) => setCameraForm((p) => ({ ...p, protocol: e.target.value as PublicCamera['protocol'] }))} className="rounded border border-slate-700 bg-[#02060c] px-2 py-1 text-[9px] text-slate-100">
                <option value="hls">HLS</option>
                <option value="mjpeg">MJPEG</option>
                <option value="iframe">iframe</option>
                <option value="link">link</option>
              </select>
              <input value={cameraForm.lat} onChange={(e) => setCameraForm((p) => ({ ...p, lat: e.target.value }))} placeholder="lat" className="rounded border border-slate-700 bg-[#02060c] px-2 py-1 text-[9px] text-slate-100" />
              <input value={cameraForm.lon} onChange={(e) => setCameraForm((p) => ({ ...p, lon: e.target.value }))} placeholder="lon" className="rounded border border-slate-700 bg-[#02060c] px-2 py-1 text-[9px] text-slate-100" />
              <button type="button" onClick={() => void addCamera()} className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[9px] font-semibold text-emerald-200">
                {L(lang, 'ক্যামেরা যোগ', 'Add camera')}
              </button>
            </div>
            {cameraStatus && <p className="mt-1 text-[9px] text-amber-300">{cameraStatus}</p>}
          </div>
        </>
      )}
    </section>
  );
}
