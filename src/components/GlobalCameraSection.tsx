import type Hls from 'hls.js';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Camera, ExternalLink, Globe2, Loader2, MapPin, Search, Video } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Language } from '../types/cyber';

interface GlobalCamera {
  id: string;
  name: string;
  lat: number;
  lon: number;
  distanceKm: number;
  kind: string;
  operator?: string;
  zone?: string;
  mount?: string;
  description?: string;
  osmUrl: string;
  streamUrl?: string;
  protocol?: 'hls' | 'mjpeg' | 'iframe' | 'link' | 'image';
  source: string;
  attribution: string;
}

interface CameraResponse {
  ok: boolean;
  cameras: GlobalCamera[];
  error?: string;
  fetchedAt: string;
}

const L10N = (lang: Language, bn: string, en: string) => (lang === 'bn' ? bn : en);

function cameraIcon(selected: boolean): L.DivIcon {
  return L.divIcon({
    className: 'sg-camera-marker-host',
    html: `<div style="width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;background:${selected ? '#22d3ee' : '#0e7490'};border:2px solid ${selected ? '#fff' : '#67e8f9'};box-shadow:0 0 10px rgba(34,211,238,.8)">📷</div>`,
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
}

function HlsVideo({ src, title }: { src: string; title: string }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    if (video.canPlayType('application/vnd.apple.mpegurl')) {
      video.src = src;
      return;
    }
    let cancelled = false;
    let hls: Hls | null = null;
    void import('hls.js').then(({ default: HlsPlayer }) => {
      if (cancelled || !HlsPlayer.isSupported()) return;
      hls = new HlsPlayer();
      hls.loadSource(src);
      hls.attachMedia(video);
    });
    return () => {
      cancelled = true;
      hls?.destroy();
    };
  }, [src]);
  return (
    <video
      ref={videoRef}
      controls
      autoPlay
      muted
      playsInline
      className="h-64 w-full rounded-lg border border-slate-800 bg-black"
      aria-label={title}
    />
  );
}

function CameraPreview({ camera, lang }: { camera: GlobalCamera; lang: Language }) {
  const [tick, setTick] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [src, setSrc] = useState('');
  const [failed, setFailed] = useState(false);

  const withCacheBust = useCallback(
    (url: string, stamp: number) => {
      const separator = url.includes('?') ? '&' : '?';
      return `${url}${separator}t=${stamp}`;
    },
    [],
  );

  useEffect(() => {
    setFailed(false);
    setTick(0);
    setSrc(camera.streamUrl ? withCacheBust(camera.streamUrl, Date.now()) : '');
  }, [camera.id, camera.streamUrl, withCacheBust]);

  useEffect(() => {
    if (camera.protocol !== 'image' || !camera.streamUrl || !autoRefresh) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), 20_000);
    return () => window.clearInterval(timer);
  }, [camera.protocol, camera.streamUrl, autoRefresh]);

  useEffect(() => {
    if (camera.protocol !== 'image' || !camera.streamUrl || tick === 0) return;
    const next = withCacheBust(camera.streamUrl, Date.now());
    const image = new Image();
    image.onload = () => {
      setFailed(false);
      setSrc(next);
    };
    image.onerror = () => setFailed(true);
    image.src = next;
  }, [camera.protocol, camera.streamUrl, tick, withCacheBust]);

  const badge = (
    <div className="flex flex-wrap items-center gap-1.5">
      <span
        className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-semibold ${
          camera.protocol === 'hls' || camera.protocol === 'mjpeg' || camera.protocol === 'iframe'
            ? 'border-red-500/40 bg-red-500/10 text-red-200'
            : 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200'
        }`}
      >
        <span className="h-1.5 w-1.5 rounded-full bg-current" />
        {camera.protocol === 'hls' || camera.protocol === 'mjpeg' || camera.protocol === 'iframe'
          ? 'LIVE'
          : 'SNAPSHOT'}
      </span>
      {camera.protocol === 'image' && (
        <button
          type="button"
          onClick={() => setAutoRefresh((value) => !value)}
          className={`rounded-full border px-2 py-0.5 text-[9px] font-semibold ${
            autoRefresh
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-slate-700 bg-slate-900 text-slate-400'
          }`}
        >
          {autoRefresh
            ? L10N(lang, 'অটো রিফ্রেশ: চালু', 'Auto refresh: on')
            : L10N(lang, 'অটো রিফ্রেশ: বন্ধ', 'Auto refresh: off')}
        </button>
      )}
    </div>
  );

  if (!camera.streamUrl) {
    return (
      <div className="space-y-2">
        {badge}
        <div className="rounded-lg border border-slate-800 bg-[#02060c] p-3 text-[10px] text-slate-400">
          {L10N(
            lang,
            'এই পাবলিক ক্যামেরার সরাসরি স্ট্রিম OSM-এ নেই। নিচের OSM লিংক থেকে মালিক/অপারেটরের তথ্য দেখুন।',
            'This public camera has no direct stream in OSM. Open the OSM link for owner/operator details.',
          )}
        </div>
      </div>
    );
  }
  if (camera.protocol === 'image') {
    return (
      <div className="space-y-2">
        {badge}
        {failed && (
          <p className="text-[9px] text-amber-300">
            {L10N(lang, 'স্ন্যাপশট লোড হয়নি। অপারেটর হয়তো ফিড বন্ধ করেছে।', 'Snapshot did not load. The operator may have stopped the feed.')}
          </p>
        )}
        <img
          src={src}
          alt={camera.name}
          onError={() => setFailed(true)}
          className="h-64 w-full rounded-lg border border-slate-800 bg-black object-contain"
          loading="lazy"
          referrerPolicy="no-referrer"
        />
      </div>
    );
  }
  if (camera.protocol === 'iframe') {
    return (
      <div className="space-y-2">
        {badge}
        <iframe
          title={camera.name}
          src={camera.streamUrl}
          className="h-64 w-full rounded-lg border border-slate-800 bg-black"
          referrerPolicy="no-referrer"
          sandbox="allow-scripts allow-same-origin"
        />
      </div>
    );
  }
  if (camera.protocol === 'hls') {
    return (
      <div className="space-y-2">
        {badge}
        <HlsVideo key={camera.streamUrl} src={camera.streamUrl} title={camera.name} />
      </div>
    );
  }
  if (camera.protocol === 'mjpeg') {
    return (
      <div className="space-y-2">
        {badge}
        <img
          src={camera.streamUrl}
          alt={camera.name}
          onError={() => setFailed(true)}
          className="h-64 w-full rounded-lg border border-slate-800 bg-black object-contain"
          referrerPolicy="no-referrer"
        />
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {badge}
      <a
        href={camera.streamUrl}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-[11px] font-semibold text-cyan-200"
      >
        <Video className="h-3.5 w-3.5" />
        {L10N(lang, 'পাবলিক স্ট্রিম খুলুন', 'Open public stream')}
      </a>
    </div>
  );
}

export function GlobalCameraSection({
  lang,
  focus,
}: {
  lang: Language;
  focus?: { lat: number; lon: number; label: string } | null;
}) {
  const mapElementRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markersRef = useRef<L.LayerGroup | null>(null);
  const loadTimerRef = useRef<number | null>(null);
  const suppressMoveRef = useRef(false);
  const [cameras, setCameras] = useState<GlobalCamera[]>([]);
  const [selected, setSelected] = useState<GlobalCamera | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');

  const load = useCallback(async () => {
    const map = mapRef.current;
    if (!map) return;
    const bounds = map.getBounds();
    setLoading(true);
    try {
      const params = new URLSearchParams({
        south: String(bounds.getSouth()),
        west: String(bounds.getWest()),
        north: String(bounds.getNorth()),
        east: String(bounds.getEast()),
      });
      const center = bounds.getCenter();
      const loadOsm = async (): Promise<CameraResponse> => {
        try {
          const direct = await fetch(`/api/cameras/osm-bbox?${params.toString()}`, {
            cache: 'no-store',
          });
          const payload = (await direct.json().catch(() => null)) as CameraResponse | null;
          return payload ?? {
            ok: false,
            cameras: [],
            fetchedAt: new Date().toISOString(),
            error: `OSM HTTP ${direct.status}`,
          };
        } catch {
          return {
            ok: false,
            cameras: [],
            fetchedAt: new Date().toISOString(),
            error: 'OSM request failed',
          };
        }
      };
      const loadFeeds = async (): Promise<CameraResponse> => {
        try {
          const response = await fetch(
            `/api/cameras/public-nearby?lat=${center.lat}&lon=${center.lng}&radius=80`,
            { cache: 'no-store' },
          );
          const payload = (await response.json().catch(() => null)) as CameraResponse | null;
          return payload ?? { ok: false, cameras: [], fetchedAt: new Date().toISOString() };
        } catch {
          return { ok: false, cameras: [], fetchedAt: new Date().toISOString() };
        }
      };
      const [osmPayload, feedPayload] = await Promise.all([loadOsm(), loadFeeds()]);
      const merged = [...(osmPayload.cameras ?? []), ...(feedPayload.cameras ?? [])]
        .filter((camera, index, list) => list.findIndex((item) => item.id === camera.id) === index)
        .sort((a, b) => a.distanceKm - b.distanceKm)
        .slice(0, 80);
      setCameras(merged);
      setStatus(
        merged.length === 0
          ? L10N(lang, 'এই এলাকায় কোনো পাবলিক ক্যামেরা পাওয়া যায়নি। জুম করুন বা অন্য জায়গায় যান।', 'No public cameras in this area. Zoom in or move the map.')
          : L10N(
              lang,
              `${merged.length}টি নিকটতম পাবলিক ক্যামেরা দেখানো হচ্ছে।`,
              `Showing the ${merged.length} nearest public camera(s).`,
            ),
      );
    } catch (error) {
      setCameras([]);
      setStatus(error instanceof Error ? error.message : 'Camera query failed');
    } finally {
      setLoading(false);
    }
  }, [lang]);

  useEffect(() => {
    if (!mapElementRef.current || mapRef.current) return;
    const map = L.map(mapElementRef.current, {
      center: [22, 12],
      zoom: 3,
      worldCopyJump: true,
      preferCanvas: true,
    });
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      attribution: 'Tiles © Esri · Cameras © OpenStreetMap contributors (ODbL)',
      maxZoom: 18,
    }).addTo(map);
    const markers = L.layerGroup().addTo(map);
    mapRef.current = map;
    markersRef.current = markers;
    const scheduleLoad = () => {
      if (suppressMoveRef.current) return;
      if (loadTimerRef.current !== null) window.clearTimeout(loadTimerRef.current);
      loadTimerRef.current = window.setTimeout(() => void load(), 450);
    };
    map.on('moveend', scheduleLoad);
    window.setTimeout(() => void load(), 600);
    return () => {
      if (loadTimerRef.current !== null) window.clearTimeout(loadTimerRef.current);
      map.remove();
      mapRef.current = null;
      markersRef.current = null;
    };
  }, [load]);

  const focusLat = focus?.lat;
  const focusLon = focus?.lon;
  const focusLabel = focus?.label;

  useEffect(() => {
    if (focusLat === undefined || focusLon === undefined || !mapRef.current) return;
    suppressMoveRef.current = true;
    mapRef.current.setView([focusLat, focusLon], 13);
    window.setTimeout(() => {
      suppressMoveRef.current = false;
    }, 900);
    setStatus(
      L10N(
        lang,
        `${focusLabel ?? ''}-এর আশেপাশের পাবলিক ক্যামেরা লোড হচ্ছে…`,
        `Loading public cameras near ${focusLabel ?? ''}…`,
      ),
    );
  }, [focusLat, focusLon, focusLabel, lang]);

  useEffect(() => {
    const markers = markersRef.current;
    if (!markers) return;
    markers.clearLayers();
    for (const camera of cameras) {
      const marker = L.marker([camera.lat, camera.lon], {
        icon: cameraIcon(selected?.id === camera.id),
        title: camera.name,
      });
      marker.on('click', () => setSelected(camera));
      marker.bindTooltip(camera.name, { direction: 'top', offset: [0, -10] });
      marker.addTo(markers);
    }
  }, [cameras, selected]);

  const selectedPosition = useMemo(
    () => (selected ? [selected.lat, selected.lon] as [number, number] : null),
    [selected],
  );

  useEffect(() => {
    if (selectedPosition && mapRef.current) {
      suppressMoveRef.current = true;
      mapRef.current.flyTo(selectedPosition, Math.max(mapRef.current.getZoom(), 14), { duration: 0.8 });
      window.setTimeout(() => {
        suppressMoveRef.current = false;
      }, 1200);
    }
  }, [selectedPosition]);

  const jumpTo = (lat: number, lon: number, zoom = 14) => {
    mapRef.current?.setView([lat, lon], zoom);
  };

  const search = async () => {
    const q = query.trim();
    if (!q) return;
    setStatus(L10N(lang, 'জায়গা খোঁজা হচ্ছে…', 'Searching place…'));
    try {
      const res = await fetch(`https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(q)}`, {
        headers: { Accept: 'application/json' },
      });
      const rows = (await res.json()) as Array<{ lat: string; lon: string; display_name: string }>;
      if (!rows[0]) throw new Error(L10N(lang, 'জায়গা পাওয়া যায়নি।', 'Place not found.'));
      mapRef.current?.setView([Number(rows[0].lat), Number(rows[0].lon)], 14);
      setStatus(rows[0].display_name);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Search failed');
    }
  };

  return (
    <section aria-label="Global public CCTV" className="soc-panel rounded-xl p-4 sm:p-5 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-50">
              {L10N(lang, 'বিশ্বব্যাপী পাবলিক ক্যামেরা ও CCTV', 'Global public cameras & CCTV')}
            </h2>
          </div>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">
            {L10N(
              lang,
              'ওপেনস্ট্রিটম্যাপে ম্যাপ করা পাবলিক সার্ভেইল্যান্স ও স্ট্রিট ক্যামেরা। ম্যাপ যেখানে নিয়ে যাবেন, সেখানকার ক্যামেরা লোড হবে। কোনো আক্রমণকারী IP সিলেক্ট করলে তার আশেপাশের ক্যামেরাও লোড হবে।',
              'Public surveillance and street cameras mapped in OpenStreetMap. Pan/zoom anywhere to load that area. Select an attacker IP to load cameras around it.',
            )}
          </p>
          <div className="mt-2 flex flex-wrap gap-1 text-[9px] text-slate-400">
            {['NYC DOT', 'TfL JamCams', 'Caltrans (12 districts)', 'OpenStreetMap', 'Operator feeds'].map((source) => (
              <span key={source} className="rounded-full border border-slate-700 bg-slate-900/70 px-2 py-0.5">
                {source}
              </span>
            ))}
          </div>
          <p className="mt-1 text-[9px] text-amber-300/70">
            {L10N(
              lang,
              'শুধু পাবলিক বা অপারেটর-অনুমোদিত স্ট্রিম। বেসরকারি CCTV বা লগইন-প্রোটেক্টেড ক্যামেরা অ্যাক্সেস করা হয় না।',
              'Public or operator-authorised streams only. Private CCTV and login-protected cameras are never accessed.',
            )}
          </p>
          {focus && (
            <div className="mt-1 inline-flex items-center gap-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-[9px] text-cyan-200">
              <MapPin className="h-2.5 w-2.5" />
              {focus.label}
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void search();
            }}
            placeholder={L10N(lang, 'শহর/দেশ খুঁজুন', 'Search city/country')}
            className="w-44 rounded-lg border border-slate-700 bg-[#04060A] px-2 py-1.5 text-[11px] text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <button
            type="button"
            onClick={() => void search()}
            className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-[10px] font-semibold text-cyan-200"
          >
            <Search className="h-3 w-3" /> {L10N(lang, 'খুঁজুন', 'Search')}
          </button>
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-[10px] font-semibold text-slate-300 disabled:opacity-50"
          >
            {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Camera className="h-3 w-3" />}
            {L10N(lang, 'রিফ্রেশ', 'Refresh')}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1">
        {[
          ['Dhaka', 23.8103, 90.4125],
          ['London', 51.5072, -0.1276],
          ['New York', 40.7128, -74.006],
          ['Los Angeles', 34.0522, -118.2437],
          ['San Francisco', 37.7749, -122.4194],
          ['Tokyo', 35.6762, 139.6503],
          ['Dubai', 25.2048, 55.2708],
          ['Singapore', 1.3521, 103.8198],
        ].map(([name, lat, lon]) => (
          <button
            key={String(name)}
            type="button"
            onClick={() => jumpTo(Number(lat), Number(lon))}
            className="rounded-full border border-slate-700 bg-slate-900 px-2 py-0.5 text-[9px] text-slate-300 hover:border-cyan-500/50 hover:text-cyan-200"
          >
            {name}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[320px_1fr]">
        <div className="max-h-[520px] space-y-2 overflow-y-auto rounded-lg border border-slate-800 bg-[#04060A] p-2">
          {status && <div className="rounded border border-cyan-500/20 bg-cyan-500/5 p-2 text-[10px] text-cyan-200">{status}</div>}
          {cameras.length === 0 ? (
            <p className="p-2 text-[10px] text-slate-500">
              {L10N(lang, 'ম্যাপে জুম ইন করুন বা শহরের নাম লিখে খুঁজুন।', 'Zoom into the map or search for a city.')}
            </p>
          ) : (
            cameras.map((camera) => (
              <button
                key={camera.id}
                type="button"
                onClick={() => setSelected(camera)}
                className={`w-full rounded-lg border p-2 text-left transition-colors ${
                  selected?.id === camera.id
                    ? 'border-cyan-500/60 bg-cyan-500/10'
                    : 'border-slate-800 bg-[#02060c] hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-1.5">
                  <Camera className="h-3 w-3 shrink-0 text-cyan-300" />
                  <span className="truncate text-[10px] font-semibold text-slate-200">{camera.name}</span>
                  <span className="ml-auto shrink-0 font-mono text-[8px] text-slate-500">
                    {camera.distanceKm < 1 ? `${Math.round(camera.distanceKm * 1000)} m` : `${camera.distanceKm.toFixed(1)} km`}
                  </span>
                </div>
                <div className="truncate text-[9px] text-slate-500">
                  {[camera.kind, camera.operator, camera.zone].filter(Boolean).join(' · ')}
                </div>
                <div className="mt-0.5 flex items-center gap-2 text-[8px] text-slate-600">
                  <MapPin className="h-2.5 w-2.5" /> {camera.lat.toFixed(4)}, {camera.lon.toFixed(4)}
                  {camera.streamUrl && <span className="text-emerald-400">● live link</span>}
                </div>
              </button>
            ))
          )}
        </div>

        <div className="space-y-2">
          {selected && (
            <div className="rounded-lg border border-slate-800 bg-[#04060A] p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-bold text-slate-100">{selected.name}</span>
                <span className="text-[9px] text-slate-500">{selected.kind}</span>
                <a
                  href={selected.osmUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="ml-auto inline-flex items-center gap-1 text-[9px] text-cyan-300 underline decoration-dotted"
                >
                  <ExternalLink className="h-3 w-3" /> OSM
                </a>
              </div>
              <CameraPreview camera={selected} lang={lang} />
              <p className="text-[9px] text-slate-500">
                {selected.attribution}
                {selected.description ? ` · ${selected.description}` : ''}
              </p>
            </div>
          )}

          <div ref={mapElementRef} className="h-[520px] w-full rounded-lg border border-slate-800" />
        </div>
      </div>
    </section>
  );
}
