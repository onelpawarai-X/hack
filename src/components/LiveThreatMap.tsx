import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Crosshair, Flame, Globe2, Maximize2, Radar, ZoomIn, ZoomOut } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { LabTranslations } from '../i18n/labTranslations';
import type { TargetScanResult, ThreatNode, ThreatSeverity } from '../types/cyber';
import type { ScanGeoPayload, ScannerOrigin } from '../types/realtime';
import { ThreatGlobe3D } from './ThreatGlobe3D';

interface LiveThreatMapProps {
  t: LabTranslations;
  nodes: ThreatNode[];
  scanResult: TargetScanResult | null;
  scanGeo: ScanGeoPayload | null;
  scannerOrigin: ScannerOrigin | null;
  selectedNodeId: string | null;
  blockedIps: string[];
  scanning: boolean;
  loading: boolean;
  onSelectNode: (node: ThreatNode) => void;
}

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  ELEVATED: '#eab308',
  CLEAN: '#10b981',
};

const SEVERITY_HEAT_RADIUS: Record<ThreatSeverity, number> = {
  CRITICAL: 70000,
  HIGH: 50000,
  ELEVATED: 35000,
  CLEAN: 22000,
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function nodeIcon(color: string, selected: boolean, pulse: boolean, blocked: boolean): L.DivIcon {
  const classes = [
    'sg-map-marker',
    pulse ? 'sg-map-marker--pulse' : '',
    selected ? 'sg-map-marker--selected' : '',
    blocked ? 'sg-map-marker--blocked' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return L.divIcon({
    className: 'sg-map-marker-host',
    html: `<div class="${classes}" style="--sg-color:${color}"><span class="sg-map-ring"></span><span class="sg-map-dot"></span></div>`,
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
}

function scannerIcon(): L.DivIcon {
  return L.divIcon({
    className: 'sg-map-marker-host',
    html: `<div class="sg-scanner-marker"><span class="sg-scanner-ring"></span><span class="sg-scanner-core"></span></div>`,
    iconSize: [26, 26],
    iconAnchor: [13, 13],
  });
}

function popupHtml(node: ThreatNode): string {
  return `
    <div class="sg-popup">
      <div class="sg-popup-title">${escapeHtml(node.threatType || 'Network host')}</div>
      <div class="sg-popup-row"><span>IP</span><b>${escapeHtml(node.ip)}</b></div>
      <div class="sg-popup-row"><span>Location</span><b>${escapeHtml(node.city || 'Unknown')}, ${escapeHtml(node.country || 'Unknown')}</b></div>
      <div class="sg-popup-row"><span>ASN</span><b>${escapeHtml(node.asn || 'Unknown')}</b></div>
      <div class="sg-popup-row"><span>ISP</span><b>${escapeHtml(node.isp || 'Unknown')}</b></div>
      <div class="sg-popup-row"><span>Feed</span><b>${escapeHtml(node.sourceFeed)}</b></div>
      <div class="sg-popup-row"><span>Severity</span><b style="color:${SEVERITY_COLORS[node.severity]}">${node.severity}</b></div>
    </div>`;
}

export function LiveThreatMap({
  t,
  nodes,
  scanResult,
  scanGeo,
  scannerOrigin,
  selectedNodeId,
  blockedIps,
  scanning,
  loading,
  onSelectNode,
}: LiveThreatMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const tileRef = useRef<L.TileLayer | null>(null);
  const heatGroupRef = useRef<L.LayerGroup | null>(null);
  const threatGroupRef = useRef<L.LayerGroup | null>(null);
  const scanGroupRef = useRef<L.LayerGroup | null>(null);
  const linkGroupRef = useRef<L.LayerGroup | null>(null);
  const didInitialFitRef = useRef(false);
  const lastFocusedTargetRef = useRef<string | null>(null);
  const [heatEnabled, setHeatEnabled] = useState(true);
  const [view3d, setView3d] = useState(false);

  const blockedSet = useMemo(() => new Set(blockedIps), [blockedIps]);

  const attributionNodes = useMemo(() => {
    const merged = [...nodes];
    for (const node of scanResult?.attribution ?? []) {
      if (!merged.some((item) => item.ip === node.ip)) merged.push(node);
    }
    return merged;
  }, [nodes, scanResult]);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const map = L.map(containerRef.current, {
      center: [22, 30],
      zoom: 3,
      minZoom: 2,
      maxZoom: 16,
      zoomControl: false,
      attributionControl: true,
      worldCopyJump: true,
    });
    mapRef.current = map;

    tileRef.current = L.tileLayer(
      'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
      {
        attribution:
          'Tiles &copy; <a href="https://www.esri.com/">Esri</a> &mdash; Esri, DeLorme, NAVTEQ',
        maxZoom: 16,
      },
    ).addTo(map);

    heatGroupRef.current = L.layerGroup().addTo(map);
    linkGroupRef.current = L.layerGroup().addTo(map);
    threatGroupRef.current = L.layerGroup().addTo(map);
    scanGroupRef.current = L.layerGroup().addTo(map);

    const handleResize = () => map.invalidateSize();
    window.addEventListener('resize', handleResize);
    const timer = setTimeout(handleResize, 250);

    return () => {
      clearTimeout(timer);
      window.removeEventListener('resize', handleResize);
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const heatGroup = heatGroupRef.current;
    if (!map || !heatGroup) return;
    heatGroup.clearLayers();
    if (!heatEnabled) return;

    for (const node of attributionNodes) {
      if (!Number.isFinite(node.lat) || !Number.isFinite(node.lon)) continue;
      if (node.lat === 0 && node.lon === 0) continue;
      L.circle([node.lat, node.lon], {
        radius: SEVERITY_HEAT_RADIUS[node.severity],
        stroke: false,
        fillColor: SEVERITY_COLORS[node.severity],
        fillOpacity: node.severity === 'CRITICAL' ? 0.16 : 0.1,
      }).addTo(heatGroup);
    }
  }, [attributionNodes, heatEnabled]);

  useEffect(() => {
    const map = mapRef.current;
    const threatGroup = threatGroupRef.current;
    if (!map || !threatGroup) return;
    threatGroup.clearLayers();

    for (const node of attributionNodes) {
      if (!Number.isFinite(node.lat) || !Number.isFinite(node.lon)) continue;
      if (node.lat === 0 && node.lon === 0) continue;
      const isSelected = node.id === selectedNodeId;
      const marker = L.marker([node.lat, node.lon], {
        icon: nodeIcon(
          SEVERITY_COLORS[node.severity],
          isSelected,
          node.severity === 'CRITICAL',
          blockedSet.has(node.ip),
        ),
        title: `${node.ip} · ${node.threatType}`,
        zIndexOffset: isSelected ? 1000 : node.severity === 'CRITICAL' ? 500 : 0,
      });
      marker.bindPopup(popupHtml(node), { closeButton: true, maxWidth: 300 });
      marker.on('click', () => onSelectNode(node));
      marker.addTo(threatGroup);
    }
  }, [attributionNodes, selectedNodeId, blockedSet, onSelectNode]);

  useEffect(() => {
    const map = mapRef.current;
    const scanGroup = scanGroupRef.current;
    const linkGroup = linkGroupRef.current;
    if (!map || !scanGroup || !linkGroup) return;
    scanGroup.clearLayers();
    linkGroup.clearLayers();

    const points = scanGeo?.points ?? [];

    for (const point of points) {
      if (!Number.isFinite(point.lat) || !Number.isFinite(point.lon)) continue;
      const matching = attributionNodes.find((node) => node.ip === point.ip);
      const marker = L.marker([point.lat, point.lon], {
        icon: L.divIcon({
          className: 'sg-map-marker-host',
          html: `<div class="sg-target-marker" style="--sg-color:${SEVERITY_COLORS[point.severity]}"><span class="sg-target-ring"></span><span class="sg-target-ring sg-target-ring--delay"></span><span class="sg-target-core"></span></div>`,
          iconSize: [46, 46],
          iconAnchor: [23, 23],
        }),
        zIndexOffset: 1200,
      });
      const title = matching
        ? popupHtml(matching)
        : `<div class="sg-popup"><div class="sg-popup-title">${escapeHtml(point.label)}</div><div class="sg-popup-row"><span>IP</span><b>${escapeHtml(point.ip)}</b></div><div class="sg-popup-row"><span>Role</span><b>${escapeHtml(point.role)}</b></div></div>`;
      marker.bindPopup(title, { maxWidth: 300 });
      marker.on('click', () => {
        if (matching) onSelectNode(matching);
      });
      marker.addTo(scanGroup);

      if (scannerOrigin && Number.isFinite(scannerOrigin.lat)) {
        L.polyline(
          [
            [scannerOrigin.lat, scannerOrigin.lon],
            [point.lat, point.lon],
          ],
          {
            color: '#22d3ee',
            weight: 1.6,
            opacity: 0.8,
            dashArray: '6 8',
            className: 'sg-attack-line',
          },
        ).addTo(linkGroup);
      }
    }

    if (scannerOrigin && Number.isFinite(scannerOrigin.lat)) {
      const originMarker = L.marker([scannerOrigin.lat, scannerOrigin.lon], {
        icon: scannerIcon(),
        title: `${t.mapScannerOrigin}: ${scannerOrigin.ip}`,
        zIndexOffset: 1500,
      });
      originMarker.bindPopup(
        `<div class="sg-popup"><div class="sg-popup-title">${escapeHtml(t.mapScannerOrigin)}</div><div class="sg-popup-row"><span>IP</span><b>${escapeHtml(scannerOrigin.ip)}</b></div><div class="sg-popup-row"><span>Location</span><b>${escapeHtml(scannerOrigin.city || 'Unknown')}, ${escapeHtml(scannerOrigin.country || 'Unknown')}</b></div><div class="sg-popup-row"><span>ASN</span><b>${escapeHtml(scannerOrigin.asn || 'Unknown')}</b></div></div>`,
        { maxWidth: 300 },
      );
      originMarker.addTo(scanGroup);
    }
  }, [scanGeo, scannerOrigin, attributionNodes, onSelectNode, t.mapScannerOrigin]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || didInitialFitRef.current) return;
    const points: Array<[number, number]> = [];
    for (const node of attributionNodes.slice(0, 60)) {
      if (node.lat === 0 && node.lon === 0) continue;
      points.push([node.lat, node.lon]);
    }
    if (points.length > 0) {
      map.fitBounds(L.latLngBounds(points).pad(0.25), { maxZoom: 3, animate: false });
      didInitialFitRef.current = true;
    }
  }, [attributionNodes]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !scanGeo || scanGeo.points.length === 0) return;
    if (lastFocusedTargetRef.current === scanGeo.target) return;
    lastFocusedTargetRef.current = scanGeo.target;

    const points: Array<[number, number]> = scanGeo.points.map((point) => [point.lat, point.lon]);
    if (scannerOrigin && Number.isFinite(scannerOrigin.lat)) {
      points.push([scannerOrigin.lat, scannerOrigin.lon]);
    }
    map.fitBounds(L.latLngBounds(points).pad(0.6), { maxZoom: 7 });
  }, [scanGeo, scannerOrigin]);

  const focusScan = () => {
    const map = mapRef.current;
    if (!map) return;
    const points: Array<[number, number]> = [];
    for (const point of scanGeo?.points ?? []) points.push([point.lat, point.lon]);
    if (scannerOrigin) points.push([scannerOrigin.lat, scannerOrigin.lon]);
    if (points.length === 0) return;
    map.fitBounds(L.latLngBounds(points).pad(0.5), { maxZoom: 7 });
  };

  const resetView = () => {
    const map = mapRef.current;
    if (!map) return;
    const points: Array<[number, number]> = [];
    for (const node of attributionNodes.slice(0, 80)) {
      if (node.lat === 0 && node.lon === 0) continue;
      points.push([node.lat, node.lon]);
    }
    if (points.length > 0) {
      map.fitBounds(L.latLngBounds(points).pad(0.25), { maxZoom: 3 });
    } else {
      map.setView([22, 30], 3);
    }
  };

  return (
    <section aria-label={t.mapTitle} className="soc-panel rounded-xl overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2">
            <Radar className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            <h2 className="text-base font-bold text-slate-50">{t.mapTitle}</h2>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[10px] font-semibold text-emerald-300">
              <span className={`w-1.5 h-1.5 rounded-full bg-emerald-400 ${scanning ? 'animate-ping' : ''}`} />
              {t.mapLiveBadge}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">{t.mapSubtitle}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setView3d((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold transition-colors cursor-pointer ${
              view3d
                ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200'
                : 'bg-[#06090F] border-slate-700 text-slate-300 hover:border-slate-500'
            }`}
            aria-pressed={view3d}
          >
            <Globe2 className="w-3.5 h-3.5" aria-hidden="true" />
            {view3d ? '3D' : '3D'}
          </button>
          <button
            type="button"
            onClick={() => setHeatEnabled((prev) => !prev)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold transition-colors cursor-pointer ${
              heatEnabled
                ? 'bg-orange-500/15 border-orange-500/40 text-orange-200'
                : 'bg-[#06090F] border-slate-700 text-slate-300 hover:border-slate-500'
            }`}
            aria-pressed={heatEnabled}
          >
            <Flame className="w-3.5 h-3.5" aria-hidden="true" />
            {heatEnabled ? t.mapHeatOn : t.mapHeatOff}
          </button>
          <button
            type="button"
            onClick={focusScan}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/40 text-cyan-200 text-[11px] font-semibold hover:bg-cyan-500/20 transition-colors cursor-pointer"
          >
            <Crosshair className="w-3.5 h-3.5" aria-hidden="true" />
            {t.mapFocusScan}
          </button>
          <button
            type="button"
            onClick={resetView}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#06090F] border border-slate-700 text-slate-300 text-[11px] font-semibold hover:border-slate-500 transition-colors cursor-pointer"
          >
            <Maximize2 className="w-3.5 h-3.5" aria-hidden="true" />
            {t.mapResetView}
          </button>
        </div>
      </div>

      <div className="relative">
        <div ref={containerRef} className="h-[460px] w-full bg-[#06090F]" role="application" aria-label={t.mapTitle} />

        <div className="absolute top-3 right-3 z-[1000] flex flex-col gap-1.5">
          <button
            type="button"
            aria-label="Zoom in"
            onClick={() => mapRef.current?.zoomIn()}
            className="w-8 h-8 grid place-items-center rounded-md bg-[#0B101B]/95 border border-slate-700 text-slate-200 hover:border-cyan-500/60 transition-colors cursor-pointer"
          >
            <ZoomIn className="w-4 h-4" aria-hidden="true" />
          </button>
          <button
            type="button"
            aria-label="Zoom out"
            onClick={() => mapRef.current?.zoomOut()}
            className="w-8 h-8 grid place-items-center rounded-md bg-[#0B101B]/95 border border-slate-700 text-slate-200 hover:border-cyan-500/60 transition-colors cursor-pointer"
          >
            <ZoomOut className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        <div className="absolute bottom-3 left-3 z-[1000] rounded-lg bg-[#0B101B]/95 border border-slate-700 px-3 py-2 text-[10px] text-slate-300 space-y-1">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" /> {t.mapLegendCritical}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500" /> {t.mapLegendHigh}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> {t.mapLegendClean}
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> {t.mapLegendScanner}
            </span>
          </div>
          <div className="text-slate-400">
            {attributionNodes.length} {t.mapNodesLabel} · {scanGeo?.points.length ?? 0} {t.mapScanPointsLabel}
          </div>
        </div>

        <div className="absolute top-3 left-3 z-[1000] max-w-[70%] rounded-lg bg-[#0B101B]/95 border border-slate-700 px-3 py-2 text-[10px] text-slate-300">
          {scannerOrigin ? (
            <span>
              <b className="text-cyan-300">{t.mapScannerOrigin}:</b> {scannerOrigin.ip} ·{' '}
              {scannerOrigin.city || 'Unknown'}, {scannerOrigin.country || 'Unknown'}
            </span>
          ) : (
            <span className="text-amber-300">{t.mapOriginUnknown}</span>
          )}
        </div>

        {view3d && (
          <div className="absolute inset-0 z-[1200] bg-[#02060c]">
            <ThreatGlobe3D
              nodes={attributionNodes}
              scannerOrigin={scannerOrigin}
              onSelectNode={onSelectNode}
            />
          </div>
        )}

        {loading && (
          <div className="absolute inset-0 z-[1300] grid place-items-center bg-[#06090F]/70 backdrop-blur-sm text-xs text-slate-300">
            {t.mapLoading}
          </div>
        )}
      </div>
    </section>
  );
}
