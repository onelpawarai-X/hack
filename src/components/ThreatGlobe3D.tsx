import { useEffect, useMemo, useRef, useState } from 'react';
import Globe, { type GlobeMethods } from 'react-globe.gl';
import * as THREE from 'three';
import { feature } from 'topojson-client';
import countriesTopology from 'world-atlas/countries-110m.json';
import type { ThreatNode, ThreatSeverity } from '../types/cyber';
import type { ScannerOrigin } from '../types/realtime';

interface ThreatGlobe3DProps {
  nodes: ThreatNode[];
  scannerOrigin: ScannerOrigin | null;
  onSelectNode: (node: ThreatNode) => void;
}

const COLORS: Record<ThreatSeverity, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  ELEVATED: '#eab308',
  CLEAN: '#10b981',
};

const countryFeatures = feature(
  countriesTopology as never,
  (countriesTopology as unknown as { objects: { countries: unknown } }).objects.countries as never,
) as unknown as { features: Array<Record<string, unknown>> };

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    };
    return map[char] ?? char;
  });
}

export function ThreatGlobe3D({ nodes, scannerOrigin, onSelectNode }: ThreatGlobe3DProps) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ width: 900, height: 520 });

  useEffect(() => {
    const update = () => {
      const rect = containerRef.current?.getBoundingClientRect();
      if (rect) setSize({ width: Math.max(320, rect.width), height: Math.max(360, rect.height) });
    };
    update();
    window.addEventListener('resize', update);
    return () => window.removeEventListener('resize', update);
  }, []);

  const globeMaterial = useMemo(
    () =>
      new THREE.MeshPhongMaterial({
        color: '#071a2a',
        emissive: '#03111c',
        emissiveIntensity: 0.8,
        shininess: 8,
        transparent: true,
        opacity: 0.96,
      }),
    [],
  );

  const points = useMemo(
    () =>
      nodes
        .filter((node) => Number.isFinite(node.lat) && Number.isFinite(node.lon))
        .map((node) => ({ ...node })),
    [nodes],
  );

  const arcs = useMemo(() => {
    if (!scannerOrigin) return [];
    return points.map((node) => ({
      startLat: scannerOrigin.lat,
      startLng: scannerOrigin.lon,
      endLat: node.lat,
      endLng: node.lon,
      color: [COLORS[node.severity], 'rgba(34,211,238,0.15)'],
      node,
    }));
  }, [points, scannerOrigin]);

  useEffect(() => {
    const controls = globeRef.current?.controls();
    if (!controls) return;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.35;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
  }, []);

  return (
    <div ref={containerRef} className="relative h-full min-h-[420px] w-full overflow-hidden rounded-xl border border-cyan-500/20 bg-[#02060c]">
      <Globe
        ref={globeRef}
        width={size.width}
        height={size.height}
        backgroundColor="#02060c"
        globeMaterial={globeMaterial}
        showAtmosphere
        atmosphereColor="#22d3ee"
        atmosphereAltitude={0.18}
        polygonsData={countryFeatures.features}
        polygonCapColor={() => 'rgba(8,145,178,0.16)'}
        polygonSideColor={() => 'rgba(8,145,178,0.05)'}
        polygonStrokeColor={() => 'rgba(34,211,238,0.55)'}
        polygonAltitude={0.006}
        arcsData={arcs}
        arcStartLat="startLat"
        arcStartLng="startLng"
        arcEndLat="endLat"
        arcEndLng="endLng"
        arcColor="color"
        arcAltitudeAutoScale={0.35}
        arcStroke={0.5}
        arcDashLength={0.45}
        arcDashGap={0.25}
        arcDashAnimateTime={2200}
        pointsData={points}
        pointLat="lat"
        pointLng="lon"
        pointColor={(point) => COLORS[(point as ThreatNode).severity]}
        pointAltitude={0.035}
        pointRadius={0.28}
        pointLabel={(point) => {
          const node = point as ThreatNode;
          return `<div style="font-family:ui-monospace,monospace;font-size:11px;color:#e2e8f0;background:#02060c;border:1px solid #164e63;padding:8px;border-radius:6px;line-height:1.5">
            <b style="color:${COLORS[node.severity]}">${escapeHtml(node.severity)}</b> · ${escapeHtml(node.ip)}<br/>
            ${escapeHtml(node.city || 'Unknown')}, ${escapeHtml(node.country || 'Unknown')}<br/>
            ${escapeHtml(node.asn || 'Unknown ASN')} · ${escapeHtml(node.isp || 'Unknown ISP')}
          </div>`;
        }}
        onPointClick={(point) => onSelectNode(point as ThreatNode)}
        ringsData={points.filter((node) => node.severity === 'CRITICAL' || node.severity === 'HIGH')}
        ringLat="lat"
        ringLng="lon"
        ringColor={(ring: object) => COLORS[(ring as ThreatNode).severity]}
        ringMaxRadius={3.2}
        ringPropagationSpeed={1.2}
        ringRepeatPeriod={1400}
      />
      <div className="pointer-events-none absolute bottom-2 left-3 text-[9px] text-slate-500">
        Offline 3D globe · Natural Earth geometry · no tile/API dependency
      </div>
    </div>
  );
}
