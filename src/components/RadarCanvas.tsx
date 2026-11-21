import { Globe, Pause, Play, Radar, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent,
  type PointerEvent,
  type WheelEvent,
} from 'react';
import { WORLD_CONTINENTS } from '../data/worldOutlines';
import type { CyberTranslations } from '../i18n/cyberTranslations';
import type { ThreatNode } from '../types/cyber';

interface RadarCanvasProps {
  t: CyberTranslations;
  nodes: ThreatNode[];
  pinnedNode: ThreatNode | null;
  selectedNodeId: string | null;
  blockedIps: string[];
  onSelectNode: (node: ThreatNode) => void;
  loading: boolean;
}

type RadarProjectionMode = 'globe3d' | 'tactical2d';

const DEG2RAD = Math.PI / 180;

function project2D(
  lon: number,
  lat: number,
  width: number,
  height: number,
  zoom: number,
  panX: number,
  panY: number,
) {
  const baseX = ((lon + 180) / 360) * width;
  const baseY = ((90 - lat) / 180) * height;
  const x = width / 2 + (baseX - width / 2) * zoom + panX;
  const y = height / 2 + (baseY - height / 2) * zoom + panY;
  return { x, y };
}

function project3DOrthographic(
  lonDeg: number,
  latDeg: number,
  centerLonDeg: number,
  centerLatDeg: number,
  cx: number,
  cy: number,
  radius: number,
  altitudeScale = 1,
): { x: number; y: number; z: number; visible: boolean } {
  const lambda = lonDeg * DEG2RAD;
  const phi = latDeg * DEG2RAD;
  const lambda0 = centerLonDeg * DEG2RAD;
  const phi0 = centerLatDeg * DEG2RAD;

  const cosPhi = Math.cos(phi);
  const sinPhi = Math.sin(phi);
  const cosPhi0 = Math.cos(phi0);
  const sinPhi0 = Math.sin(phi0);
  const dLambda = lambda - lambda0;
  const cosD = Math.cos(dLambda);

  const z = sinPhi0 * sinPhi + cosPhi0 * cosPhi * cosD;
  const x = cx + radius * altitudeScale * cosPhi * Math.sin(dLambda);
  const y = cy - radius * altitudeScale * (cosPhi0 * sinPhi - sinPhi0 * cosPhi * cosD);

  return { x, y, z, visible: z >= -0.05 };
}

function slerpLonLat(
  lon1: number,
  lat1: number,
  lon2: number,
  lat2: number,
  t: number,
): [number, number] {
  const p1 = lat1 * DEG2RAD;
  const l1 = lon1 * DEG2RAD;
  const p2 = lat2 * DEG2RAD;
  const l2 = lon2 * DEG2RAD;

  const x1 = Math.cos(p1) * Math.cos(l1);
  const y1 = Math.cos(p1) * Math.sin(l1);
  const z1 = Math.sin(p1);
  const x2 = Math.cos(p2) * Math.cos(l2);
  const y2 = Math.cos(p2) * Math.sin(l2);
  const z2 = Math.sin(p2);

  const dot = Math.max(-1, Math.min(1, x1 * x2 + y1 * y2 + z1 * z2));
  const omega = Math.acos(dot);
  if (omega < 0.001) return [lon1, lat1];
  const sinOmega = Math.sin(omega);
  const s1 = Math.sin((1 - t) * omega) / sinOmega;
  const s2 = Math.sin(t * omega) / sinOmega;

  const x = s1 * x1 + s2 * x2;
  const y = s1 * y1 + s2 * y2;
  const z = s1 * z1 + s2 * z2;

  return [Math.atan2(y, x) / DEG2RAD, Math.atan2(z, Math.hypot(x, y)) / DEG2RAD];
}

export function RadarCanvas({
  t,
  nodes,
  pinnedNode,
  selectedNodeId,
  blockedIps,
  onSelectNode,
  loading,
}: RadarCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [mode, setMode] = useState<RadarProjectionMode>('globe3d');
  const [sweepActive, setSweepActive] = useState(true);
  const [zoom, setZoom] = useState(1);
  const [hoveredNode, setHoveredNode] = useState<ThreatNode | null>(null);

  const combinedNodes = useMemo(() => {
    if (!pinnedNode) return nodes;
    if (nodes.some((n) => n.id === pinnedNode.id || n.ip === pinnedNode.ip)) {
      return nodes.map((n) =>
        n.ip === pinnedNode.ip ? { ...n, ...pinnedNode } : n,
      );
    }
    return [pinnedNode, ...nodes];
  }, [nodes, pinnedNode]);

  const blockedSet = useMemo(() => new Set(blockedIps), [blockedIps]);

  const nodesRef = useRef<ThreatNode[]>(combinedNodes);
  const blockedRef = useRef<Set<string>>(blockedSet);
  const selectedIdRef = useRef<string | null>(selectedNodeId);
  const sweepActiveRef = useRef<boolean>(sweepActive);
  const modeRef = useRef<RadarProjectionMode>(mode);
  const zoomRef = useRef<number>(zoom);
  const angleRef = useRef<number>(0);

  // Camera state for 3D globe & 2D pan
  const globeCamRef = useRef({ lon: 45, lat: 20 });
  const panRef = useRef({ x: 0, y: 0 });
  const dragRef = useRef<{
    active: boolean;
    moved: boolean;
    lastX: number;
    lastY: number;
  }>({ active: false, moved: false, lastX: 0, lastY: 0 });

  // Cache 2D static background only when zoom/pan unchanged
  const bgCacheRef = useRef<{
    canvas: HTMLCanvasElement | null;
    w: number;
    h: number;
    dpr: number;
    zoom: number;
    panX: number;
    panY: number;
  }>({ canvas: null, w: 0, h: 0, dpr: 1, zoom: 1, panX: 0, panY: 0 });

  nodesRef.current = combinedNodes;
  blockedRef.current = blockedSet;
  selectedIdRef.current = selectedNodeId;
  sweepActiveRef.current = sweepActive;
  modeRef.current = mode;
  zoomRef.current = zoom;

  // Smoothly focus 3D globe toward newly locked node
  useEffect(() => {
    if (!selectedNodeId) return;
    const hit = combinedNodes.find((n) => n.id === selectedNodeId);
    if (hit) {
      globeCamRef.current = {
        lon: hit.lon,
        lat: Math.max(-55, Math.min(55, hit.lat)),
      };
    }
  }, [selectedNodeId, combinedNodes]);

  useEffect(() => {
    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      setSweepActive(false);
      sweepActiveRef.current = false;
    }
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let rafId = 0;
    let lastTime = performance.now();
    let lastDraw = 0;

    const ensure2DBackground = (
      width: number,
      height: number,
      dpr: number,
      z: number,
      px: number,
      py: number,
    ) => {
      const c = bgCacheRef.current;
      if (
        c.canvas &&
        c.w === width &&
        c.h === height &&
        c.dpr === dpr &&
        c.zoom === z &&
        c.panX === px &&
        c.panY === py
      ) {
        return c.canvas;
      }
      const bg = c.canvas ?? document.createElement('canvas');
      bg.width = width * dpr;
      bg.height = height * dpr;
      c.canvas = bg;
      c.w = width;
      c.h = height;
      c.dpr = dpr;
      c.zoom = z;
      c.panX = px;
      c.panY = py;

      const bctx = bg.getContext('2d');
      if (!bctx) return bg;
      bctx.setTransform(1, 0, 0, 1, 0, 0);
      bctx.scale(dpr, dpr);

      bctx.fillStyle = '#050911';
      bctx.fillRect(0, 0, width, height);

      // Graticule
      bctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
      bctx.lineWidth = 1;
      for (let lon = -150; lon <= 150; lon += 30) {
        const pt = project2D(lon, 0, width, height, z, px, py);
        bctx.beginPath();
        bctx.moveTo(pt.x, 0);
        bctx.lineTo(pt.x, height);
        bctx.stroke();
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        const pt = project2D(0, lat, width, height, z, px, py);
        bctx.beginPath();
        bctx.moveTo(0, pt.y);
        bctx.lineTo(width, pt.y);
        bctx.stroke();
      }

      // Continents
      bctx.fillStyle = 'rgba(30, 41, 59, 0.62)';
      bctx.strokeStyle = 'rgba(148, 163, 184, 0.28)';
      bctx.lineWidth = 1;
      for (const poly of WORLD_CONTINENTS) {
        bctx.beginPath();
        poly.forEach(([lon, lat], idx) => {
          const pt = project2D(lon, lat, width, height, z, px, py);
          if (idx === 0) bctx.moveTo(pt.x, pt.y);
          else bctx.lineTo(pt.x, pt.y);
        });
        bctx.closePath();
        bctx.fill();
        bctx.stroke();
      }

      // Tactical Radar Compass Rings & Azimuth Ticks
      const cx = width / 2;
      const cy = height / 2;
      const maxRadarR = Math.min(width, height) * 0.46;
      bctx.strokeStyle = 'rgba(16, 185, 129, 0.17)';
      for (const factor of [0.25, 0.5, 0.75, 1]) {
        bctx.beginPath();
        bctx.arc(cx, cy, maxRadarR * factor, 0, Math.PI * 2);
        bctx.stroke();
      }

      bctx.font = '500 9px "JetBrains Mono", monospace';
      bctx.fillStyle = 'rgba(52, 211, 153, 0.5)';
      for (let deg = 0; deg < 360; deg += 30) {
        const rad = (deg - 90) * DEG2RAD;
        const r1 = maxRadarR - 4;
        const r2 = maxRadarR + 4;
        bctx.beginPath();
        bctx.moveTo(cx + Math.cos(rad) * r1, cy + Math.sin(rad) * r1);
        bctx.lineTo(cx + Math.cos(rad) * r2, cy + Math.sin(rad) * r2);
        bctx.stroke();
        if (deg % 90 === 0) {
          const label = `${String(deg).padStart(3, '0')}°`;
          bctx.fillText(
            label,
            cx + Math.cos(rad) * (maxRadarR + 12) - 10,
            cy + Math.sin(rad) * (maxRadarR + 12) + 3,
          );
        }
      }

      return bg;
    };

    const drawNodeMarker = (
      x: number,
      y: number,
      node: ThreatNode,
      isSelected: boolean,
      isBlocked: boolean,
      recentlySwept: number,
      pulsePhase: number,
      dimmed = false,
    ) => {
      const isPinnedSource =
        node.sourceFeed === 'Live Attribution' ||
        node.sourceFeed === 'Photo GPS' ||
        node.sourceFeed === 'Image Embedded IP';
      const isCritical = node.severity === 'CRITICAL';
      const baseAlpha = dimmed ? 0.25 : 1;

      if (!dimmed && (isCritical || isPinnedSource || isBlocked || recentlySwept > 0.2)) {
        const ringR = 5 + pulsePhase * (isCritical || isPinnedSource ? 15 : 10);
        const ringAlpha = (1 - pulsePhase) * (isCritical || isPinnedSource ? 0.65 : 0.38);
        ctx.strokeStyle = isBlocked
          ? `rgba(16, 185, 129, ${ringAlpha.toFixed(2)})`
          : isCritical
            ? `rgba(239, 68, 68, ${ringAlpha.toFixed(2)})`
            : isPinnedSource
              ? `rgba(56, 189, 248, ${ringAlpha.toFixed(2)})`
              : `rgba(249, 115, 22, ${ringAlpha.toFixed(2)})`;
        ctx.lineWidth = 1.3;
        ctx.beginPath();
        ctx.arc(x, y, ringR, 0, Math.PI * 2);
        ctx.stroke();
      }

      ctx.globalAlpha = baseAlpha;
      ctx.fillStyle = isBlocked
        ? '#10B981'
        : isCritical
          ? '#EF4444'
          : isPinnedSource
            ? '#38BDF8'
            : '#F97316';
      ctx.beginPath();
      ctx.arc(x, y, isCritical || isPinnedSource || isBlocked ? 4.6 : 3.3, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = isSelected ? '#FFFFFF' : 'rgba(255,255,255,0.7)';
      ctx.lineWidth = isSelected ? 2 : 0.8;
      ctx.stroke();
      ctx.globalAlpha = 1;

      if (isBlocked && !dimmed) {
        ctx.strokeStyle = 'rgba(16, 185, 129, 0.9)';
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.arc(x, y, 8.5, 0, Math.PI * 2);
        ctx.stroke();
      }

      if (isSelected) {
        ctx.strokeStyle = '#F8FAFC';
        ctx.lineWidth = 1.4;
        const r = 13;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.moveTo(x - r - 5, y);
        ctx.lineTo(x - 5, y);
        ctx.moveTo(x + 5, y);
        ctx.lineTo(x + r + 5, y);
        ctx.moveTo(x, y - r - 5);
        ctx.lineTo(x, y - 5);
        ctx.moveTo(x, y + 5);
        ctx.lineTo(x, y + r + 5);
        ctx.stroke();
      }
    };

    const drawCallout = (
      lockedNode: ThreatNode,
      lockedPt: { x: number; y: number },
      width: number,
      height: number,
      isBlocked: boolean,
    ) => {
      const subject =
        lockedNode.ip.length > 20 ? `${lockedNode.ip.slice(0, 18)}…` : lockedNode.ip;
      const prefix = isBlocked ? 'SHIELDED · ' : '';
      const labelText = `${prefix}${subject} · ${lockedNode.city}, ${lockedNode.countryCode}`;
      ctx.font = '600 11px "JetBrains Mono", monospace';
      const metrics = ctx.measureText(labelText);
      const maxBoxW = Math.min(255, width - 20);
      const boxW = Math.min(maxBoxW, metrics.width + 16);
      const boxH = 22;

      let lx = lockedPt.x + 18;
      if (lx + boxW > width - 8) {
        lx = lockedPt.x - boxW - 18;
      }
      let ly = lockedPt.y - boxH / 2;
      if (lx < 8) {
        lx = Math.max(8, Math.min(width - boxW - 8, lockedPt.x - boxW / 2));
        ly =
          lockedPt.y > boxH + 32
            ? lockedPt.y - boxH - 22
            : Math.min(height - boxH - 8, lockedPt.y + 22);
      } else {
        ly = Math.max(8, Math.min(height - boxH - 8, ly));
      }

      ctx.fillStyle = 'rgba(5, 7, 11, 0.92)';
      ctx.strokeStyle = isBlocked
        ? 'rgba(16, 185, 129, 0.85)'
        : lockedNode.severity === 'CRITICAL'
          ? 'rgba(239, 68, 68, 0.78)'
          : 'rgba(56, 189, 248, 0.78)';
      ctx.lineWidth = 1;
      ctx.fillRect(lx, ly, boxW, boxH);
      ctx.strokeRect(lx, ly, boxW, boxH);

      ctx.fillStyle = '#F8FAFC';
      ctx.fillText(labelText, lx + 8, ly + 15, boxW - 16);
    };

    const drawFrame = (now: number) => {
      rafId = requestAnimationFrame(drawFrame);
      if (now - lastDraw < 38 && lastDraw !== 0) {
        return;
      }
      lastDraw = now;

      const dt = Math.min(0.08, (now - lastTime) / 1000);
      lastTime = now;

      if (sweepActiveRef.current) {
        angleRef.current = (angleRef.current + dt * 0.9) % (Math.PI * 2);
        if (modeRef.current === 'globe3d' && !dragRef.current.active && !selectedIdRef.current) {
          globeCamRef.current.lon = ((globeCamRef.current.lon + dt * 8 + 180) % 360) - 180;
        }
      }

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const rect = canvas.getBoundingClientRect();
      const width = Math.max(320, Math.floor(rect.width));
      const height = Math.max(240, Math.floor(rect.height));

      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }

      const currentNodes = nodesRef.current;
      const selectedId = selectedIdRef.current;
      const blocked = blockedRef.current;
      const pulsePhase = (now / 900) % 1;
      const z = zoomRef.current;
      const cx = width / 2;
      const cy = height / 2;

      if (modeRef.current === 'tactical2d') {
        const bg = ensure2DBackground(width, height, dpr, z, panRef.current.x, panRef.current.y);
        ctx.save();
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.drawImage(bg, 0, 0);
        ctx.scale(dpr, dpr);

        const maxR = Math.hypot(cx, cy);
        const sweepAngle = angleRef.current;
        const wakeSpan = 0.58;
        const steps = 12;
        for (let i = 0; i < steps; i++) {
          const a0 = sweepAngle - ((i + 1) / steps) * wakeSpan;
          const a1 = sweepAngle - (i / steps) * wakeSpan;
          const alpha = (1 - i / steps) * 0.16;
          ctx.fillStyle = `rgba(16, 185, 129, ${alpha.toFixed(3)})`;
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.arc(cx, cy, maxR, a0, a1);
          ctx.closePath();
          ctx.fill();
        }

        ctx.strokeStyle = 'rgba(52, 211, 153, 0.78)';
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(sweepAngle) * maxR, cy + Math.sin(sweepAngle) * maxR);
        ctx.stroke();

        // Great-circle attack trajectories connecting critical nodes
        const hubPt = project2D(90.41, 23.81, width, height, z, panRef.current.x, panRef.current.y);
        ctx.lineWidth = 1;
        for (const node of currentNodes.filter((n) => n.severity === 'CRITICAL').slice(0, 6)) {
          const srcPt = project2D(node.lon, node.lat, width, height, z, panRef.current.x, panRef.current.y);
          ctx.strokeStyle = blocked.has(node.ip)
            ? 'rgba(16, 185, 129, 0.32)'
            : 'rgba(239, 68, 68, 0.28)';
          ctx.beginPath();
          ctx.moveTo(srcPt.x, srcPt.y);
          const midX = (srcPt.x + hubPt.x) / 2;
          const midY = Math.min(srcPt.y, hubPt.y) - 34;
          ctx.quadraticCurveTo(midX, midY, hubPt.x, hubPt.y);
          ctx.stroke();
        }

        let lockedNode: ThreatNode | null = null;
        let lockedPt = { x: 0, y: 0 };

        for (const node of currentNodes) {
          const { x, y } = project2D(node.lon, node.lat, width, height, z, panRef.current.x, panRef.current.y);
          const isSelected = node.id === selectedId;
          if (isSelected) {
            lockedNode = node;
            lockedPt = { x, y };
          }
          const nodeAngle = Math.atan2(y - cy, x - cx);
          let diff = (sweepAngle - nodeAngle) % (Math.PI * 2);
          if (diff < 0) diff += Math.PI * 2;
          const recentlySwept = diff < 0.7 ? 1 - diff / 0.7 : 0;

          drawNodeMarker(
            x,
            y,
            node,
            isSelected,
            blocked.has(node.ip),
            recentlySwept,
            pulsePhase,
          );
        }

        if (lockedNode) {
          drawCallout(lockedNode, lockedPt, width, height, blocked.has(lockedNode.ip));
        }
        ctx.restore();
        return;
      }

      // === MODE 2: REAL 3D ORTHOGRAPHIC GLOBE RADAR ===
      ctx.save();
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      // Deep space background + faint polar radar ring
      ctx.fillStyle = '#050911';
      ctx.fillRect(0, 0, width, height);

      const maxBaseR = Math.max(85, Math.min(width, height) / 2 - 42);
      const globeR = maxBaseR * Math.min(1.65, Math.max(0.75, z));
      const camLon = globeCamRef.current.lon;
      const camLat = globeCamRef.current.lat;

      // Outer tactical bearing ring around 3D globe
      const ringR = globeR + 18;
      ctx.strokeStyle = 'rgba(16, 185, 129, 0.22)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, ringR, 0, Math.PI * 2);
      ctx.stroke();

      ctx.font = '500 9px "JetBrains Mono", monospace';
      ctx.fillStyle = 'rgba(52, 211, 153, 0.58)';
      for (let deg = 0; deg < 360; deg += 30) {
        const rad = (deg - 90) * DEG2RAD;
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(rad) * (ringR - 3), cy + Math.sin(rad) * (ringR - 3));
        ctx.lineTo(cx + Math.cos(rad) * (ringR + 4), cy + Math.sin(rad) * (ringR + 4));
        ctx.stroke();
        if (deg % 90 === 0) {
          ctx.fillText(
            `${String(deg).padStart(3, '0')}°`,
            cx + Math.cos(rad) * (ringR + 12) - 11,
            cy + Math.sin(rad) * (ringR + 12) + 3,
          );
        }
      }

      // Globe sphere fill & atmospheric rim
      const grad = ctx.createRadialGradient(
        cx - globeR * 0.25,
        cy - globeR * 0.25,
        globeR * 0.1,
        cx,
        cy,
        globeR,
      );
      grad.addColorStop(0, '#0D1829');
      grad.addColorStop(0.75, '#070E1A');
      grad.addColorStop(1, '#040810');
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(cx, cy, globeR, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = 'rgba(52, 211, 153, 0.35)';
      ctx.lineWidth = 1.4;
      ctx.stroke();

      // Clip inside globe sphere for graticules, continents, and radar beam
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, globeR, 0, Math.PI * 2);
      ctx.clip();

      // 3D Latitude / Longitude Grid
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.09)';
      ctx.lineWidth = 0.8;
      for (let lon = -150; lon <= 180; lon += 30) {
        ctx.beginPath();
        let started = false;
        for (let lat = -84; lat <= 84; lat += 6) {
          const p = project3DOrthographic(lon, lat, camLon, camLat, cx, cy, globeR);
          if (p.visible) {
            if (!started) {
              ctx.moveTo(p.x, p.y);
              started = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let started = false;
        for (let lon = -180; lon <= 180; lon += 6) {
          const p = project3DOrthographic(lon, lat, camLon, camLat, cx, cy, globeR);
          if (p.visible) {
            if (!started) {
              ctx.moveTo(p.x, p.y);
              started = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // 3D Continents
      ctx.fillStyle = 'rgba(30, 41, 59, 0.72)';
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.34)';
      ctx.lineWidth = 1;
      for (const poly of WORLD_CONTINENTS) {
        const pts = poly.map(([lon, lat]) =>
          project3DOrthographic(lon, lat, camLon, camLat, cx, cy, globeR),
        );
        if (!pts.some((p) => p.z > 0)) continue;
        ctx.beginPath();
        pts.forEach((p, idx) => {
          if (idx === 0) ctx.moveTo(p.x, p.y);
          else ctx.lineTo(p.x, p.y);
        });
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      }

      // 3D Rotating Radar Sweep Sector over Globe
      const sweepAngle = angleRef.current;
      const wakeSpan = 0.55;
      for (let i = 0; i < 10; i++) {
        const a0 = sweepAngle - ((i + 1) / 10) * wakeSpan;
        const a1 = sweepAngle - (i / 10) * wakeSpan;
        ctx.fillStyle = `rgba(16, 185, 129, ${((1 - i / 10) * 0.14).toFixed(3)})`;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, globeR, a0, a1);
        ctx.closePath();
        ctx.fill();
      }
      ctx.strokeStyle = 'rgba(52, 211, 153, 0.78)';
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(sweepAngle) * globeR, cy + Math.sin(sweepAngle) * globeR);
      ctx.stroke();

      // 3D Elevated Great-Circle Attack Arcs
      const anchorNode =
        currentNodes.find((n) => n.id === selectedId) ?? { lon: 90.41, lat: 23.81 };
      for (const node of currentNodes.filter((n) => n.severity === 'CRITICAL').slice(0, 8)) {
        if (node.id === selectedId) continue;
        ctx.strokeStyle = blocked.has(node.ip)
          ? 'rgba(16, 185, 129, 0.45)'
          : 'rgba(239, 68, 68, 0.36)';
        ctx.lineWidth = 1.1;
        ctx.beginPath();
        let started = false;
        for (let step = 0; step <= 16; step++) {
          const frac = step / 16;
          const [lon, lat] = slerpLonLat(node.lon, node.lat, anchorNode.lon, anchorNode.lat, frac);
          const alt = 1 + Math.sin(frac * Math.PI) * 0.14;
          const p = project3DOrthographic(lon, lat, camLon, camLat, cx, cy, globeR, alt);
          if (p.z > -0.08) {
            if (!started) {
              ctx.moveTo(p.x, p.y);
              started = true;
            } else {
              ctx.lineTo(p.x, p.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      ctx.restore(); // end globe clip

      // Plot visible threat nodes on 3D Globe
      let lockedNode: ThreatNode | null = null;
      let lockedPt = { x: 0, y: 0 };

      for (const node of currentNodes) {
        const p = project3DOrthographic(node.lon, node.lat, camLon, camLat, cx, cy, globeR);
        const isSelected = node.id === selectedId;
        if (!p.visible && !isSelected) continue;

        if (isSelected) {
          lockedNode = node;
          lockedPt = { x: p.x, y: p.y };
        }
        const nodeAngle = Math.atan2(p.y - cy, p.x - cx);
        let diff = (sweepAngle - nodeAngle) % (Math.PI * 2);
        if (diff < 0) diff += Math.PI * 2;
        const recentlySwept = diff < 0.7 ? 1 - diff / 0.7 : 0;

        drawNodeMarker(
          p.x,
          p.y,
          node,
          isSelected,
          blocked.has(node.ip),
          recentlySwept,
          pulsePhase,
          !p.visible,
        );
      }

      if (lockedNode) {
        drawCallout(lockedNode, lockedPt, width, height, blocked.has(lockedNode.ip));
      }

      ctx.restore();
    };

    rafId = requestAnimationFrame(drawFrame);
    return () => cancelAnimationFrame(rafId);
  }, []);

  const getHitNode = (clientX: number, clientY: number): ThreatNode | null => {
    const canvas = canvasRef.current;
    if (!canvas || combinedNodes.length === 0) return null;
    const rect = canvas.getBoundingClientRect();
    const mx = clientX - rect.left;
    const my = clientY - rect.top;
    const cx = rect.width / 2;
    const cy = rect.height / 2;

    let best: ThreatNode | null = null;
    let bestDist = 18;

    if (mode === 'tactical2d') {
      for (const node of combinedNodes) {
        const pt = project2D(node.lon, node.lat, rect.width, rect.height, zoom, panRef.current.x, panRef.current.y);
        const d = Math.hypot(pt.x - mx, pt.y - my);
        if (d < bestDist) {
          bestDist = d;
          best = node;
        }
      }
    } else {
      const globeR =
        Math.max(85, Math.min(rect.width, rect.height) / 2 - 42) *
        Math.min(1.65, Math.max(0.75, zoom));
      for (const node of combinedNodes) {
        const p = project3DOrthographic(
          node.lon,
          node.lat,
          globeCamRef.current.lon,
          globeCamRef.current.lat,
          cx,
          cy,
          globeR,
        );
        if (!p.visible) continue;
        const d = Math.hypot(p.x - mx, p.y - my);
        if (d < bestDist) {
          bestDist = d;
          best = node;
        }
      }
    }
    return best;
  };

  const handlePointerDown = (e: PointerEvent<HTMLCanvasElement>) => {
    dragRef.current = { active: true, moved: false, lastX: e.clientX, lastY: e.clientY };
  };

  const handlePointerMove = (e: PointerEvent<HTMLCanvasElement>) => {
    if (dragRef.current.active) {
      const dx = e.clientX - dragRef.current.lastX;
      const dy = e.clientY - dragRef.current.lastY;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragRef.current.moved = true;
      dragRef.current.lastX = e.clientX;
      dragRef.current.lastY = e.clientY;

      if (mode === 'globe3d') {
        globeCamRef.current.lon = ((globeCamRef.current.lon - dx * 0.35 + 180) % 360) - 180;
        globeCamRef.current.lat = Math.max(-75, Math.min(75, globeCamRef.current.lat + dy * 0.3));
      } else {
        panRef.current.x += dx;
        panRef.current.y += dy;
      }
      return;
    }
    setHoveredNode(getHitNode(e.clientX, e.clientY));
  };

  const handlePointerUp = () => {
    dragRef.current.active = false;
  };

  const handleClick = (e: MouseEvent<HTMLCanvasElement>) => {
    if (dragRef.current.moved) return;
    const hit = getHitNode(e.clientX, e.clientY);
    if (hit) onSelectNode(hit);
  };

  const handleWheel = (e: WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.15 : -0.15;
    setZoom((prev) => Number(Math.max(0.8, Math.min(3.5, prev + delta)).toFixed(2)));
  };

  const resetView = () => {
    setZoom(1);
    panRef.current = { x: 0, y: 0 };
    globeCamRef.current = { lon: 45, lat: 20 };
  };

  return (
    <section
      aria-label={t.radarTitle}
      className="soc-panel rounded-xl overflow-hidden flex flex-col justify-between"
    >
      <div className="px-5 py-4 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-slate-50 flex items-center gap-2">
            <Radar className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
            <span>{t.radarTitle}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5 max-w-2xl">{t.radarSubtitle}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* 3D Globe vs 2D Tactical Map Switch */}
          <div
            role="group"
            aria-label="Radar projection mode"
            className="inline-flex items-center p-0.5 rounded-lg bg-[#05070B] border border-slate-800"
          >
            <button
              type="button"
              onClick={() => setMode('globe3d')}
              aria-pressed={mode === 'globe3d'}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                mode === 'globe3d'
                  ? 'bg-emerald-600 text-white'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              <Globe className="w-3 h-3" aria-hidden="true" />
              <span>{t.modeGlobe3d}</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('tactical2d')}
              aria-pressed={mode === 'tactical2d'}
              className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                mode === 'tactical2d'
                  ? 'bg-emerald-600 text-white'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              <Radar className="w-3 h-3" aria-hidden="true" />
              <span>{t.modeTactical2d}</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(3.5, Number((z + 0.3).toFixed(2))))}
            aria-label={t.zoomInBtn}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-200 cursor-pointer"
          >
            <ZoomIn className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.8, Number((z - 0.3).toFixed(2))))}
            aria-label={t.zoomOutBtn}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-200 cursor-pointer"
          >
            <ZoomOut className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
          <button
            type="button"
            onClick={resetView}
            aria-label={t.resetViewBtn}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-200 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
          </button>

          <button
            type="button"
            onClick={() => setSweepActive((prev) => !prev)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-emerald-500/50 text-xs font-medium text-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {sweepActive ? (
              <>
                <Pause className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                <span>{t.pauseSweepBtn}</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                <span>{t.resumeSweepBtn}</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="relative w-full h-[360px] sm:h-[420px] bg-[#050911]">
        <canvas
          ref={canvasRef}
          data-testid="threat-radar-canvas"
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
          onWheel={handleWheel}
          onClick={handleClick}
          onMouseLeave={() => {
            dragRef.current.active = false;
            setHoveredNode(null);
          }}
          className={`w-full h-full block touch-none ${
            hoveredNode ? 'cursor-pointer' : 'cursor-grab active:cursor-grabbing'
          }`}
        />

        {hoveredNode && (
          <div className="pointer-events-none absolute top-3 left-3 px-3 py-2 rounded-lg bg-slate-950/90 border border-red-500/40 text-xs space-y-0.5 max-w-[280px]">
            <div className="font-mono font-semibold text-red-400">
              {hoveredNode.ip}
              {hoveredNode.port ? `:${hoveredNode.port}` : ''}
            </div>
            <div className="text-slate-200">
              {hoveredNode.city}, {hoveredNode.country}
            </div>
            {hoveredNode.physicalAddress && (
              <div className="text-slate-400 line-clamp-2">{hoveredNode.physicalAddress}</div>
            )}
          </div>
        )}

        {loading && combinedNodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center bg-slate-950/60 text-xs text-slate-300 font-mono">
            {t.scanningNow}
          </div>
        )}
      </div>

      <div className="px-5 py-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-4">
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[2px] bg-red-500 inline-block" aria-hidden="true" />
            <span className="text-red-300">{t.legendCritical}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[2px] bg-orange-500 inline-block" aria-hidden="true" />
            <span>{t.legendHigh}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[2px] bg-sky-400 inline-block" aria-hidden="true" />
            <span className="text-sky-300">{t.legendPinned}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[2px] bg-emerald-500 inline-block" aria-hidden="true" />
            <span className="text-emerald-300">{t.legendDefended}</span>
          </span>
          <span className="inline-flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-[2px] border border-white inline-block" aria-hidden="true" />
            <span>{t.legendSelected}</span>
          </span>
        </div>

        <div className="font-mono tabular-nums text-slate-300">
          {combinedNodes.length} {t.geoNodesLabel}
        </div>
      </div>
    </section>
  );
}
