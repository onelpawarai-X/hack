import { XMLParser } from 'fast-xml-parser';

export interface OsmSurveillanceCamera {
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
  protocol?: 'hls' | 'mjpeg' | 'iframe' | 'link' | 'image';
  source: 'OpenStreetMap';
  attribution: string;
}

export interface OsmSurveillanceResult {
  ok: boolean;
  source: 'OpenStreetMap';
  bbox: { south: number; west: number; north: number; east: number };
  fetchedAt: string;
  cameras: OsmSurveillanceCamera[];
  error?: string;
}

const OSM_MAP_URL = 'https://api.openstreetmap.org/api/0.6/map';
const CACHE_TTL_MS = 10 * 60 * 1000;
const MAX_RADIUS_KM = 0.5;
const MAX_RESULTS = 200;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseAttributeValue: false,
  parseTagValue: false,
  trimValues: true,
});

const cache = new Map<string, { expiresAt: number; value: OsmSurveillanceResult }>();

function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function tagsOf(node: Record<string, unknown>): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const tag of asArray(node.tag as Record<string, unknown> | Record<string, unknown>[] | undefined)) {
    const key = String(tag['@_k'] ?? '');
    if (key) tags[key] = String(tag['@_v'] ?? '');
  }
  return tags;
}

function isSurveillance(tags: Record<string, string>): boolean {
  return (
    tags['man_made'] === 'surveillance' ||
    tags.highway === 'speed_camera' ||
    Boolean(tags.surveillance) ||
    Boolean(tags['camera:type'])
  );
}

function isPublicSurveillance(tags: Record<string, string>): boolean {
  if (tags['camera:type'] === 'doorbell' || tags['surveillance:type'] === 'doorbell') return false;
  if (tags.access === 'private' || tags.access === 'no') return false;
  if (['residence', 'private', 'residential'].includes(tags['surveillance:zone'] ?? '')) return false;
  if (tags.surveillance === 'indoor' || tags['surveillance:type'] === 'indoor') return false;
  const label = [tags.name, tags.operator, tags.description].filter(Boolean).join(' ');
  if (/doorbell|klingel|video.?ring|residential/i.test(label)) return false;
  return true;
}

function normalizeStreamUrl(url?: string): string | undefined {
  if (!url) return undefined;
  const youtube =
    url.match(/youtube\.com\/watch\?v=([A-Za-z0-9_-]{6,})/i) ??
    url.match(/youtu\.be\/([A-Za-z0-9_-]{6,})/i);
  return youtube ? `https://www.youtube.com/embed/${youtube[1]}` : url;
}

function streamProtocol(url: string): 'hls' | 'mjpeg' | 'iframe' | 'link' | 'image' {
  if (/\.m3u8($|\?)/i.test(url)) return 'hls';
  if (/mjpe?g|\.mjpg($|\?)|action=stream/i.test(url)) return 'mjpeg';
  if (/embed|iframe|youtube\.com\/embed|player\./i.test(url)) return 'iframe';
  return 'link';
}

function distanceKm(aLat: number, aLon: number, bLat: number, bLon: number): number {
  const radius = 6371;
  const toRad = (value: number) => (value * Math.PI) / 180;
  const dLat = toRad(bLat - aLat);
  const dLon = toRad(bLon - aLon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2;
  return 2 * radius * Math.asin(Math.sqrt(h));
}

function buildCamera(
  id: string,
  lat: number,
  lon: number,
  tags: Record<string, string>,
  originLat: number,
  originLon: number,
): OsmSurveillanceCamera | null {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || !isSurveillance(tags) || !isPublicSurveillance(tags)) {
    return null;
  }
  const streamUrl = normalizeStreamUrl(
    tags['contact:webcam'] || tags.webcam || tags.url || tags.website || tags.image,
  );
  const kind =
    tags['surveillance:type'] ||
    tags['camera:type'] ||
    tags.surveillance ||
    (tags.highway === 'speed_camera' ? 'speed camera' : 'surveillance');
  return {
    id,
    name: tags.name || tags.operator || tags.ref || `Public ${kind}`,
    lat,
    lon,
    distanceKm: Number(distanceKm(originLat, originLon, lat, lon).toFixed(3)),
    kind,
    operator: tags.operator,
    zone: tags['surveillance:zone'],
    mount: tags['camera:mount'],
    direction: tags['camera:direction'] || tags.direction,
    description: tags.description || tags.note,
    osmUrl: `https://www.openstreetmap.org/${id}`,
    streamUrl,
    protocol: streamUrl ? streamProtocol(streamUrl) : undefined,
    source: 'OpenStreetMap',
    attribution: '© OpenStreetMap contributors, ODbL',
  };
}

export function parseOsmMapXml(
  xml: string,
  originLat: number,
  originLon: number,
  radiusKm: number,
): OsmSurveillanceCamera[] {
  const parsed = parser.parse(xml) as { osm?: Record<string, unknown> };
  const osm = parsed.osm ?? {};
  const nodes = asArray(osm.node as Record<string, unknown> | Record<string, unknown>[]);
  const ways = asArray(osm.way as Record<string, unknown> | Record<string, unknown>[]);

  const nodeIndex = new Map<string, { lat: number; lon: number; tags: Record<string, string> }>();
  for (const node of nodes) {
    const id = String(node['@_id'] ?? '');
    const nodeLat = Number(node['@_lat']);
    const nodeLon = Number(node['@_lon']);
    if (id && Number.isFinite(nodeLat) && Number.isFinite(nodeLon)) {
      nodeIndex.set(id, { lat: nodeLat, lon: nodeLon, tags: tagsOf(node) });
    }
  }

  const cameras: OsmSurveillanceCamera[] = [];
  for (const [id, node] of nodeIndex) {
    const camera = buildCamera(`node/${id}`, node.lat, node.lon, node.tags, originLat, originLon);
    if (camera) cameras.push(camera);
  }

  for (const way of ways) {
    const tags = tagsOf(way);
    if (!isSurveillance(tags) || !isPublicSurveillance(tags)) continue;
    const refs = asArray(way.nd as Record<string, unknown> | Record<string, unknown>[])
      .map((nd) => nodeIndex.get(String(nd['@_ref'] ?? '')))
      .filter((node): node is { lat: number; lon: number; tags: Record<string, string> } => Boolean(node));
    if (refs.length === 0) continue;
    const centerLat = refs.reduce((sum, node) => sum + node.lat, 0) / refs.length;
    const centerLon = refs.reduce((sum, node) => sum + node.lon, 0) / refs.length;
    const camera = buildCamera(`way/${String(way['@_id'] ?? '')}`, centerLat, centerLon, tags, originLat, originLon);
    if (camera) cameras.push(camera);
  }

  return cameras
    .filter((camera) => camera.distanceKm <= radiusKm)
    .sort((a, b) => a.distanceKm - b.distanceKm)
    .slice(0, MAX_RESULTS);
}

export function parseOsmMapXmlBbox(
  xml: string,
  centerLat: number,
  centerLon: number,
  limit = 500,
): OsmSurveillanceCamera[] {
  const parsed = parser.parse(xml) as { osm?: Record<string, unknown> };
  const osm = parsed.osm ?? {};
  const nodes = asArray(osm.node as Record<string, unknown> | Record<string, unknown>[]);
  const ways = asArray(osm.way as Record<string, unknown> | Record<string, unknown>[]);
  const nodeIndex = new Map<string, { lat: number; lon: number; tags: Record<string, string> }>();
  for (const node of nodes) {
    const id = String(node['@_id'] ?? '');
    const nodeLat = Number(node['@_lat']);
    const nodeLon = Number(node['@_lon']);
    if (id && Number.isFinite(nodeLat) && Number.isFinite(nodeLon)) {
      nodeIndex.set(id, { lat: nodeLat, lon: nodeLon, tags: tagsOf(node) });
    }
  }
  const cameras: OsmSurveillanceCamera[] = [];
  for (const [id, node] of nodeIndex) {
    const camera = buildCamera(`node/${id}`, node.lat, node.lon, node.tags, centerLat, centerLon);
    if (camera) cameras.push(camera);
  }
  for (const way of ways) {
    const tags = tagsOf(way);
    if (!isSurveillance(tags) || !isPublicSurveillance(tags)) continue;
    const refs = asArray(way.nd as Record<string, unknown> | Record<string, unknown>[])
      .map((nd) => nodeIndex.get(String(nd['@_ref'] ?? '')))
      .filter((node): node is { lat: number; lon: number; tags: Record<string, string> } => Boolean(node));
    if (refs.length === 0) continue;
    const center = {
      lat: refs.reduce((sum, node) => sum + node.lat, 0) / refs.length,
      lon: refs.reduce((sum, node) => sum + node.lon, 0) / refs.length,
    };
    const camera = buildCamera(`way/${String(way['@_id'] ?? '')}`, center.lat, center.lon, tags, centerLat, centerLon);
    if (camera) cameras.push(camera);
  }
  return cameras.sort((a, b) => a.distanceKm - b.distanceKm).slice(0, limit);
}

export async function findOsmSurveillanceBbox(
  south: number,
  west: number,
  north: number,
  east: number,
): Promise<OsmSurveillanceResult> {
  const bbox = { south, west, north, east };
  if (![south, west, north, east].every(Number.isFinite)) {
    return { ok: false, source: 'OpenStreetMap', bbox, fetchedAt: new Date().toISOString(), cameras: [], error: 'Invalid bounding box.' };
  }
  const area = Math.abs((north - south) * (east - west));
  if (area > 0.08) {
    return {
      ok: false,
      source: 'OpenStreetMap',
      bbox,
      fetchedAt: new Date().toISOString(),
      cameras: [],
      error: 'Zoom in: the viewport is too large for a live OpenStreetMap camera query.',
    };
  }
  const cacheKey = `bbox:${south.toFixed(3)},${west.toFixed(3)},${north.toFixed(3)},${east.toFixed(3)}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  try {
    const url = `${OSM_MAP_URL}?bbox=${west},${south},${east},${north}`;
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'SentinelGlobe/1.0 (public surveillance research; contact: security@localhost)',
        Accept: 'application/xml,text/xml',
      },
      signal: AbortSignal.timeout(25_000),
    });
    const base = { source: 'OpenStreetMap' as const, bbox, fetchedAt: new Date().toISOString() };
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      return { ...base, ok: false, cameras: [], error: `OpenStreetMap returned HTTP ${response.status}${body ? `: ${body.slice(0, 160)}` : '.'}` };
    }
    const xml = await response.text();
    const result: OsmSurveillanceResult = {
      ...base,
      ok: true,
      cameras: parseOsmMapXmlBbox(xml, (south + north) / 2, (west + east) / 2),
    };
    cache.set(cacheKey, { expiresAt: Date.now() + CACHE_TTL_MS, value: result });
    return result;
  } catch (err) {
    return {
      ok: false,
      source: 'OpenStreetMap',
      bbox,
      fetchedAt: new Date().toISOString(),
      cameras: [],
      error: err instanceof Error ? err.message : 'OpenStreetMap query failed',
    };
  }
}

export async function findOsmSurveillance(
  lat: number,
  lon: number,
  radiusKm: number,
): Promise<OsmSurveillanceResult> {
  const radius = Math.min(Math.max(Number.isFinite(radiusKm) ? radiusKm : 0.5, 0.2), MAX_RADIUS_KM);
  const cacheKey = `${lat.toFixed(3)},${lon.toFixed(3)},${radius.toFixed(2)}`;
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) return cached.value;

  const bboxFor = (km: number) => {
    const latDelta = km / 111;
    const lonDelta = km / Math.max(111 * Math.cos((lat * Math.PI) / 180), 1);
    return {
      south: Number((lat - latDelta).toFixed(6)),
      west: Number((lon - lonDelta).toFixed(6)),
      north: Number((lat + latDelta).toFixed(6)),
      east: Number((lon + lonDelta).toFixed(6)),
    };
  };

  try {
    let effectiveRadius = radius;
    let bbox = bboxFor(effectiveRadius);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const url = `${OSM_MAP_URL}?bbox=${bbox.west},${bbox.south},${bbox.east},${bbox.north}`;
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'SentinelGlobe/1.0 (public surveillance research; contact: security@localhost)',
          Accept: 'application/xml,text/xml',
        },
        signal: AbortSignal.timeout(20_000),
      });
      const base = {
        source: 'OpenStreetMap' as const,
        bbox,
        fetchedAt: new Date().toISOString(),
      };
      if (response.ok) {
        const xml = await response.text();
        const result: OsmSurveillanceResult = {
          ...base,
          ok: true,
          cameras: parseOsmMapXml(xml, lat, lon, effectiveRadius),
        };
        cache.set(cacheKey, { expiresAt: Date.now() + CACHE_TTL_MS, value: result });
        return result;
      }
      const body = await response.text().catch(() => '');
      if (response.status === 400 && /too many nodes/i.test(body) && effectiveRadius > 0.16) {
        effectiveRadius /= 2;
        bbox = bboxFor(effectiveRadius);
        continue;
      }
      return {
        ...base,
        ok: false,
        cameras: [],
        error: `OpenStreetMap returned HTTP ${response.status}${body ? `: ${body.slice(0, 160)}` : '.'}`,
      };
    }
    return {
      source: 'OpenStreetMap',
      bbox,
      fetchedAt: new Date().toISOString(),
      ok: false,
      cameras: [],
      error: 'OpenStreetMap area is too dense; reduce the search radius.',
    };
  } catch (err) {
    return {
      source: 'OpenStreetMap',
      bbox: bboxFor(radius),
      fetchedAt: new Date().toISOString(),
      ok: false,
      cameras: [],
      error: err instanceof Error ? err.message : 'OpenStreetMap query failed.',
    };
  }
}
