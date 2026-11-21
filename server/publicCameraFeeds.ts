export type FeedProtocol = 'hls' | 'mjpeg' | 'iframe' | 'link' | 'image';

export interface FeedCamera {
  id: string;
  name: string;
  lat: number;
  lon: number;
  distanceKm: number;
  kind: string;
  operator?: string;
  zone?: string;
  description?: string;
  osmUrl: string;
  streamUrl: string;
  protocol: FeedProtocol;
  source: string;
  attribution: string;
}

const CACHE_TTL_MS = 5 * 60 * 1000;
const FETCH_TIMEOUT_MS = 12_000;
const cache = new Map<string, { expiresAt: number; cameras: FeedCamera[] }>();

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

async function fetchJson(url: string): Promise<unknown> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { Accept: 'application/json', 'User-Agent': 'SentinelGlobe/1.0 public-camera-index' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res.json();
}

async function loadNycCameras(): Promise<FeedCamera[]> {
  const rows = (await fetchJson('https://webcams.nyctmc.org/api/cameras')) as Array<Record<string, unknown>>;
  if (!Array.isArray(rows)) return [];
  return rows
    .filter((row) => String(row.isOnline ?? 'true') !== 'false')
    .map((row): FeedCamera | null => {
      const lat = Number(row.latitude);
      const lon = Number(row.longitude);
      const imageUrl = String(row.imageUrl ?? '');
      if (!Number.isFinite(lat) || !Number.isFinite(lon) || !/^https:\/\//i.test(imageUrl)) return null;
      const name = String(row.name ?? 'NYC traffic camera');
      return {
        id: `nyc:${String(row.id ?? name)}`,
        name,
        lat,
        lon,
        distanceKm: 0,
        kind: 'nyc traffic camera',
        operator: 'NYC DOT',
        zone: row.area ? String(row.area) : undefined,
        description: 'Live snapshot refreshed automatically by NYC DOT.',
        osmUrl: imageUrl,
        streamUrl: imageUrl,
        protocol: 'image' as const,
        source: 'NYC DOT',
        attribution: 'NYC DOT public traffic cameras',
      };
    })
    .filter((camera): camera is FeedCamera => camera !== null);
}

async function loadTflCameras(): Promise<FeedCamera[]> {
  const rows = (await fetchJson('https://api.tfl.gov.uk/Place/Type/JamCam')) as Array<Record<string, unknown>>;
  if (!Array.isArray(rows)) return [];
  return rows
    .map((row): FeedCamera | null => {
      const lat = Number(row.lat);
      const lon = Number(row.lon);
      const props = Array.isArray(row.additionalProperties)
        ? (row.additionalProperties as Array<Record<string, unknown>>)
        : [];
      const get = (key: string) => {
        const found = props.find((prop) => prop.key === key);
        return found?.value ? String(found.value) : '';
      };
      const available = get('available');
      const imageUrl = get('imageUrl');
      const videoUrl = get('videoUrl');
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
      if (available === 'false') return null;
      const streamUrl = imageUrl || videoUrl;
      if (!/^https:\/\//i.test(streamUrl)) return null;
      return {
        id: `tfl:${String(row.id ?? row.commonName ?? 'camera')}`,
        name: String(row.commonName ?? 'TfL JamCam'),
        lat,
        lon,
        distanceKm: 0,
        kind: 'london traffic camera',
        operator: 'Transport for London',
        zone: get('view') || undefined,
        description: 'TfL JamCam snapshot refreshed automatically.',
        osmUrl: videoUrl || streamUrl,
        streamUrl,
        protocol: 'image' as const,
        source: 'TfL',
        attribution: 'Transport for London JamCam public feeds',
      };
    })
    .filter((camera): camera is FeedCamera => camera !== null);
}

const CALTRANS_DISTRICTS = ['03', '04', '07', '08', '11', '12'];

async function loadCaltransCameras(): Promise<FeedCamera[]> {
  const districts = await Promise.allSettled(
    CALTRANS_DISTRICTS.map(async (district) => {
      const payload = (await fetchJson(
        `https://cwwp2.dot.ca.gov/data/d${Number(district)}/cctv/cctvStatusD${district}.json`,
      )) as { data?: Array<Record<string, unknown>> };
      return Array.isArray(payload.data) ? payload.data : [];
    }),
  );
  const cameras: FeedCamera[] = [];
  for (const district of districts) {
    if (district.status !== 'fulfilled') continue;
    for (const row of district.value) {
      const cctv = (row.cctv ?? {}) as Record<string, unknown>;
      const location = (cctv.location ?? {}) as Record<string, unknown>;
      const imageData = (cctv.imageData ?? {}) as Record<string, unknown>;
      const staticData = (imageData.static ?? {}) as Record<string, unknown>;
      const lat = Number(location.latitude);
      const lon = Number(location.longitude);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) continue;
      if (String(cctv.inService ?? 'true') === 'false') continue;
      const videoUrl = String(imageData.streamingVideoURL ?? '');
      const imageUrl = String(staticData.currentImageURL ?? '');
      const streamUrl = /^https:\/\//i.test(videoUrl) ? videoUrl : imageUrl;
      if (!/^https:\/\//i.test(streamUrl)) continue;
      const name = String(location.locationName ?? location.nearbyPlace ?? 'Caltrans camera');
      cameras.push({
        id: `caltrans:${String(cctv.index ?? name)}:${String(location.route ?? '')}`,
        name,
        lat,
        lon,
        distanceKm: 0,
        kind: 'california traffic camera',
        operator: 'Caltrans',
        zone: [location.nearbyPlace, location.county].filter(Boolean).join(' · ') || undefined,
        description: 'Caltrans public CCTV feed.',
        osmUrl: imageUrl || streamUrl,
        streamUrl,
        protocol: /\.m3u8($|\?)/i.test(streamUrl) ? 'hls' : 'image',
        source: 'Caltrans',
        attribution: 'California Department of Transportation public CCTV',
      });
    }
  }
  return cameras;
}

async function cached(key: string, loader: () => Promise<FeedCamera[]>): Promise<FeedCamera[]> {
  const hit = cache.get(key);
  if (hit && hit.expiresAt > Date.now()) return hit.cameras;
  try {
    const cameras = await loader();
    cache.set(key, { expiresAt: Date.now() + CACHE_TTL_MS, cameras });
    return cameras;
  } catch {
    return hit?.cameras ?? [];
  }
}

export async function nearbyPublicFeeds(
  lat: number,
  lon: number,
  radiusKm: number,
): Promise<FeedCamera[]> {
  const [nyc, tfl, caltrans] = await Promise.all([
    cached('nyc', loadNycCameras),
    cached('tfl', loadTflCameras),
    cached('caltrans', loadCaltransCameras),
  ]);
  return [...nyc, ...tfl, ...caltrans]
    .map((camera) => ({
      ...camera,
      distanceKm: Number(distanceKm(lat, lon, camera.lat, camera.lon).toFixed(3)),
    }))
    .filter((camera) => camera.distanceKm <= radiusKm)
    .sort((a, b) => a.distanceKm - b.distanceKm);
}
