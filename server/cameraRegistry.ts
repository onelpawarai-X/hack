import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type CameraProtocol = 'hls' | 'mjpeg' | 'iframe' | 'link';

export interface PublicCamera {
  id: string;
  name: string;
  lat: number;
  lon: number;
  url: string;
  protocol: CameraProtocol;
  city?: string;
  country?: string;
  source: string;
  attribution?: string;
  addedAt: string;
}

const DATA_DIR = path.resolve(process.cwd(), 'data', 'cameras');
const FILE = path.join(DATA_DIR, 'cameras.json');

function load(): PublicCamera[] {
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function save(cameras: PublicCamera[]) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(cameras, null, 2), 'utf8');
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

class CameraRegistry {
  private cameras: PublicCamera[] = load();

  list(): PublicCamera[] {
    return [...this.cameras];
  }

  nearby(lat: number, lon: number, radiusKm = 10): Array<PublicCamera & { distanceKm: number }> {
    return this.cameras
      .map((camera) => ({ ...camera, distanceKm: distanceKm(lat, lon, camera.lat, camera.lon) }))
      .filter((camera) => camera.distanceKm <= radiusKm)
      .sort((a, b) => a.distanceKm - b.distanceKm);
  }

  add(input: Partial<PublicCamera>): { ok: boolean; error?: string; camera?: PublicCamera } {
    const name = String(input.name ?? '').trim();
    const url = String(input.url ?? '').trim();
    const lat = Number(input.lat);
    const lon = Number(input.lon);
    if (!name) return { ok: false, error: 'Camera name is required.' };
    if (!Number.isFinite(lat) || lat < -90 || lat > 90) return { ok: false, error: 'Latitude is invalid.' };
    if (!Number.isFinite(lon) || lon < -180 || lon > 180) return { ok: false, error: 'Longitude is invalid.' };
    if (!/^https?:\/\//i.test(url)) return { ok: false, error: 'A public http(s) stream URL is required.' };
    const protocol = (['hls', 'mjpeg', 'iframe', 'link'].includes(String(input.protocol))
      ? input.protocol
      : 'link') as CameraProtocol;
    const camera: PublicCamera = {
      id: randomUUID(),
      name,
      lat,
      lon,
      url,
      protocol,
      city: input.city ? String(input.city) : undefined,
      country: input.country ? String(input.country) : undefined,
      source: input.source ? String(input.source) : 'operator-import',
      attribution: input.attribution ? String(input.attribution) : undefined,
      addedAt: new Date().toISOString(),
    };
    this.cameras.push(camera);
    save(this.cameras);
    return { ok: true, camera };
  }

  remove(id: string): boolean {
    const next = this.cameras.filter((camera) => camera.id !== id);
    if (next.length === this.cameras.length) return false;
    this.cameras = next;
    save(this.cameras);
    return true;
  }

  reload(): void {
    this.cameras = load();
  }
}

export const cameraRegistry = new CameraRegistry();
