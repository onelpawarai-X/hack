export const DEFAULT_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

interface CacheEntry<T> {
  value: T;
  cachedAt: number;
  expiresAt: number;
}

export class MemoryCache {
  private store = new Map<string, CacheEntry<unknown>>();
  private ttlMs: number;

  constructor(ttlMs: number = DEFAULT_CACHE_TTL_MS) {
    this.ttlMs = ttlMs;
  }

  get<T>(
    key: string,
    now: number = Date.now(),
  ): { value: T; cachedAt: number; expiresAt: number } | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (now >= entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return {
      value: entry.value as T,
      cachedAt: entry.cachedAt,
      expiresAt: entry.expiresAt,
    };
  }

  set<T>(
    key: string,
    value: T,
    now: number = Date.now(),
    customTtlMs?: number,
  ): { cachedAt: number; expiresAt: number } {
    const ttl = customTtlMs ?? this.ttlMs;
    const cachedAt = now;
    const expiresAt = now + ttl;
    this.store.set(key, { value, cachedAt, expiresAt });
    return { cachedAt, expiresAt };
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  clearByPrefix(prefix: string): number {
    let removed = 0;
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        this.store.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  clearAll(): void {
    this.store.clear();
  }

  stats(now: number = Date.now()): { activeEntries: number; ttlMinutes: number } {
    let activeEntries = 0;
    for (const [key, entry] of this.store.entries()) {
      if (now < entry.expiresAt) {
        activeEntries += 1;
      } else {
        this.store.delete(key);
      }
    }
    return {
      activeEntries,
      ttlMinutes: Math.round(this.ttlMs / 60000),
    };
  }
}
