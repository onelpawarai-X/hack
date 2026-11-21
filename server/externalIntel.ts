import type { ThreatActorExternalIntel } from '../src/types/cyber.ts';

type Json = Record<string, unknown>;

function asRecord(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function strings(value: unknown, limit = 12): string[] {
  return asArray(value)
    .map((item) => (typeof item === 'string' ? item : ''))
    .filter(Boolean)
    .slice(0, limit);
}

async function getJson(url: string, timeout = 12_000): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'SentinelGlobe/1.0 (authorized threat-intelligence audit)' },
      signal: AbortSignal.timeout(timeout),
    });
    if (!response.ok) return { ok: false, error: `HTTP ${response.status}` };
    return { ok: true, data: await response.json() };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'request failed' };
  }
}

export async function collectExternalIntel(ip: string): Promise<ThreatActorExternalIntel> {
  const [shodanResult, otxGeneral, otxPassiveDns, otxMalware, otxUrls] = await Promise.all([
    getJson(`https://internetdb.shodan.io/${ip}`, 8_000),
    getJson(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, 15_000),
    getJson(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/passive_dns`, 15_000),
    getJson(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/malware`, 15_000),
    getJson(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/url_list`, 15_000),
  ]);

  const shodanRecord = asRecord(shodanResult.data);
  const shodan = shodanRecord
    ? {
        ports: asArray(shodanRecord.ports).filter((value): value is number => typeof value === 'number').slice(0, 40),
        hostnames: strings(shodanRecord.hostnames, 20),
        tags: strings(shodanRecord.tags, 20),
        vulns: strings(shodanRecord.vulns, 30),
        cpes: strings(shodanRecord.cpes, 20),
      }
    : undefined;

  const general = asRecord(otxGeneral.data);
  const pulseInfo = asRecord(general?.pulse_info);
  const pulses = asArray(pulseInfo?.pulses)
    .map((item) => asRecord(item))
    .filter((item): item is Json => Boolean(item))
    .slice(0, 12)
    .map((pulse) => ({
      name: text(pulse.name) ?? 'Unnamed OTX pulse',
      description: text(pulse.description)?.slice(0, 400),
      tags: strings(pulse.tags, 12),
      malwareFamilies: strings(pulse.malware_families, 12),
      attackIds: asArray(pulse.attack_ids)
        .map((item) => asRecord(item))
        .filter((item): item is Json => Boolean(item))
        .slice(0, 12)
        .map((item) => [text(item.id), text(item.name)].filter(Boolean).join(' ')),
      adversary: text(pulse.adversary),
      targetedCountries: strings(pulse.targeted_countries, 12),
      created: text(pulse.created),
      modified: text(pulse.modified),
      references: strings(pulse.references, 6),
    }));

  const passiveDns = asArray(asRecord(otxPassiveDns.data)?.passive_dns)
    .map((item) => asRecord(item))
    .filter((item): item is Json => Boolean(item))
    .slice(0, 40)
    .map((item) => ({
      hostname: text(item.hostname) ?? '',
      address: text(item.address),
      first: text(item.first),
      last: text(item.last),
      recordType: text(item.record_type),
    }))
    .filter((item) => item.hostname);

  const malware = asArray(asRecord(otxMalware.data)?.data)
    .map((item) => asRecord(item))
    .filter((item): item is Json => Boolean(item))
    .slice(0, 15)
    .map((item) => ({
      hash: text(item.hash) ?? '',
      detections: typeof item.detections === 'number' ? item.detections : undefined,
      family: text(item.family),
      date: text(item.date),
    }))
    .filter((item) => item.hash);

  const urls = asArray(asRecord(otxUrls.data)?.url_list)
    .map((item) => asRecord(item))
    .filter((item): item is Json => Boolean(item))
    .slice(0, 30)
    .map((item) => ({
      url: text(item.url) ?? '',
      domain: text(item.domain),
      hostname: text(item.hostname),
      date: text(item.date),
      httpCode: typeof item.httpcode === 'number' ? item.httpcode : undefined,
    }))
    .filter((item) => item.url);

  const validation = asArray(general?.validation)
    .map((item) => asRecord(item))
    .filter((item): item is Json => Boolean(item))
    .slice(0, 8)
    .map((item) => `${text(item.name) ?? 'validation'}: ${text(item.message) ?? ''}`);

  return {
    generatedAt: new Date().toISOString(),
    sources: [
      {
        name: 'Shodan InternetDB',
        status: shodanResult.ok ? 'online' : 'degraded',
        detail: shodanResult.ok ? `${shodan?.ports.length ?? 0} open port(s)` : shodanResult.error ?? 'unavailable',
      },
      {
        name: 'AlienVault OTX',
        status: otxGeneral.ok ? 'online' : 'degraded',
        detail: otxGeneral.ok ? `${pulseInfo?.count ?? pulses.length} pulse(s)` : otxGeneral.error ?? 'unavailable',
      },
      {
        name: 'OTX passive DNS',
        status: otxPassiveDns.ok ? 'online' : 'degraded',
        detail: otxPassiveDns.ok ? `${passiveDns.length} record(s)` : otxPassiveDns.error ?? 'unavailable',
      },
      {
        name: 'OTX malware',
        status: otxMalware.ok ? 'online' : 'degraded',
        detail: otxMalware.ok ? `${malware.length} sample(s)` : otxMalware.error ?? 'unavailable',
      },
      {
        name: 'OTX URL history',
        status: otxUrls.ok ? 'online' : 'degraded',
        detail: otxUrls.ok ? `${urls.length} URL(s)` : otxUrls.error ?? 'unavailable',
      },
    ],
    shodan,
    otx: {
      pulseCount: typeof pulseInfo?.count === 'number' ? pulseInfo.count : pulses.length,
      pulses,
      validation,
      passiveDns,
      malware,
      urls,
      tags: Array.from(new Set(pulses.flatMap((pulse) => pulse.tags))).slice(0, 30),
      malwareFamilies: Array.from(new Set(pulses.flatMap((pulse) => pulse.malwareFamilies))).slice(0, 20),
    },
  };
}
