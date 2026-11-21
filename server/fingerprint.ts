import { createHash } from 'node:crypto';
import type { Request } from 'express';
import Tlsh from 'tlsh';

function header(req: Request, name: string): string | undefined {
  const value = req.headers[name];
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (Array.isArray(value) && value[0]?.trim()) return value[0].trim();
  return undefined;
}

export interface RequestFingerprint {
  ja3?: string;
  ja4?: string;
  tlsh?: string;
  tlsVersion?: string;
  cipher?: string;
  sha256: string;
  subnet?: string;
  asn?: string;
}

export function ipv4Subnet(ip: string): string | undefined {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return undefined;
  const parts = ip.split('.');
  if (parts.some((part) => Number(part) > 255)) return undefined;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function asnFromHeaders(req: Request): string | undefined {
  const raw = header(req, 'cf-asn') ?? header(req, 'x-asn') ?? header(req, 'x-ip-asn');
  if (!raw) return undefined;
  const clean = raw.trim();
  if (/^\d+$/.test(clean)) return `AS${clean}`;
  return clean.slice(0, 40);
}

function canonicalRequest(req: Request): string {
  const tls = req.socket as unknown as {
    getProtocol?: () => string | null;
    getCipher?: () => { name?: string } | null;
  };
  const protocol = header(req, 'x-tls-version') ?? tls.getProtocol?.() ?? '';
  const cipher = header(req, 'x-tls-cipher') ?? tls.getCipher?.()?.name ?? '';
  return JSON.stringify({
    m: req.method,
    p: req.path,
    ua: header(req, 'user-agent') ?? '',
    accept: header(req, 'accept') ?? '',
    language: header(req, 'accept-language') ?? '',
    encoding: header(req, 'accept-encoding') ?? '',
    chUa: header(req, 'sec-ch-ua') ?? '',
    chPlatform: header(req, 'sec-ch-ua-platform') ?? '',
    tls: protocol,
    cipher,
    ja3: header(req, 'x-ja3-hash') ?? header(req, 'x-ja3') ?? '',
    ja4: header(req, 'x-ja4') ?? '',
  });
}

export function tlshFromText(text: string): string | undefined {
  if (text.length < 50) return undefined;
  try {
    const hasher = new Tlsh();
    hasher.update(Buffer.from(text, 'utf8'));
    hasher.final();
    return hasher.toString();
  } catch {
    return undefined;
  }
}

export function requestFingerprint(req: Request, ip: string): RequestFingerprint {
  const canonical = canonicalRequest(req);
  const sha256 = createHash('sha256').update(canonical).digest('hex');

  let tlsh: string | undefined;
  const bodyText =
    req.body && typeof req.body === 'object' && Object.keys(req.body as object).length > 0
      ? JSON.stringify(req.body)
      : '';
  const sample = `${canonical}\n${bodyText}`;
  if (sample.length >= 50) {
    try {
      const hasher = new Tlsh();
      hasher.update(Buffer.from(sample, 'utf8'));
      hasher.final();
      tlsh = hasher.toString();
    } catch {
      tlsh = undefined;
    }
  }

  const tls = req.socket as unknown as {
    getProtocol?: () => string | null;
    getCipher?: () => { name?: string } | null;
  };

  return {
    ja3: header(req, 'x-ja3-hash') ?? header(req, 'x-ja3') ?? header(req, 'cf-ja3-hash'),
    ja4: header(req, 'x-ja4') ?? header(req, 'cf-ja4'),
    tlsh,
    tlsVersion: header(req, 'x-tls-version') ?? tls.getProtocol?.() ?? undefined,
    cipher: header(req, 'x-tls-cipher') ?? tls.getCipher?.()?.name ?? undefined,
    sha256,
    subnet: ipv4Subnet(ip),
    asn: asnFromHeaders(req),
  };
}
