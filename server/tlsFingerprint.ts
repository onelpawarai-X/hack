import { createHash } from 'node:crypto';

export interface TlsClientHello {
  ja3: string;
  ja3Hash: string;
  ja4: string;
  tlsVersion: string;
  cipherSuites: string[];
  extensions: string[];
  ellipticCurves: string[];
  pointFormats: string[];
  signatureAlgorithms: string[];
  sni?: string;
  alpn: string[];
}

export type ClientHelloParse =
  | { status: 'complete'; hello: TlsClientHello }
  | { status: 'need-more' }
  | { status: 'invalid'; reason: string };

const GREASE = new Set<number>();
for (let i = 0; i < 16; i += 1) GREASE.add(0x0a0a + i * 0x1010);

function isGrease(value: number): boolean {
  return GREASE.has(value);
}

function readUInt24BE(buffer: Buffer, offset: number): number {
  return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
}

function hex(value: number): string {
  return value.toString(16).padStart(4, '0');
}

function tlsVersionCode(version: number): string {
  if (version >= 0x0304) return '13';
  if (version === 0x0303) return '12';
  if (version === 0x0302) return '11';
  if (version === 0x0301) return '10';
  return '00';
}

function tlsVersionLabel(version: number): string {
  if (version >= 0x0304) return 'TLSv1.3';
  if (version === 0x0303) return 'TLSv1.2';
  if (version === 0x0302) return 'TLSv1.1';
  if (version === 0x0301) return 'TLSv1.0';
  return `0x${version.toString(16)}`;
}

function parseSni(data: Buffer): string | undefined {
  if (data.length < 2) return undefined;
  const listLength = data.readUInt16BE(0);
  let offset = 2;
  const end = Math.min(2 + listLength, data.length);
  while (offset + 3 <= end) {
    const type = data[offset];
    const length = data.readUInt16BE(offset + 1);
    offset += 3;
    if (offset + length > data.length) return undefined;
    if (type === 0) return data.subarray(offset, offset + length).toString('utf8');
    offset += length;
  }
  return undefined;
}

function parseUint16List(data: Buffer, lengthBytes: 1 | 2): number[] {
  if (data.length < lengthBytes) return [];
  const length = lengthBytes === 1 ? data[0] : data.readUInt16BE(0);
  const values: number[] = [];
  for (let offset = lengthBytes; offset + 1 < Math.min(data.length, lengthBytes + length); offset += 2) {
    values.push(data.readUInt16BE(offset));
  }
  return values;
}

function parseAlpn(data: Buffer): string[] {
  if (data.length < 2) return [];
  const listLength = data.readUInt16BE(0);
  let offset = 2;
  const end = Math.min(2 + listLength, data.length);
  const protocols: string[] = [];
  while (offset < end) {
    const length = data[offset];
    offset += 1;
    if (offset + length > data.length) break;
    protocols.push(data.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  return protocols;
}

function parseExtensions(data: Buffer): {
  extensions: number[];
  curves: number[];
  pointFormats: number[];
  signatureAlgorithms: number[];
  supportedVersions: number[];
  sni?: string;
  alpn: string[];
} {
  const extensions: number[] = [];
  const curves: number[] = [];
  const pointFormats: number[] = [];
  const signatureAlgorithms: number[] = [];
  const supportedVersions: number[] = [];
  let sni: string | undefined;
  let alpn: string[] = [];

  let offset = 0;
  while (offset + 4 <= data.length) {
    const type = data.readUInt16BE(offset);
    const length = data.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + length > data.length) break;
    const body = data.subarray(offset, offset + length);
    extensions.push(type);

    if (type === 0x0000) sni = parseSni(body);
    else if (type === 0x000a) curves.push(...parseUint16List(body, 2));
    else if (type === 0x000b) {
      const listLength = body.length > 0 ? body[0] : 0;
      for (let i = 1; i < Math.min(body.length, 1 + listLength); i += 1) pointFormats.push(body[i]);
    } else if (type === 0x000d) signatureAlgorithms.push(...parseUint16List(body, 2));
    else if (type === 0x0010) alpn = parseAlpn(body);
    else if (type === 0x002b) {
      if (body.length > 0) {
        const listLength = body[0];
        for (let i = 1; i + 1 < Math.min(body.length, 1 + listLength); i += 2) {
          supportedVersions.push(body.readUInt16BE(i));
        }
      }
    }

    offset += length;
  }

  return { extensions, curves, pointFormats, signatureAlgorithms, supportedVersions, sni, alpn };
}

function parseHandshake(handshake: Buffer): TlsClientHello {
  let offset = 0;
  const clientVersion = handshake.readUInt16BE(offset);
  offset += 2 + 32; // legacy_version + random
  if (offset >= handshake.length) throw new Error('ClientHello truncated at session id');

  const sessionIdLength = handshake[offset];
  offset += 1 + sessionIdLength;
  if (offset + 2 > handshake.length) throw new Error('ClientHello truncated at cipher suites');
  const cipherLength = handshake.readUInt16BE(offset);
  offset += 2;
  if (offset + cipherLength > handshake.length) throw new Error('ClientHello truncated in cipher suites');
  const cipherSuites: number[] = [];
  for (let i = 0; i < cipherLength; i += 2) cipherSuites.push(handshake.readUInt16BE(offset + i));
  offset += cipherLength;

  if (offset >= handshake.length) throw new Error('ClientHello truncated at compression methods');
  const compressionLength = handshake[offset];
  offset += 1 + compressionLength;

  let parsedExtensions: {
    extensions: number[];
    curves: number[];
    pointFormats: number[];
    signatureAlgorithms: number[];
    supportedVersions: number[];
    sni?: string;
    alpn: string[];
  } = {
    extensions: [],
    curves: [],
    pointFormats: [],
    signatureAlgorithms: [],
    supportedVersions: [],
    alpn: [],
  };
  if (offset + 2 <= handshake.length) {
    const extensionLength = handshake.readUInt16BE(offset);
    offset += 2;
    if (offset + extensionLength <= handshake.length) {
      parsedExtensions = parseExtensions(handshake.subarray(offset, offset + extensionLength));
    }
  }

  const cleanCiphers = cipherSuites.filter((value) => !isGrease(value));
  const cleanExtensions = parsedExtensions.extensions.filter((value) => !isGrease(value));
  const cleanCurves = parsedExtensions.curves.filter((value) => !isGrease(value));
  const cleanPointFormats = parsedExtensions.pointFormats;
  const cleanSignatures = parsedExtensions.signatureAlgorithms.filter((value) => !isGrease(value));

  const ja3 = [
    clientVersion,
    cleanCiphers.join('-'),
    cleanExtensions.join('-'),
    cleanCurves.join('-'),
    cleanPointFormats.join('-'),
  ].join(',');
  const ja3Hash = createHash('md5').update(ja3).digest('hex');

  const supportedMax = parsedExtensions.supportedVersions.length
    ? Math.max(...parsedExtensions.supportedVersions)
    : clientVersion;
  const versionCode = tlsVersionCode(supportedMax);
  const sniFlag = parsedExtensions.sni ? 'd' : 'i';
  const alpn = parsedExtensions.alpn[0] ?? '';
  const alpnCode = alpn.length >= 2 ? `${alpn[0]}${alpn[alpn.length - 1]}` : '00';
  const ja4a = `t${versionCode}${sniFlag}${String(cleanCiphers.length).padStart(2, '0')}${String(cleanExtensions.length).padStart(2, '0')}${alpnCode}`;
  const ja4b = createHash('sha256')
    .update([...cleanCiphers].sort((a, b) => a - b).map(hex).join(','))
    .digest('hex')
    .slice(0, 12);
  const hashExtensions = cleanExtensions
    .filter((type) => type !== 0x0000 && type !== 0x0010)
    .sort((a, b) => a - b)
    .map(hex)
    .join(',');
  const hashSignatures = [...cleanSignatures].sort((a, b) => a - b).map(hex).join(',');
  const ja4c = createHash('sha256')
    .update(`${hashExtensions}_${hashSignatures}`)
    .digest('hex')
    .slice(0, 12);
  const ja4 = `${ja4a}_${ja4b}_${ja4c}`;

  return {
    ja3,
    ja3Hash,
    ja4,
    tlsVersion: tlsVersionLabel(supportedMax),
    cipherSuites: cleanCiphers.map(hex),
    extensions: cleanExtensions.map(hex),
    ellipticCurves: cleanCurves.map(hex),
    pointFormats: cleanPointFormats.map((value) => value.toString(16).padStart(2, '0')),
    signatureAlgorithms: cleanSignatures.map(hex),
    sni: parsedExtensions.sni,
    alpn: parsedExtensions.alpn,
  };
}

/**
 * Parse a TLS ClientHello from raw bytes captured before TLS termination.
 * Returns need-more until the full handshake message is present.
 */
export function parseClientHello(buffer: Buffer): ClientHelloParse {
  if (buffer.length < 5) return { status: 'need-more' };
  if (buffer[0] !== 0x16) return { status: 'invalid', reason: 'Not a TLS handshake record' };

  let offset = 0;
  let handshake = Buffer.alloc(0);
  let handshakeLength: number | null = null;

  while (offset + 5 <= buffer.length) {
    const contentType = buffer[offset];
    const recordLength = buffer.readUInt16BE(offset + 3);
    if (contentType !== 0x16) return { status: 'invalid', reason: 'Unexpected TLS record type' };
    if (offset + 5 + recordLength > buffer.length) return { status: 'need-more' };
    handshake = Buffer.concat([handshake, buffer.subarray(offset + 5, offset + 5 + recordLength)]);
    offset += 5 + recordLength;

    if (handshake.length >= 4) {
      handshakeLength = readUInt24BE(handshake, 1);
      if (handshake.length >= 4 + handshakeLength) {
        if (handshake[0] !== 0x01) return { status: 'invalid', reason: 'Not a ClientHello' };
        try {
          return { status: 'complete', hello: parseHandshake(handshake.subarray(4, 4 + handshakeLength)) };
        } catch (err) {
          return { status: 'invalid', reason: err instanceof Error ? err.message : 'Malformed ClientHello' };
        }
      }
    }
    if (offset === buffer.length) break;
  }

  return { status: 'need-more' };
}

export function fingerprintFromHeaders(headers: Record<string, string | undefined>): {
  ja3?: string;
  ja4?: string;
  tlsVersion?: string;
  cipher?: string;
} {
  return {
    ja3: headers['x-ja3-hash'] ?? headers['x-ja3'] ?? headers['cf-ja3-hash'],
    ja4: headers['x-ja4'] ?? headers['cf-ja4'],
    tlsVersion: headers['x-tls-version'],
    cipher: headers['x-tls-cipher'],
  };
}
