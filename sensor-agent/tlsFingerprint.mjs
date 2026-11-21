import { createHash } from 'node:crypto';

const GREASE = new Set();
for (let i = 0; i < 16; i += 1) GREASE.add(0x0a0a + i * 0x1010);

const isGrease = (value) => GREASE.has(value);
const hex = (value) => value.toString(16).padStart(4, '0');

function versionCode(version) {
  if (version >= 0x0304) return '13';
  if (version === 0x0303) return '12';
  if (version === 0x0302) return '11';
  if (version === 0x0301) return '10';
  return '00';
}

function versionLabel(version) {
  if (version >= 0x0304) return 'TLSv1.3';
  if (version === 0x0303) return 'TLSv1.2';
  if (version === 0x0302) return 'TLSv1.1';
  if (version === 0x0301) return 'TLSv1.0';
  return `0x${version.toString(16)}`;
}

function uint16List(data) {
  if (data.length < 2) return [];
  const length = data.readUInt16BE(0);
  const values = [];
  for (let offset = 2; offset + 1 < Math.min(data.length, 2 + length); offset += 2) {
    values.push(data.readUInt16BE(offset));
  }
  return values;
}

function parseSni(data) {
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

function parseAlpn(data) {
  if (data.length < 2) return [];
  const listLength = data.readUInt16BE(0);
  let offset = 2;
  const end = Math.min(2 + listLength, data.length);
  const protocols = [];
  while (offset < end) {
    const length = data[offset];
    offset += 1;
    if (offset + length > data.length) break;
    protocols.push(data.subarray(offset, offset + length).toString('ascii'));
    offset += length;
  }
  return protocols;
}

function parseExtensions(data) {
  const extensions = [];
  const curves = [];
  const pointFormats = [];
  const signatures = [];
  const supportedVersions = [];
  let sni;
  let alpn = [];
  let offset = 0;
  while (offset + 4 <= data.length) {
    const type = data.readUInt16BE(offset);
    const length = data.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + length > data.length) break;
    const body = data.subarray(offset, offset + length);
    extensions.push(type);
    if (type === 0x0000) sni = parseSni(body);
    else if (type === 0x000a) curves.push(...uint16List(body));
    else if (type === 0x000b) {
      const listLength = body.length > 0 ? body[0] : 0;
      for (let i = 1; i < Math.min(body.length, 1 + listLength); i += 1) pointFormats.push(body[i]);
    } else if (type === 0x000d) signatures.push(...uint16List(body));
    else if (type === 0x0010) alpn = parseAlpn(body);
    else if (type === 0x002b && body.length > 0) {
      const listLength = body[0];
      for (let i = 1; i + 1 < Math.min(body.length, 1 + listLength); i += 2) {
        supportedVersions.push(body.readUInt16BE(i));
      }
    }
    offset += length;
  }
  return { extensions, curves, pointFormats, signatures, supportedVersions, sni, alpn };
}

function parseHandshake(handshake) {
  let offset = 0;
  const clientVersion = handshake.readUInt16BE(offset);
  offset += 2 + 32;
  const sessionIdLength = handshake[offset];
  offset += 1 + sessionIdLength;
  const cipherLength = handshake.readUInt16BE(offset);
  offset += 2;
  const ciphers = [];
  for (let i = 0; i < cipherLength; i += 2) ciphers.push(handshake.readUInt16BE(offset + i));
  offset += cipherLength;
  const compressionLength = handshake[offset];
  offset += 1 + compressionLength;

  let parsed = {
    extensions: [],
    curves: [],
    pointFormats: [],
    signatures: [],
    supportedVersions: [],
    sni: undefined,
    alpn: [],
  };
  if (offset + 2 <= handshake.length) {
    const extensionLength = handshake.readUInt16BE(offset);
    offset += 2;
    if (offset + extensionLength <= handshake.length) {
      parsed = parseExtensions(handshake.subarray(offset, offset + extensionLength));
    }
  }

  const cleanCiphers = ciphers.filter((value) => !isGrease(value));
  const cleanExtensions = parsed.extensions.filter((value) => !isGrease(value));
  const cleanCurves = parsed.curves.filter((value) => !isGrease(value));
  const cleanSignatures = parsed.signatures.filter((value) => !isGrease(value));

  const ja3 = [
    clientVersion,
    cleanCiphers.join('-'),
    cleanExtensions.join('-'),
    cleanCurves.join('-'),
    parsed.pointFormats.join('-'),
  ].join(',');
  const ja3Hash = createHash('md5').update(ja3).digest('hex');

  const supportedMax = parsed.supportedVersions.length
    ? Math.max(...parsed.supportedVersions)
    : clientVersion;
  const alpn = parsed.alpn[0] ?? '';
  const alpnCode = alpn.length >= 2 ? `${alpn[0]}${alpn[alpn.length - 1]}` : '00';
  const ja4a = `t${versionCode(supportedMax)}${parsed.sni ? 'd' : 'i'}${String(cleanCiphers.length).padStart(2, '0')}${String(cleanExtensions.length).padStart(2, '0')}${alpnCode}`;
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

  return {
    ja3: ja3Hash,
    ja3String: ja3,
    ja4: `${ja4a}_${ja4b}_${ja4c}`,
    tlsVersion: versionLabel(supportedMax),
    cipher: cleanCiphers[0] ? hex(cleanCiphers[0]) : undefined,
    sni: parsed.sni,
    alpn: parsed.alpn,
  };
}

export function parseClientHello(buffer) {
  if (buffer.length < 5) return { status: 'need-more' };
  if (buffer[0] !== 0x16) return { status: 'invalid', reason: 'Not a TLS handshake record' };
  let offset = 0;
  let handshake = Buffer.alloc(0);
  while (offset + 5 <= buffer.length) {
    if (buffer[offset] !== 0x16) return { status: 'invalid', reason: 'Unexpected TLS record type' };
    const recordLength = buffer.readUInt16BE(offset + 3);
    if (offset + 5 + recordLength > buffer.length) return { status: 'need-more' };
    handshake = Buffer.concat([handshake, buffer.subarray(offset + 5, offset + 5 + recordLength)]);
    offset += 5 + recordLength;
    if (handshake.length >= 4) {
      const handshakeLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
      if (handshake.length >= 4 + handshakeLength) {
        if (handshake[0] !== 0x01) return { status: 'invalid', reason: 'Not a ClientHello' };
        try {
          return { status: 'complete', hello: parseHandshake(handshake.subarray(4, 4 + handshakeLength)) };
        } catch (err) {
          return { status: 'invalid', reason: err.message };
        }
      }
    }
    if (offset === buffer.length) break;
  }
  return { status: 'need-more' };
}
