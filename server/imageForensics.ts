import crypto from 'node:crypto';
import zlib from 'node:zlib';
import exifr from 'exifr';
import type { ImageForensicsResult, ThreatNode } from '../src/types/cyber.ts';
import { isPrivateOrReservedIp, isValidIpv4 } from './threatRules.ts';

export function detectImageMagicBytes(buf: Buffer): {
  format: string;
  expectedMimes: string[];
  suspiciousExecutable: boolean;
} {
  if (buf.length < 4) {
    return { format: 'UNKNOWN', expectedMimes: [], suspiciousExecutable: false };
  }

  const headAscii = buf.subarray(0, 64).toString('utf8').trimStart();
  if (buf[0] === 0x4d && buf[1] === 0x5a) {
    return { format: 'PE/MZ Executable', expectedMimes: [], suspiciousExecutable: true };
  }
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { format: 'ELF Binary', expectedMimes: [], suspiciousExecutable: true };
  }
  if (/^(<!doctype|<html|<script|<\?php|#!\s*\/)/i.test(headAscii)) {
    return { format: 'Embedded Script / HTML', expectedMimes: [], suspiciousExecutable: true };
  }

  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { format: 'JPEG', expectedMimes: ['image/jpeg', 'image/jpg'], suspiciousExecutable: false };
  }
  if (
    buf.length >= 8 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return { format: 'PNG', expectedMimes: ['image/png'], suspiciousExecutable: false };
  }
  if (buf.subarray(0, 4).toString('ascii') === 'GIF8') {
    return { format: 'GIF', expectedMimes: ['image/gif'], suspiciousExecutable: false };
  }
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return { format: 'WebP', expectedMimes: ['image/webp'], suspiciousExecutable: false };
  }
  if (
    (buf[0] === 0x49 && buf[1] === 0x49 && buf[2] === 0x2a && buf[3] === 0x00) ||
    (buf[0] === 0x4d && buf[1] === 0x4d && buf[2] === 0x00 && buf[3] === 0x2a)
  ) {
    return { format: 'TIFF', expectedMimes: ['image/tiff'], suspiciousExecutable: false };
  }
  if (buf[0] === 0x42 && buf[1] === 0x4d) {
    return { format: 'BMP', expectedMimes: ['image/bmp'], suspiciousExecutable: false };
  }
  if (buf.length >= 12 && buf.subarray(4, 8).toString('ascii') === 'ftyp') {
    const brand = buf.subarray(8, 12).toString('ascii').toLowerCase();
    if (brand.includes('heic') || brand.includes('heix') || brand.includes('mif1')) {
      return { format: 'HEIC', expectedMimes: ['image/heic', 'image/heif'], suspiciousExecutable: false };
    }
    if (brand.includes('avif')) {
      return { format: 'AVIF', expectedMimes: ['image/avif'], suspiciousExecutable: false };
    }
  }
  if (/^<svg\b/i.test(headAscii) || /^<\?xml/i.test(headAscii)) {
    return { format: 'SVG / XML', expectedMimes: ['image/svg+xml'], suspiciousExecutable: false };
  }

  return { format: 'UNKNOWN', expectedMimes: [], suspiciousExecutable: false };
}

export function computeShannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) {
    counts[buf[i]] += 1;
  }
  let entropy = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function findTrailingBytesAfterEof(buf: Buffer, format: string): {
  count: number;
  preview?: string;
} {
  let eofEnd = -1;
  if (format === 'JPEG') {
    const idx = buf.lastIndexOf(Buffer.from([0xff, 0xd9]));
    if (idx !== -1) eofEnd = idx + 2;
  } else if (format === 'PNG') {
    const iendMarker = Buffer.from([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
    const idx = buf.indexOf(iendMarker);
    if (idx !== -1) eofEnd = idx + 8;
  }

  if (eofEnd !== -1 && eofEnd < buf.length) {
    const tail = buf.subarray(eofEnd);
    const printable = tail
      .subarray(0, 240)
      .toString('latin1')
      .replace(/[^\x20-\x7e]/g, '.');
    return { count: tail.length, preview: printable };
  }
  return { count: 0 };
}

export function parseJpegStructure(buf: Buffer): {
  markers: string[];
  comments: string[];
  sofWidth?: number;
  sofHeight?: number;
  pipelineClass: string;
  recompressionSignals: string[];
} {
  const markers: string[] = [];
  const comments: string[] = [];
  const recompressionSignals: string[] = [];
  let sofWidth: number | undefined;
  let sofHeight: number | undefined;
  let hasApp0 = false;
  let hasApp1Exif = false;
  let hasApp13Iptc = false;
  let dqtCount = 0;

  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) {
    return { markers, comments, pipelineClass: 'Non-JPEG', recompressionSignals };
  }

  markers.push('SOI');
  let pos = 2;
  while (pos + 1 < buf.length && markers.length < 48) {
    if (buf[pos] !== 0xff) break;
    while (pos < buf.length && buf[pos] === 0xff) pos++;
    if (pos >= buf.length) break;
    const marker = buf[pos++];

    if (marker === 0xd9) {
      markers.push('EOI');
      break;
    }
    if (marker === 0xda) {
      markers.push('SOS');
      break; // Scan bitstream begins
    }
    if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7)) continue;

    if (pos + 1 >= buf.length) break;
    const segLen = buf.readUInt16BE(pos);
    if (segLen < 2) break;
    const segDataStart = pos + 2;
    const segDataEnd = Math.min(buf.length, pos + segLen);

    if (marker === 0xe0) {
      hasApp0 = true;
      markers.push('APP0(JFIF)');
    } else if (marker === 0xe1) {
      const hdr = buf.subarray(segDataStart, segDataStart + 6).toString('ascii');
      if (hdr.startsWith('Exif')) {
        hasApp1Exif = true;
        markers.push('APP1(Exif)');
      } else if (hdr.startsWith('http:')) {
        markers.push('APP1(XMP)');
      } else {
        markers.push('APP1');
      }
    } else if (marker === 0xe2) {
      markers.push('APP2(ICC)');
    } else if (marker === 0xed) {
      hasApp13Iptc = true;
      markers.push('APP13(Photoshop/IPTC)');
    } else if (marker === 0xee) {
      markers.push('APP14(Adobe)');
    } else if (marker === 0xdb) {
      dqtCount++;
      markers.push('DQT');
    } else if (marker === 0xc0 || marker === 0xc2) {
      const tagName = marker === 0xc2 ? 'SOF2(Progressive)' : 'SOF0(Baseline)';
      markers.push(tagName);
      if (segDataStart + 5 <= segDataEnd) {
        sofHeight = buf.readUInt16BE(segDataStart + 1);
        sofWidth = buf.readUInt16BE(segDataStart + 3);
      }
      if (marker === 0xc2) {
        recompressionSignals.push('Progressive JPEG scan (typical of web/social CDN re-encoding)');
      }
    } else if (marker === 0xc4) {
      markers.push('DHT');
    } else if (marker === 0xfe) {
      markers.push('COM');
      const txt = buf.subarray(segDataStart, segDataEnd).toString('utf8').replace(/\0/g, '').trim();
      if (txt) comments.push(txt);
    } else {
      markers.push(`0xFF${marker.toString(16).toUpperCase()}`);
    }

    pos = segDataEnd;
  }

  let pipelineClass = 'Standard JPEG Pipeline';
  if (hasApp13Iptc) {
    pipelineClass = 'Adobe / Editor-Processed JPEG';
    recompressionSignals.push('Contains APP13 Photoshop/IPTC segment');
  } else if (hasApp1Exif && !hasApp0) {
    pipelineClass = 'Direct Camera / Smartphone EXIF Pipeline';
  } else if (hasApp0 && !hasApp1Exif) {
    pipelineClass = 'Stripped JFIF Re-Encoded Image (Messaging / Web Platform)';
    recompressionSignals.push(
      'Contains APP0(JFIF) with zero APP1(Exif) — strong indicator of WhatsApp, Messenger, Telegram, or web export stripping',
    );
  }
  if (dqtCount > 0) {
    recompressionSignals.push(`Quantization tables present: ${dqtCount} DQT`);
  }

  return {
    markers,
    comments,
    sofWidth,
    sofHeight,
    pipelineClass,
    recompressionSignals,
  };
}

export function parsePngChunksWithZlib(buf: Buffer): {
  chunks: string[];
  extractedTexts: string[];
  zlibExtractedCount: number;
  width?: number;
  height?: number;
} {
  const chunks: string[] = [];
  const extractedTexts: string[] = [];
  let zlibExtractedCount = 0;
  let width: number | undefined;
  let height: number | undefined;

  if (buf.length < 16 || buf[0] !== 0x89 || buf[1] !== 0x50) {
    return { chunks, extractedTexts, zlibExtractedCount };
  }

  let pos = 8;
  while (pos + 8 <= buf.length && chunks.length < 64) {
    const len = buf.readUInt32BE(pos);
    const type = buf.subarray(pos + 4, pos + 8).toString('ascii');
    chunks.push(type);
    const dataStart = pos + 8;
    const dataEnd = Math.min(buf.length, dataStart + len);

    if (type === 'IHDR' && len >= 8 && dataStart + 8 <= buf.length) {
      width = buf.readUInt32BE(dataStart);
      height = buf.readUInt32BE(dataStart + 4);
    } else if (type === 'tEXt' && len > 0) {
      const raw = buf.subarray(dataStart, dataEnd).toString('latin1').replace(/\0+/g, ': ').trim();
      if (raw) extractedTexts.push(raw);
    } else if (type === 'zTXt' && len > 2) {
      const payload = buf.subarray(dataStart, dataEnd);
      const nulIdx = payload.indexOf(0);
      if (nulIdx !== -1 && nulIdx + 2 < payload.length) {
        const key = payload.subarray(0, nulIdx).toString('latin1');
        const compressed = payload.subarray(nulIdx + 2);
        try {
          const decompressed = zlib.inflateSync(compressed).toString('utf8');
          zlibExtractedCount++;
          extractedTexts.push(`${key}: ${decompressed}`);
        } catch {
          // malformed zlib chunk
        }
      }
    } else if (type === 'iTXt' && len > 4) {
      const payload = buf.subarray(dataStart, dataEnd);
      const nulIdx = payload.indexOf(0);
      if (nulIdx !== -1 && nulIdx + 3 < payload.length) {
        const key = payload.subarray(0, nulIdx).toString('utf8');
        const compressionFlag = payload[nulIdx + 1];
        // Skip compressionFlag, compressionMethod, languageTag\0, translatedKeyword\0
        let cursor = nulIdx + 3;
        const langEnd = payload.indexOf(0, cursor);
        if (langEnd !== -1) {
          const transEnd = payload.indexOf(0, langEnd + 1);
          if (transEnd !== -1) {
            const body = payload.subarray(transEnd + 1);
            if (compressionFlag === 1) {
              try {
                const decompressed = zlib.inflateSync(body).toString('utf8');
                zlibExtractedCount++;
                extractedTexts.push(`${key}: ${decompressed}`);
              } catch {
                // ignore
              }
            } else {
              const text = body.toString('utf8').trim();
              if (text) extractedTexts.push(`${key}: ${text}`);
            }
          }
        }
      }
    }

    pos = dataEnd + 4; // +4 CRC
    if (type === 'IEND') break;
  }

  return { chunks, extractedTexts, zlibExtractedCount, width, height };
}

export function extractEmbeddedStrings(
  buf: Buffer,
  extraTexts: string[] = [],
): ImageForensicsResult['embeddedStrings'] {
  const slice = buf.length > 4 * 1024 * 1024 ? buf.subarray(0, 4 * 1024 * 1024) : buf;
  const asciiMatches = slice.toString('latin1').match(/[\x20-\x7e]{5,}/g) ?? [];

  // Decode UTF-16LE sequences (common in Windows XPAuthor / XPComment / Adobe XMP)
  const utf16Chunk = slice.subarray(0, Math.min(slice.length, 512 * 1024)).toString('utf16le');
  const utf16Matches = utf16Chunk.match(/[A-Za-z0-9:/\\._@?=&+-]{6,}/g) ?? [];

  const joined = [...asciiMatches, ...utf16Matches, ...extraTexts].join('\n');

  const urls = Array.from(
    new Set(joined.match(/https?:\/\/[^\s"'<>()]{4,160}/gi) ?? []),
  ).slice(0, 25);

  const rawIps =
    joined.match(
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    ) ?? [];
  const ips = Array.from(
    new Set(rawIps.filter((ip) => isValidIpv4(ip) && !isPrivateOrReservedIp(ip))),
  ).slice(0, 15);

  const ipv6s = Array.from(
    new Set(
      joined.match(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi) ?? [],
    ),
  )
    .filter((v) => !v.startsWith('fe80:'))
    .slice(0, 10);

  const domains = Array.from(
    new Set(
      (joined.match(/\b(?:[a-z0-9-]{2,}\.)+(?:com|net|org|io|info|biz|ru|cn|xyz|top|app|dev|bd|uk|de)\b/gi) ?? [])
        .map((d) => d.toLowerCase())
        .filter((d) => !['ns.adobe.com', 'purl.org', 'w3.org', 'iptc.org', 'cipa.jp'].some((std) => d.endsWith(std))),
    ),
  ).slice(0, 20);

  const emails = Array.from(
    new Set(joined.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []),
  ).slice(0, 15);

  const filePaths = Array.from(
    new Set([
      ...(joined.match(/[A-Z]:\\(?:Users|Documents|Pictures|Desktop|Temp)[^\n"'<>]{3,90}/gi) ?? []),
      ...(joined.match(/\/(?:Users|home|var|tmp|sdcard|storage\/emulated)\/[^\s"'<>]{3,90}/g) ?? []),
    ]),
  ).slice(0, 12);

  const suspiciousPatterns = [
    /<script\b/i,
    /<\?php/i,
    /\beval\s*\(/i,
    /\bpowershell\b/i,
    /\bcmd\.exe\b/i,
    /javascript:/i,
    /\bonerror\s*=/i,
    /\bonload\s*=/i,
    /PK\x03\x04/,
  ];
  const suspiciousTokens: string[] = [];
  const rawLatin = slice.toString('latin1');
  for (const pat of suspiciousPatterns) {
    const m = rawLatin.match(pat);
    if (m) {
      suspiciousTokens.push(m[0].replace(/[^\x20-\x7e]/g, '?'));
    }
  }

  return { urls, domains, ips, ipv6s, emails, filePaths, suspiciousTokens };
}

export async function reverseGeocodeAddress(
  lat: number,
  lon: number,
  _zoom = 18,
): Promise<{
  displayAddress?: string;
  city?: string;
  country?: string;
  countryCode?: string;
  postal?: string;
} | null> {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  return {
    displayAddress: `${lat.toFixed(5)}, ${lon.toFixed(5)} (offline coordinate; no reverse-geocode API)`,
  };
}

function formatTagValue(val: unknown): string {
  if (val === null || val === undefined) return '';
  if (val instanceof Date) return val.toISOString();
  if (Array.isArray(val)) return val.slice(0, 8).map(String).join(', ');
  if (val instanceof Uint8Array) return `[Binary ${val.byteLength} bytes]`;
  if (typeof val === 'object') {
    try {
      return JSON.stringify(val).slice(0, 180);
    } catch {
      return '[Object]';
    }
  }
  return String(val).slice(0, 220);
}

export async function analyzeImageBuffer(
  buffer: Buffer,
  filename: string,
  declaredMimeType: string,
  ipTraceFn?: (ip: string) => Promise<ThreatNode | null>,
): Promise<ImageForensicsResult> {
  const analyzedAt = new Date().toISOString();
  const magic = detectImageMagicBytes(buffer);
  const entropyBitsPerByte = computeShannonEntropy(buffer);
  const trailingInfo = findTrailingBytesAfterEof(buffer, magic.format);

  let containerAnalysis: ImageForensicsResult['containerAnalysis'] = {
    pipelineClass: `${magic.format} Container`,
    recompressionSignals: [],
    markersOrChunks: [],
    zlibExtractedCount: 0,
  };
  const extraStrings: string[] = [];
  let containerWidth: number | undefined;
  let containerHeight: number | undefined;

  if (magic.format === 'JPEG') {
    const jpegStruct = parseJpegStructure(buffer);
    containerAnalysis = {
      pipelineClass: jpegStruct.pipelineClass,
      recompressionSignals: jpegStruct.recompressionSignals,
      markersOrChunks: jpegStruct.markers,
      zlibExtractedCount: 0,
    };
    extraStrings.push(...jpegStruct.comments);
    containerWidth = jpegStruct.sofWidth;
    containerHeight = jpegStruct.sofHeight;
  } else if (magic.format === 'PNG') {
    const pngStruct = parsePngChunksWithZlib(buffer);
    containerAnalysis = {
      pipelineClass:
        pngStruct.chunks.includes('eXIf')
          ? 'PNG with Embedded EXIF/Metadata'
          : 'Standard PNG Chunk Pipeline',
      recompressionSignals:
        pngStruct.zlibExtractedCount > 0
          ? [`Decompressed ${pngStruct.zlibExtractedCount} zlib PNG text/XMP chunks`]
          : [],
      markersOrChunks: pngStruct.chunks,
      zlibExtractedCount: pngStruct.zlibExtractedCount,
    };
    extraStrings.push(...pngStruct.extractedTexts);
    containerWidth = pngStruct.width;
    containerHeight = pngStruct.height;
  }

  let parsedSegments: Record<string, Record<string, unknown>> | null = null;
  let gpsFlat: { latitude?: number; longitude?: number; altitude?: number } | null = null;
  let embeddedThumbnailDataUrl: string | undefined;

  try {
    parsedSegments = (await exifr.parse(buffer, {
      tiff: true,
      exif: true,
      gps: true,
      xmp: true,
      iptc: true,
      icc: true,
      jfif: true,
      ihdr: true,
      mergeOutput: false,
      sanitize: true,
    })) as Record<string, Record<string, unknown>> | null;
  } catch {
    parsedSegments = null;
  }

  try {
    gpsFlat = (await exifr.gps(buffer)) as {
      latitude?: number;
      longitude?: number;
      altitude?: number;
    } | null;
  } catch {
    gpsFlat = null;
  }

  try {
    const thumbBuf = await exifr.thumbnail(buffer);
    if (thumbBuf && thumbBuf.length > 0 && thumbBuf.length <= 150 * 1024) {
      embeddedThumbnailDataUrl = `data:image/jpeg;base64,${Buffer.from(thumbBuf).toString('base64')}`;
    }
  } catch {
    embeddedThumbnailDataUrl = undefined;
  }

  const rawTags: Array<{ group: string; key: string; value: string }> = [];
  const flatLookup: Record<string, unknown> = {};

  if (parsedSegments && typeof parsedSegments === 'object') {
    for (const [group, tags] of Object.entries(parsedSegments)) {
      if (!tags || typeof tags !== 'object') continue;
      for (const [key, val] of Object.entries(tags)) {
        flatLookup[key] = val;
        const formatted = formatTagValue(val);
        if (formatted) {
          rawTags.push({ group, key, value: formatted });
          extraStrings.push(`${key}=${formatted}`);
        }
        if (rawTags.length >= 220) break;
      }
    }
  }

  const embeddedStrings = extractEmbeddedStrings(buffer, extraStrings);

  const hashes = {
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
  };

  const lowerMime = (declaredMimeType || '').toLowerCase();
  const mimeMismatch =
    magic.suspiciousExecutable ||
    (magic.expectedMimes.length > 0 &&
      Boolean(lowerMime) &&
      !magic.expectedMimes.includes(lowerMime));

  const polyglotWarnings: string[] = [];
  if (magic.suspiciousExecutable) {
    polyglotWarnings.push(
      `CRITICAL: Binary signature is "${magic.format}" disguised as an image file!`,
    );
  } else if (mimeMismatch) {
    polyglotWarnings.push(
      `MIME mismatch: Declared "${declaredMimeType}" but binary magic bytes are ${magic.format}`,
    );
  }
  if (trailingInfo.count > 64) {
    polyglotWarnings.push(
      `Detected ${trailingInfo.count.toLocaleString('en-US')} trailing bytes appended after image EOF marker (possible hidden payload or steganography)`,
    );
  }
  if (embeddedStrings.suspiciousTokens.length > 0) {
    polyglotWarnings.push(
      `Embedded script/code tokens found inside binary: ${embeddedStrings.suspiciousTokens.join(', ')}`,
    );
  }

  const width =
    typeof flatLookup.ExifImageWidth === 'number'
      ? flatLookup.ExifImageWidth
      : typeof flatLookup.ImageWidth === 'number'
        ? flatLookup.ImageWidth
        : containerWidth;
  const height =
    typeof flatLookup.ExifImageHeight === 'number'
      ? flatLookup.ExifImageHeight
      : typeof flatLookup.ImageHeight === 'number'
        ? flatLookup.ImageHeight
        : containerHeight;

  const exposureVal = flatLookup.ExposureTime;
  const exposureTime =
    typeof exposureVal === 'number' && exposureVal > 0 && exposureVal < 1
      ? `1/${Math.round(1 / exposureVal)}s`
      : exposureVal !== undefined
        ? String(exposureVal)
        : undefined;

  const focalVal = flatLookup.FocalLength;
  const focalLength = typeof focalVal === 'number' ? `${focalVal} mm` : undefined;

  const camera: ImageForensicsResult['camera'] = {
    make: flatLookup.Make ? String(flatLookup.Make) : undefined,
    model: flatLookup.Model ? String(flatLookup.Model) : undefined,
    hostComputer: flatLookup.HostComputer ? String(flatLookup.HostComputer) : undefined,
    lensMake: flatLookup.LensMake ? String(flatLookup.LensMake) : undefined,
    lens: flatLookup.LensModel ? String(flatLookup.LensModel) : undefined,
    serialNumber: flatLookup.SerialNumber ? String(flatLookup.SerialNumber) : undefined,
    bodySerialNumber: flatLookup.BodySerialNumber
      ? String(flatLookup.BodySerialNumber)
      : flatLookup.InternalSerialNumber
        ? String(flatLookup.InternalSerialNumber)
        : undefined,
    software: flatLookup.Software
      ? String(flatLookup.Software)
      : flatLookup.CreatorTool
        ? String(flatLookup.CreatorTool)
        : undefined,
    artist: flatLookup.Artist
      ? String(flatLookup.Artist)
      : flatLookup.Creator
        ? String(flatLookup.Creator)
        : undefined,
    ownerName: flatLookup.OwnerName
      ? String(flatLookup.OwnerName)
      : flatLookup.CameraOwnerName
        ? String(flatLookup.CameraOwnerName)
        : undefined,
    copyright: flatLookup.Copyright ? String(flatLookup.Copyright) : undefined,
    imageUniqueId: flatLookup.ImageUniqueID ? String(flatLookup.ImageUniqueID) : undefined,
    dateTimeOriginal: flatLookup.DateTimeOriginal
      ? formatTagValue(flatLookup.DateTimeOriginal)
      : undefined,
    createDate: flatLookup.CreateDate ? formatTagValue(flatLookup.CreateDate) : undefined,
    modifyDate: flatLookup.ModifyDate ? formatTagValue(flatLookup.ModifyDate) : undefined,
    iso: typeof flatLookup.ISO === 'number' ? flatLookup.ISO : undefined,
    fNumber: typeof flatLookup.FNumber === 'number' ? flatLookup.FNumber : undefined,
    exposureTime,
    focalLength,
  };

  let gps: ImageForensicsResult['gps'] = null;
  const lat = gpsFlat?.latitude;
  const lon = gpsFlat?.longitude;
  if (typeof lat === 'number' && typeof lon === 'number' && Number.isFinite(lat) && Number.isFinite(lon)) {
    const rev = await reverseGeocodeAddress(lat, lon, 18);
    const altitude =
      typeof gpsFlat?.altitude === 'number'
        ? Number(gpsFlat.altitude.toFixed(1))
        : typeof flatLookup.GPSAltitude === 'number'
          ? Number(flatLookup.GPSAltitude.toFixed(1))
          : undefined;
    const compassHeading =
      typeof flatLookup.GPSImgDirection === 'number'
        ? Number(flatLookup.GPSImgDirection.toFixed(1))
        : undefined;
    const speed =
      typeof flatLookup.GPSSpeed === 'number' ? Number(flatLookup.GPSSpeed.toFixed(1)) : undefined;
    const gpsMethod = flatLookup.GPSProcessingMethod
      ? String(flatLookup.GPSProcessingMethod)
      : undefined;
    const gpsTimestamp = flatLookup.GPSDateStamp
      ? `${String(flatLookup.GPSDateStamp)} ${formatTagValue(flatLookup.GPSTimeStamp)}`.trim()
      : undefined;
    const osmUrl = `https://www.openstreetmap.org/?mlat=${lat.toFixed(6)}&mlon=${lon.toFixed(6)}#map=18/${lat.toFixed(6)}/${lon.toFixed(6)}`;

    const mapNode: ThreatNode = {
      id: `photo-gps-${hashes.sha256.slice(0, 10)}`,
      ip: `EXIF GPS (${filename})`,
      threatType: 'Extracted Photo GPS Origin',
      sourceFeed: 'Photo GPS',
      severity: polyglotWarnings.length > 0 ? 'CRITICAL' : 'ELEVATED',
      country: rev?.country || 'GPS Coordinate',
      countryCode: rev?.countryCode || 'GPS',
      city: rev?.city || `${lat.toFixed(3)}, ${lon.toFixed(3)}`,
      postal: rev?.postal,
      physicalAddress: rev?.displayAddress,
      lat,
      lon,
      asn: camera.make || camera.hostComputer
        ? `${camera.make || ''} ${camera.model || camera.hostComputer || ''}`.trim()
        : 'EXIF Sensor',
      isp: camera.software || 'Embedded EXIF GPS',
      org: camera.ownerName || camera.artist || filename,
    };

    gps = {
      latitude: Number(lat.toFixed(6)),
      longitude: Number(lon.toFixed(6)),
      altitude,
      compassHeading,
      speed,
      gpsMethod,
      gpsTimestamp,
      physicalAddress: rev?.displayAddress,
      osmUrl,
      mapNode,
    };
  }

  const textualLocation: ImageForensicsResult['textualLocation'] =
    flatLookup.City || flatLookup.Sublocation || flatLookup.State || flatLookup.ProvinceState || flatLookup.Country
      ? {
          city: flatLookup.City ? String(flatLookup.City) : undefined,
          sublocation: flatLookup.Sublocation ? String(flatLookup.Sublocation) : undefined,
          state: flatLookup.State
            ? String(flatLookup.State)
            : flatLookup.ProvinceState
              ? String(flatLookup.ProvinceState)
              : undefined,
          country: flatLookup.Country
            ? String(flatLookup.Country)
            : flatLookup.CountryName
              ? String(flatLookup.CountryName)
              : undefined,
          countryCode: flatLookup.CountryCode ? String(flatLookup.CountryCode) : undefined,
        }
      : null;

  // Automatically geolocate and trace up to 3 public IPs extracted from binary/XMP/PNG chunks
  let embeddedIpTraces: ThreatNode[] = [];
  if (ipTraceFn && embeddedStrings.ips.length > 0) {
    const traced: Array<ThreatNode | null> = await Promise.all(
      embeddedStrings.ips.slice(0, 3).map(async (ip): Promise<ThreatNode | null> => {
        const node = await ipTraceFn(ip).catch(() => null);
        if (!node) return null;
        return {
          ...node,
          id: `img-ip-${ip}`,
          sourceFeed: 'Image Embedded IP',
          threatType: `Embedded IP inside "${filename}" (${node.threatType})`,
        };
      }),
    );
    embeddedIpTraces = traced.filter((n): n is ThreatNode => n !== null);
  }

  const originSummaryParts: string[] = [];
  if (camera.make || camera.model || camera.hostComputer) {
    originSummaryParts.push(
      `Device identified: ${[camera.make, camera.model, camera.hostComputer].filter(Boolean).join(' ')}.`,
    );
  } else {
    originSummaryParts.push(
      'No hardware device/phone model tags remain in this file (likely stripped by messaging/web export or never written).',
    );
  }
  if (gps) {
    originSummaryParts.push(
      `Exact GPS coordinates (${gps.latitude}, ${gps.longitude}) extracted and street-geocoded.`,
    );
  }
  if (embeddedIpTraces.length > 0) {
    originSummaryParts.push(
      `Extracted & geolocated ${embeddedIpTraces.length} public IP address(es) embedded inside binary/metadata.`,
    );
  } else {
    originSummaryParts.push(
      'No public IPv4 strings are stored inside this image binary (standard camera files only contain IP addresses if custom software, XMP logs, or appended payloads embed them).',
    );
  }

  return {
    filename,
    declaredMimeType: declaredMimeType || 'application/octet-stream',
    detectedFormat: magic.format,
    mimeMismatch,
    fileSizeBytes: buffer.length,
    hashes,
    entropyBitsPerByte,
    appendedTrailingBytes: trailingInfo.count,
    trailingPayloadPreview: trailingInfo.preview,
    polyglotWarnings,
    containerAnalysis,
    embeddedThumbnailDataUrl,
    dimensions: {
      width,
      height,
      colorSpace: flatLookup.ColorSpace ? String(flatLookup.ColorSpace) : undefined,
    },
    camera,
    gps,
    textualLocation,
    embeddedStrings,
    embeddedIpTraces,
    privacyAndOriginNote: originSummaryParts.join(' '),
    rawTags,
    analyzedAt,
  };
}
