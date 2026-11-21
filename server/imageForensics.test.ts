import assert from 'node:assert/strict';
import test from 'node:test';
import zlib from 'node:zlib';
import {
  analyzeImageBuffer,
  computeShannonEntropy,
  detectImageMagicBytes,
  extractEmbeddedStrings,
  findTrailingBytesAfterEof,
  parseJpegStructure,
  parsePngChunksWithZlib,
} from './imageForensics.ts';

test('detectImageMagicBytes identifies PNG, JPEG, and disguised PE executables', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
  assert.equal(detectImageMagicBytes(png).format, 'PNG');

  const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
  assert.equal(detectImageMagicBytes(jpg).format, 'JPEG');

  const exe = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]);
  const exeRes = detectImageMagicBytes(exe);
  assert.equal(exeRes.format, 'PE/MZ Executable');
  assert.equal(exeRes.suspiciousExecutable, true);
});

test('findTrailingBytesAfterEof detects appended data and returns preview after JPEG EOI', () => {
  const cleanJpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0xff, 0xd9]);
  assert.equal(findTrailingBytesAfterEof(cleanJpg, 'JPEG').count, 0);

  const appended = Buffer.concat([cleanJpg, Buffer.from('HIDDEN_PAYLOAD_12345', 'ascii')]);
  const res = findTrailingBytesAfterEof(appended, 'JPEG');
  assert.equal(res.count, 20);
  assert.ok(res.preview?.includes('HIDDEN_PAYLOAD_12345'));
});

test('parseJpegStructure fingerprints stripped JFIF vs EXIF camera pipeline', () => {
  const jfifOnly = Buffer.from([
    0xff, 0xd8,
    0xff, 0xe0, 0x00, 0x04, 0x4a, 0x46,
    0xff, 0xc0, 0x00, 0x0b, 0x08, 0x04, 0x00, 0x05, 0x00, 0x01, 0x01, 0x11, 0x00,
    0xff, 0xd9,
  ]);
  const parsed = parseJpegStructure(jfifOnly);
  assert.ok(parsed.markers.includes('APP0(JFIF)'));
  assert.equal(parsed.sofHeight, 1024);
  assert.equal(parsed.sofWidth, 1280);
  assert.match(parsed.pipelineClass, /Stripped JFIF/);
});

test('parsePngChunksWithZlib decompresses zTXt metadata chunk', () => {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const compressed = zlib.deflateSync(Buffer.from('Author=SentinelLab HostIP=1.1.1.1', 'utf8'));
  const ztxtData = Buffer.concat([Buffer.from('Comment\0', 'ascii'), Buffer.from([0]), compressed]);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(ztxtData.length);
  const crc = Buffer.alloc(4);
  const ztxtChunk = Buffer.concat([lenBuf, Buffer.from('zTXt'), ztxtData, crc]);
  const iend = Buffer.from([0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);

  const parsed = parsePngChunksWithZlib(Buffer.concat([sig, ztxtChunk, iend]));
  assert.equal(parsed.zlibExtractedCount, 1);
  assert.ok(parsed.chunks.includes('zTXt'));
  assert.ok(parsed.extractedTexts[0].includes('1.1.1.1'));
});

test('extractEmbeddedStrings extracts URLs, public IPs, file paths, and UTF-16 strings', () => {
  const utf16Author = Buffer.from('C:\\Users\\analyst\\Desktop\\cam_raw.jpg ', 'utf16le');
  const payload = Buffer.concat([
    Buffer.from(
      'header https://evil-c2.example/beacon 8.8.8.8 192.168.1.5 eval(test) analyst@test.org /Users/dev/photo.png ',
      'latin1',
    ),
    utf16Author,
  ]);
  const found = extractEmbeddedStrings(payload);
  assert.ok(found.urls.includes('https://evil-c2.example/beacon'));
  assert.ok(found.ips.includes('8.8.8.8'));
  assert.equal(found.ips.includes('192.168.1.5'), false);
  assert.ok(found.emails.includes('analyst@test.org'));
  assert.ok(found.filePaths.some((p) => p.includes('/Users/dev/photo.png')));
  assert.ok(found.suspiciousTokens.length > 0);
});

test('computeShannonEntropy computes expected range for uniform vs varied bytes', () => {
  const uniform = Buffer.alloc(1024, 0x41);
  assert.equal(computeShannonEntropy(uniform), 0);

  const varied = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.equal(computeShannonEntropy(varied), 8);
});

test('analyzeImageBuffer detects MIME spoofing, trailing payload, and traces embedded IP via callback', async () => {
  const cleanJpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0xff, 0xd9]);
  const payload = Buffer.from('x'.repeat(80) + ' https://trap.example 8.8.8.8 <script>alert(1)</script>');
  const combined = Buffer.concat([cleanJpg, payload]);

  const res = await analyzeImageBuffer(combined, 'disguised.png', 'image/png', async (ip) => ({
    id: `stub-${ip}`,
    ip,
    threatType: 'Stub Trace',
    sourceFeed: 'Live Attribution',
    severity: 'CLEAN',
    country: 'United States',
    countryCode: 'US',
    city: 'Mountain View',
    lat: 37.386,
    lon: -122.083,
    asn: 'AS15169',
    isp: 'Google LLC',
    org: 'Google LLC',
  }));
  assert.equal(res.detectedFormat, 'JPEG');
  assert.equal(res.mimeMismatch, true);
  assert.ok(res.appendedTrailingBytes > 64);
  assert.ok(res.polyglotWarnings.length >= 2);
  assert.equal(res.hashes.sha256.length, 64);
  assert.equal(res.embeddedIpTraces.length, 1);
  assert.equal(res.embeddedIpTraces[0].ip, '8.8.8.8');
  assert.equal(res.embeddedIpTraces[0].sourceFeed, 'Image Embedded IP');
});
