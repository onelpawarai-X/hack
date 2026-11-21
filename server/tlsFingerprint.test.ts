import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { parseClientHello } from './tlsFingerprint.ts';

function extension(type: number, body: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(body.length, 2);
  return Buffer.concat([header, body]);
}

function uint16List(values: number[]): Buffer {
  const body = Buffer.alloc(2 + values.length * 2);
  body.writeUInt16BE(values.length * 2, 0);
  values.forEach((value, index) => body.writeUInt16BE(value, 2 + index * 2));
  return body;
}

function buildClientHello(): Buffer {
  const sniName = Buffer.from('example.com', 'utf8');
  const sniBody = Buffer.alloc(2 + 1 + 2 + sniName.length);
  sniBody.writeUInt16BE(1 + 2 + sniName.length, 0);
  sniBody[2] = 0;
  sniBody.writeUInt16BE(sniName.length, 3);
  sniName.copy(sniBody, 5);

  const alpnBody = Buffer.concat([
    Buffer.from([0x00, 0x0c, 0x02]),
    Buffer.from('h2'),
    Buffer.from([0x08]),
    Buffer.from('http/1.1'),
  ]);

  const extensions = Buffer.concat([
    extension(0x0000, sniBody),
    extension(0x000a, uint16List([0x001d, 0x0017])),
    extension(0x000b, Buffer.from([0x01, 0x00])),
    extension(0x000d, uint16List([0x0403, 0x0804])),
    extension(0x0010, alpnBody),
    extension(0x002b, Buffer.concat([Buffer.from([0x04]), Buffer.from([0x03, 0x04, 0x03, 0x03])])),
  ]);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x11),
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x04, 0x13, 0x01, 0x13, 0x02]),
    Buffer.from([0x01, 0x00]),
    Buffer.from([extensions.length >> 8, extensions.length & 0xff]),
    extensions,
  ]);

  const handshake = Buffer.concat([
    Buffer.from([0x01]),
    Buffer.from([(body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);

  const record = Buffer.alloc(5);
  record[0] = 0x16;
  record.writeUInt16BE(0x0301, 1);
  record.writeUInt16BE(handshake.length, 3);
  return Buffer.concat([record, handshake]);
}

test('parseClientHello computes deterministic JA3 and JA4 from a real ClientHello', () => {
  const result = parseClientHello(buildClientHello());
  assert.equal(result.status, 'complete');
  if (result.status !== 'complete') return;

  assert.equal(result.hello.sni, 'example.com');
  assert.deepEqual(result.hello.alpn, ['h2', 'http/1.1']);
  assert.equal(result.hello.tlsVersion, 'TLSv1.3');
  assert.equal(result.hello.ja3, '771,4865-4866,0-10-11-13-16-43,29-23,0');
  assert.equal(
    result.hello.ja3Hash,
    createHash('md5').update(result.hello.ja3).digest('hex'),
  );
  assert.match(result.hello.ja4, /^t13d0206h2_[0-9a-f]{12}_[0-9a-f]{12}$/);
  assert.deepEqual(result.hello.signatureAlgorithms, ['0403', '0804']);
});

test('parseClientHello waits for a complete handshake', () => {
  const buffer = buildClientHello();
  assert.equal(parseClientHello(buffer.subarray(0, 10)).status, 'need-more');
  assert.equal(parseClientHello(buffer.subarray(0, buffer.length - 2)).status, 'need-more');
});

test('parseClientHello rejects non-TLS bytes', () => {
  const result = parseClientHello(Buffer.from('GET / HTTP/1.1\r\n\r\n'));
  assert.equal(result.status, 'invalid');
});
