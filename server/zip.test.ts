import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createZip } from './zip.ts';

test('createZip writes local headers, central directory and end record', () => {
  const archive = createZip([
    { name: 'README.md', data: '# hello' },
    { name: 'nested/agent.js', data: 'console.log(1)' },
  ]);
  assert.equal(archive.readUInt32LE(0), 0x04034b50);
  const eocd = archive.length - 22;
  assert.equal(archive.readUInt32LE(eocd), 0x06054b50);
  assert.equal(archive.readUInt16LE(eocd + 8), 2);
  assert.equal(archive.readUInt16LE(eocd + 10), 2);
  assert.ok(archive.includes(Buffer.from('nested/agent.js')));
});
