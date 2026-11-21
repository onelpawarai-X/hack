import dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { isValidIpv4 } from './threatRules.ts';

const DEFAULT_STUN_SERVERS: Array<{ host: string; port: number }> = [
  { host: 'stun.cloudflare.com', port: 3478 },
  { host: 'stun.l.google.com', port: 19302 },
];

function configuredStunServers(): Array<{ host: string; port: number }> {
  const raw = process.env.SENTINEL_STUN_SERVERS?.trim();
  if (!raw) return DEFAULT_STUN_SERVERS;
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [host, portText] = entry.split(':');
      const port = Number(portText) || 3478;
      return { host, port };
    })
    .filter((entry) => Boolean(entry.host));
}

function parseStunAddress(buffer: Buffer): string | null {
  if (buffer.length < 20) return null;
  const magic = buffer.readUInt32BE(4);
  if (magic !== 0x2112a442) return null;
  const length = buffer.readUInt16BE(2);
  let offset = 20;
  const end = Math.min(buffer.length, 20 + length);
  while (offset + 4 <= end) {
    const type = buffer.readUInt16BE(offset);
    const attrLength = buffer.readUInt16BE(offset + 2);
    const valueOffset = offset + 4;
    if (valueOffset + attrLength > end) break;
    if (type === 0x0020 || type === 0x0001) {
      const family = buffer[valueOffset + 1];
      if (family === 0x01 && attrLength >= 8) {
        const port = buffer.readUInt16BE(valueOffset + 2) ^ (type === 0x0020 ? 0x2112 : 0);
        const raw = buffer.readUInt32BE(valueOffset + 4);
        const ipValue = type === 0x0020 ? (raw ^ 0x2112a442) >>> 0 : raw;
        const ip = [ipValue >>> 24, (ipValue >>> 16) & 255, (ipValue >>> 8) & 255, ipValue & 255].join('.');
        if (isValidIpv4(ip) && port > 0) return ip;
      }
    }
    offset = valueOffset + attrLength + ((4 - (attrLength % 4)) % 4);
  }
  return null;
}

function queryStun(host: string, port: number, timeoutMs = 2500): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const transaction = randomBytes(12);
    const request = Buffer.alloc(20);
    request.writeUInt16BE(0x0001, 0);
    request.writeUInt16BE(0, 2);
    request.writeUInt32BE(0x2112a442, 4);
    transaction.copy(request, 8);
    let settled = false;
    const finish = (value: string | null) => {
      if (settled) return;
      settled = true;
      socket.close();
      resolve(value);
    };
    socket.on('message', (message) => finish(parseStunAddress(message)));
    socket.on('error', () => finish(null));
    socket.send(request, port, host, (err) => {
      if (err) finish(null);
    });
    setTimeout(() => finish(null), timeoutMs);
  });
}

export async function discoverPublicIp(): Promise<string | null> {
  const configured = process.env.SENTINEL_PUBLIC_IP?.trim();
  if (configured && isValidIpv4(configured)) return configured;
  for (const server of configuredStunServers()) {
    const ip = await queryStun(server.host, server.port);
    if (ip) return ip;
  }
  return null;
}
