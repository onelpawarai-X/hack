import { randomUUID } from 'node:crypto';
import net from 'node:net';
import type { AttackEvent } from '../src/types/defenseGrid.ts';
import { attackSensor } from './attackSensor.ts';
import { ipv4Subnet, tlshFromText } from './fingerprint.ts';
import { parseClientHello } from './tlsFingerprint.ts';

export interface TlsSensorStatus {
  enabled: boolean;
  listening: boolean;
  host: string;
  port: number;
  connections: number;
  fingerprints: number;
  lastAt?: string;
  lastError?: string;
}

const status: TlsSensorStatus = {
  enabled: false,
  listening: false,
  host: '0.0.0.0',
  port: 0,
  connections: 0,
  fingerprints: 0,
};

let server: net.Server | null = null;

export function tlsSensorStatus(): TlsSensorStatus {
  return { ...status };
}

export function startTlsFingerprintSensor(options: { port: number; host?: string }): void {
  status.enabled = options.port > 0;
  status.port = options.port;
  status.host = options.host ?? '0.0.0.0';
  if (!status.enabled || server) return;

  server = net.createServer((socket) => {
    status.connections += 1;
    let buffer = Buffer.alloc(0);
    const remoteIp = (socket.remoteAddress ?? '').replace(/^::ffff:/, '');
    const timer = setTimeout(() => socket.destroy(), 8_000);

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]).subarray(0, 64 * 1024);
      const parsed = parseClientHello(buffer);
      if (parsed.status === 'need-more') return;

      clearTimeout(timer);
      if (parsed.status === 'complete') {
        const hello = parsed.hello;
        status.fingerprints += 1;
        status.lastAt = new Date().toISOString();
        const event: AttackEvent = {
          id: randomUUID(),
          ts: new Date().toISOString(),
          ip: remoteIp || 'unknown',
          method: 'TLS',
          path: `tls://${hello.sni ?? remoteIp ?? 'clienthello'}`.slice(0, 300),
          host: hello.sni,
          userAgent: 'TLS ClientHello',
          category: 'scanner',
          severity: 'CLEAN',
          detail: `TLS ClientHello · ${hello.tlsVersion} · JA4 ${hello.ja4}`,
          action: 'observed',
          source: 'sensor',
          sensorId: 'tls-sensor',
          subnet: ipv4Subnet(remoteIp),
          ja3: hello.ja3Hash,
          ja4: hello.ja4,
          tlsh: tlshFromText(buffer.toString('base64')),
          tlsVersion: hello.tlsVersion,
          cipher: hello.cipherSuites[0],
        };
        attackSensor.ingestExternalEvents([event]);
      }
      socket.end();
    });

    socket.on('error', () => {
      clearTimeout(timer);
    });
    socket.on('close', () => clearTimeout(timer));
  });

  server.on('error', (err) => {
    status.listening = false;
    status.lastError = err.message;
    console.error(`[tls-sensor] ${err.message}`);
  });

  server.listen(status.port, status.host, () => {
    status.listening = true;
    status.lastError = undefined;
    console.log(
      `[tls-sensor] JA3/JA4 ClientHello sensor listening on ${status.host}:${status.port}`,
    );
  });
}

export function stopTlsFingerprintSensor(): Promise<void> {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => {
      server = null;
      status.listening = false;
      resolve();
    });
  });
}
