#!/usr/bin/env node
/**
 * SentinelGlobe distributed honeypot sensor.
 *
 * Runs on any VPS. It exposes decoy endpoints, captures real request metadata,
 * and ships it to the central SentinelGlobe sensor ingest API.
 *
 * Required environment:
 *   SENTINEL_CENTRAL_URL  e.g. https://sentinel.example.com
 *   SENTINEL_SENSOR_TOKEN token from Control Center -> Sensors
 *   SENSOR_ID             unique id, e.g. vps-fra-1
 * Optional:
 *   SENSOR_NAME, SENSOR_REGION, SENSOR_PORT (default 8088)
 *   SENSOR_TRUST_PROXY=true when behind nginx/Cloudflare
 */

import http from 'node:http';
import net from 'node:net';
import { parseClientHello } from './tlsFingerprint.mjs';

const CENTRAL = (process.env.SENTINEL_CENTRAL_URL || '').replace(/\/$/, '');
const TOKEN = process.env.SENTINEL_SENSOR_TOKEN || '';
const SENSOR_ID = process.env.SENSOR_ID || 'vps-unknown';
const SENSOR_NAME = process.env.SENSOR_NAME || SENSOR_ID;
const SENSOR_REGION = process.env.SENSOR_REGION || 'unknown';
const PORT = Number(process.env.SENSOR_PORT || 8088);
const TLS_PORT = Number(process.env.SENSOR_TLS_PORT || 0);
const TRUST_PROXY = process.env.SENSOR_TRUST_PROXY === 'true';
const FLUSH_MS = Number(process.env.SENSOR_FLUSH_MS || 3000);
const TARPIT_MS = Number(process.env.SENSOR_TARPIT_MS || 900);

if (!CENTRAL || !TOKEN) {
  console.error('[sensor] SENTINEL_CENTRAL_URL and SENTINEL_SENSOR_TOKEN are required.');
  process.exit(1);
}

let queue = [];
let flushing = false;
let lastHeartbeat = 0;
let tlsServer = null;

const DECOYS = {
  '/.env': {
    status: 200,
    type: 'text/plain',
    body: [
      'APP_ENV=production',
      'APP_DEBUG=false',
      'DB_HOST=127.0.0.1',
      'DB_USER=decoy',
      'DB_PASSWORD=DECOY_VALUE_NOT_REAL',
      'AWS_ACCESS_KEY_ID=DECOY',
      'AWS_SECRET_ACCESS_KEY=DECOY',
    ].join('\n'),
  },
  '/.git/config': {
    status: 200,
    type: 'text/plain',
    body: '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n',
  },
  '/actuator/env': {
    status: 200,
    type: 'application/json',
    body: JSON.stringify({ activeProfiles: ['prod'], propertySources: [], sentinel: 'decoy' }),
  },
  '/config.json': {
    status: 200,
    type: 'application/json',
    body: JSON.stringify({ apiUrl: 'https://decoy.invalid', debug: false, sentinel: 'decoy' }),
  },
};

function decoyFor(pathname) {
  const clean = pathname.toLowerCase();
  if (DECOYS[clean]) return DECOYS[clean];
  if (clean.includes('login') || clean.includes('admin')) {
    return {
      status: 200,
      type: 'text/html',
      body: '<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1><form method="post"><input name="username"><input name="password" type="password"><button>Sign in</button></form></body></html>',
    };
  }
  return {
    status: 404,
    type: 'text/html',
    body: '<!doctype html><html><body><h1>Not Found</h1></body></html>',
  };
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      return forwarded.split(',')[0].trim();
    }
  }
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

function sanitizeHeaders(headers) {
  const keep = [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
    'x-ja3-hash',
    'x-ja3',
    'cf-ja3-hash',
    'x-ja4',
    'cf-ja4',
    'x-tls-version',
    'x-tls-cipher',
    'cf-asn',
    'x-asn',
    'x-ip-asn',
  ];
  const out = {};
  for (const name of keep) {
    const value = headers[name];
    if (typeof value === 'string') out[name] = value.slice(0, 400);
  }
  return out;
}

async function flush() {
  if (flushing || queue.length === 0) return;
  flushing = true;
  const batch = queue.slice(0, 200);
  queue = queue.slice(batch.length);
  try {
    const res = await fetch(`${CENTRAL}/api/sensors/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Sensor-Token': TOKEN,
      },
      body: JSON.stringify({ sensorId: SENSOR_ID, events: batch }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`ingest HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    const payload = await res.json().catch(() => ({}));
    console.log(`[sensor] shipped ${batch.length} events (accepted=${payload.accepted ?? '?'})`);
  } catch (err) {
    console.error(`[sensor] delivery failed: ${err.message}`);
    queue = [...batch, ...queue].slice(-500);
  } finally {
    flushing = false;
  }
}

async function heartbeat() {
  if (Date.now() - lastHeartbeat < 25_000) return;
  lastHeartbeat = Date.now();
  try {
    await fetch(`${CENTRAL}/api/sensors/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Sensor-Token': TOKEN,
      },
      body: JSON.stringify({
        sensorId: SENSOR_ID,
        name: SENSOR_NAME,
        region: SENSOR_REGION,
        status: 'online',
      }),
    });
  } catch (err) {
    console.error(`[sensor] heartbeat failed: ${err.message}`);
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'sensor.local'}`);
  const chunks = [];
  let size = 0;

  req.on('data', (chunk) => {
    if (size >= 16_384) return;
    chunks.push(chunk);
    size += chunk.length;
  });

  req.on('end', () => {
    const bodyText = Buffer.concat(chunks).slice(0, 16_384).toString('utf8');
    queue.push({
      ts: new Date().toISOString(),
      ip: clientIp(req),
      method: req.method,
      path: url.pathname,
      query: url.search,
      host: req.headers.host,
      userAgent: req.headers['user-agent'],
      headers: sanitizeHeaders(req.headers),
      body: bodyText,
      sensor: { id: SENSOR_ID, name: SENSOR_NAME, region: SENSOR_REGION },
    });
    if (queue.length > 500) queue = queue.slice(-500);

    const decoy = decoyFor(url.pathname);
    const delay = decoy.status === 200 ? TARPIT_MS : 120;
    setTimeout(() => {
      res.writeHead(decoy.status, {
        'Content-Type': decoy.type,
        'Server': 'nginx',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(decoy.body);
    }, delay);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[sensor] ${SENSOR_ID} (${SENSOR_REGION}) listening on :${PORT}`);
  console.log(`[sensor] central=${CENTRAL}`);
  void heartbeat();
});

if (TLS_PORT > 0) {
  tlsServer = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    const remoteIp = (socket.remoteAddress || '').replace(/^::ffff:/, '');
    const timer = setTimeout(() => socket.destroy(), 8000);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]).subarray(0, 64 * 1024);
      const parsed = parseClientHello(buffer);
      if (parsed.status === 'need-more') return;
      clearTimeout(timer);
      if (parsed.status === 'complete') {
        const hello = parsed.hello;
        queue.push({
          ts: new Date().toISOString(),
          ip: remoteIp,
          method: 'TLS',
          path: `tls://${hello.sni || remoteIp || 'clienthello'}`,
          host: hello.sni,
          userAgent: 'TLS ClientHello',
          headers: {},
          body: '',
          ja3: hello.ja3,
          ja4: hello.ja4,
          tlsVersion: hello.tlsVersion,
          cipher: hello.cipher,
          sensor: { id: SENSOR_ID, name: SENSOR_NAME, region: SENSOR_REGION },
        });
        if (queue.length > 500) queue = queue.slice(-500);
      }
      socket.end();
    });
    socket.on('error', () => clearTimeout(timer));
    socket.on('close', () => clearTimeout(timer));
  });
  tlsServer.listen(TLS_PORT, '0.0.0.0', () => {
    console.log(`[sensor] JA3/JA4 TLS sensor listening on :${TLS_PORT}`);
  });
}

setInterval(() => {
  void flush();
  void heartbeat();
}, FLUSH_MS);

async function shutdown() {
  console.log('[sensor] shutting down, flushing queue…');
  server.close();
  if (tlsServer) tlsServer.close();
  await flush();
  process.exit(0);
}

process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
