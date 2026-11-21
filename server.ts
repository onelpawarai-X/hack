import 'dotenv/config';
import express from 'express';
import { createServer } from 'node:http';
import path from 'path';
import { fileURLToPath } from 'url';
import { attackSensor } from './server/attackSensor.ts';
import { domainVerificationStore } from './server/domainVerification.ts';
import { defenseEngine, generateFirewallRulesForIp, lookupRdapIpAbuse } from './server/defenseEngine.ts';
import { analyzeImageBuffer } from './server/imageForensics.ts';
import { createRateLimitMiddleware, SlidingWindowRateLimiter } from './server/rateLimiter.ts';
import { attachRealtime, resolveScannerOrigin } from './server/realtime.ts';
import { scanTargetOrWeb, traceAttackerIp } from './server/scanner.ts';
import { threatMonitor } from './server/threatMonitor.ts';
import { isValidIpv4 } from './server/threatRules.ts';
import type { ScanModuleId } from './src/types/cyber.ts';

const scanRateLimiter = createRateLimitMiddleware(
  new SlidingWindowRateLimiter(15, 60_000),
  'security scanning',
);

const verifyRateLimiter = createRateLimitMiddleware(
  new SlidingWindowRateLimiter(20, 60_000),
  'domain ownership verification',
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return 'Unexpected server error';
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '20mb' }));

  // Real active Express defense firewall middleware (blocks defended attacker IPs)
  app.use(defenseEngine.middleware);

  // Global attack sensor: real honeypot paths, payload signatures, DDoS rate shield.
  // It observes dashboard/API traffic but never blocks it; decoy paths are tarpitted.
  app.use(attackSensor.middleware);

  // Start continuous 24/7 global cyber threat monitor & shield watchdog loops
  threatMonitor.start();
  defenseEngine.startWatchdog();

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      monitorActive: true,
      realtime: true,
      timestamp: new Date().toISOString(),
    });
  });

  // Real public location of the scanning node (used to draw live attack lines on the map)
  app.get('/api/self/location', async (_req, res) => {
    try {
      const origin = await resolveScannerOrigin();
      if (!origin) {
        return res.status(503).json({ error: 'Scanner origin could not be geolocated.' });
      }
      return res.json(origin);
    } catch (err) {
      return res.status(502).json({
        error: 'Scanner origin lookup failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Live Radar & Continuous Global Threat Snapshot
  app.get('/api/radar', async (req, res) => {
    const forceRefresh = req.query.refresh === '1';
    try {
      const snapshot = await threatMonitor.getSnapshot(forceRefresh);
      return res.json(snapshot);
    } catch (err) {
      return res.status(502).json({
        error: 'Threat monitor sweep failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Domain Ownership Verification Status & Challenge Verification (Required before active scans)
  app.get('/api/verify-ownership/status', verifyRateLimiter, (req, res) => {
    const rawTarget = String(req.query.target ?? '').trim();
    if (rawTarget.length < 3) {
      return res.status(400).json({ error: 'Target domain or URL is required.' });
    }
    return res.json(domainVerificationStore.getStatus(rawTarget));
  });

  app.post('/api/verify-ownership/check', verifyRateLimiter, async (req, res) => {
    const rawTarget = String(req.body?.target ?? '').trim();
    const method = req.body?.method === 'http-file' ? 'http-file' : 'dns-txt';
    if (rawTarget.length < 3) {
      return res.status(400).json({ error: 'Target domain or URL is required.' });
    }
    try {
      const status = await domainVerificationStore.verifyDomainOwnership(rawTarget, method);
      return res.status(status.verified ? 200 : 422).json(status);
    } catch (err) {
      return res.status(502).json({
        error: 'Domain ownership verification check failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Deep Target / Website / Phishing Trap / Web Incident Scanner (Modular + Rate-Limited)
  app.post('/api/scan', scanRateLimiter, async (req, res) => {
    const rawTarget = req.body?.target;
    const rawModules = Array.isArray(req.body?.modules)
      ? (req.body.modules as ScanModuleId[])
      : undefined;
    if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length < 2) {
      return res.status(400).json({
        error: 'Please provide a valid URL, domain, IP address, or search target.',
      });
    }

    try {
      const report = await scanTargetOrWeb(rawTarget.trim(), rawModules);
      return res.json(report);
    } catch (err) {
      return res.status(502).json({
        error: 'Target security scan failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Real-time NDJSON Progress Streaming Modular Scan Endpoint
  app.post('/api/scan/stream', scanRateLimiter, async (req, res) => {
    const rawTarget = req.body?.target;
    const rawModules = Array.isArray(req.body?.modules)
      ? (req.body.modules as ScanModuleId[])
      : undefined;
    if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length < 2) {
      return res.status(400).json({
        error: 'Please provide a valid URL, domain, IP address, or search target.',
      });
    }

    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.flushHeaders?.();

    const writeLine = (payload: unknown) => {
      if (!res.writableEnded) {
        res.write(`${JSON.stringify(payload)}\n`);
      }
    };

    try {
      const report = await scanTargetOrWeb(
        rawTarget.trim(),
        rawModules,
        (evt) => {
          writeLine(evt);
        },
        (logEvent) => {
          writeLine({ type: 'log', ...logEvent });
        },
      );
      writeLine({ type: 'result', report });
    } catch (err) {
      writeLine({ type: 'error', error: getErrorMessage(err) });
    } finally {
      if (!res.writableEnded) res.end();
    }
  });

  // Real-time Attacker Origin, Physical Address & RDAP Abuse Contact Lookup
  app.get('/api/trace/:ip', async (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    if (!isValidIpv4(ip)) {
      return res.status(400).json({ error: 'Valid IPv4 address required.' });
    }
    try {
      const [node, rdap] = await Promise.all([
        traceAttackerIp(ip),
        lookupRdapIpAbuse(ip),
      ]);
      if (!node) {
        return res.status(404).json({ error: 'Attribution coordinates unavailable for this IP.' });
      }
      return res.json({
        ...node,
        cidr: rdap.cidr,
        abuseEmails: rdap.abuseEmails,
        defended: defenseEngine.isIpBlocked(ip),
      });
    } catch (err) {
      return res.status(502).json({
        error: 'IP attribution lookup failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Ultra-Deep Image Forensics: EXIF/XMP/IPTC/GPS, JPEG/PNG Zlib pipeline, Thumbnail, UTF-16 & Embedded IP Geolocation
  app.post('/api/forensics/image', async (req, res) => {
    const { filename, mimeType, base64 } = req.body ?? {};
    if (!base64 || typeof base64 !== 'string') {
      return res.status(400).json({ error: 'Image binary payload (base64) is required.' });
    }
    try {
      const cleanBase64 = base64.includes(',') ? base64.split(',')[1] : base64;
      const buffer = Buffer.from(cleanBase64, 'base64');
      if (buffer.length === 0 || buffer.length > 15 * 1024 * 1024) {
        return res.status(400).json({ error: 'Image must be between 1 byte and 15 MB.' });
      }
      const result = await analyzeImageBuffer(
        buffer,
        typeof filename === 'string' && filename.trim() ? filename.trim() : 'upload.bin',
        typeof mimeType === 'string' ? mimeType : 'application/octet-stream',
        traceAttackerIp,
      );
      return res.json(result);
    } catch (err) {
      return res.status(502).json({
        error: 'Image forensics extraction failed',
        details: getErrorMessage(err),
      });
    }
  });

  // Active Defense State, Attacker Blocklists, Phishing Sinkholes & Website Watchdog Shields
  app.get('/api/defense/state', (_req, res) => {
    return res.json(defenseEngine.getState());
  });

  // Global Defense Grid: real honeypot sensor events, feed intelligence and auto-defense state
  app.get('/api/defense/grid', async (_req, res) => {
    try {
      return res.json(await attackSensor.getSnapshot());
    } catch (err) {
      return res.status(502).json({
        error: 'Defense grid snapshot failed',
        details: getErrorMessage(err),
      });
    }
  });

  app.post('/api/defense/grid/auto', (req, res) => {
    if (typeof req.body?.enabled !== 'boolean') {
      return res.status(400).json({ error: 'Boolean "enabled" field required.' });
    }
    attackSensor.setAutoDefense(req.body.enabled);
    return res.json({ enabled: req.body.enabled });
  });

  app.post('/api/defense/grid/safe-ip', (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    if (!isValidIpv4(ip)) {
      return res.status(400).json({ error: 'Valid IPv4 address required.' });
    }
    const added = attackSensor.addSafeIp(ip);
    return res.json({ added, safeIps: attackSensor.getSnapshotSafeIps() });
  });

  app.delete('/api/defense/grid/safe-ip/:ip', (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    const removed = attackSensor.removeSafeIp(ip);
    return res.json({ removed, safeIps: attackSensor.getSnapshotSafeIps() });
  });

  app.post('/api/defense/grid/report', async (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    if (!isValidIpv4(ip)) {
      return res.status(400).json({ error: 'Valid IPv4 address required.' });
    }
    try {
      return res.json(await attackSensor.buildAbuseReport(ip));
    } catch (err) {
      return res.status(502).json({
        error: 'Abuse report generation failed',
        details: getErrorMessage(err),
      });
    }
  });

  app.post('/api/defense/grid/clear', (_req, res) => {
    attackSensor.clearEvents();
    return res.json({ cleared: true });
  });

  app.post('/api/defense/block-ip', async (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
    if (!isValidIpv4(ip)) {
      return res.status(400).json({ error: 'Valid IPv4 address required.' });
    }
    try {
      const entry = await defenseEngine.defendAttackerIp(ip, reason);
      return res.json({ entry, state: defenseEngine.getState() });
    } catch (err) {
      return res.status(502).json({
        error: 'Failed to activate attacker defense block',
        details: getErrorMessage(err),
      });
    }
  });

  app.delete('/api/defense/block-ip/:ip', (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    defenseEngine.unblockIp(ip);
    return res.json({ state: defenseEngine.getState() });
  });

  app.post('/api/defense/takedown-domain', async (req, res) => {
    const target = String(req.body?.target ?? '').trim();
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
    if (target.length < 3) {
      return res.status(400).json({ error: 'Valid domain or URL required.' });
    }
    try {
      const entry = await defenseEngine.takedownPhishingTarget(target, reason);
      return res.json({ entry, state: defenseEngine.getState() });
    } catch (err) {
      return res.status(502).json({
        error: 'Phishing domain sinkhole & takedown preparation failed',
        details: getErrorMessage(err),
      });
    }
  });

  app.delete('/api/defense/takedown-domain/:domain', (req, res) => {
    const domain = String(req.params.domain ?? '').trim();
    defenseEngine.removeBlockedDomain(domain);
    return res.json({ state: defenseEngine.getState() });
  });

  app.post('/api/defense/shield-target', async (req, res) => {
    const target = String(req.body?.target ?? '').trim();
    if (target.length < 3) {
      return res.status(400).json({ error: 'Valid domain or URL required to activate shield.' });
    }
    try {
      const shield = await defenseEngine.activateWebsiteShield(target);
      return res.json({ shield, state: defenseEngine.getState() });
    } catch (err) {
      return res.status(502).json({
        error: 'Failed to activate website defense shield',
        details: getErrorMessage(err),
      });
    }
  });

  app.post('/api/defense/recheck-shield/:id', async (req, res) => {
    const id = String(req.params.id ?? '').trim();
    try {
      const shield = await defenseEngine.recheckShieldById(id);
      if (!shield) {
        return res.status(404).json({ error: 'Shield ID not found.' });
      }
      return res.json({ shield, state: defenseEngine.getState() });
    } catch (err) {
      return res.status(502).json({
        error: 'Shield watchdog re-check failed',
        details: getErrorMessage(err),
      });
    }
  });

  app.delete('/api/defense/shield/:id', (req, res) => {
    const id = String(req.params.id ?? '').trim();
    defenseEngine.removeShield(id);
    return res.json({ state: defenseEngine.getState() });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  const httpServer = createServer(app);
  const io = attachRealtime(httpServer);

  attackSensor.setBroadcast((event, alert) => {
    io.emit('attack:event', event);
    if (alert && isValidIpv4(event.ip)) {
      io.emit('defense:alert', {
        event,
        blocked: true,
        firewallRules: generateFirewallRulesForIp(event.ip),
      });
    }
  });

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelGlobe Cyber Threat Monitor listening on http://localhost:${PORT}`);
    console.log('Realtime Socket.io scanning channel ready at /socket.io');
  });
}

startServer();
