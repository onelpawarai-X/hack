import 'dotenv/config';
import express from 'express';
import { createServer } from 'node:http';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  buildDossierEml,
  clearSmtpConfig,
  getSmtpStatus,
  maybeAutoSendAbuseReport,
  sendAbuseReportForIp,
  sendForensicDossierForIp,
  setSmtpConfig,
  testSmtp,
} from './server/abuseMailer.ts';
import { buildAttackerDossier } from './server/attackerDossier.ts';
import { cameraRegistry } from './server/cameraRegistry.ts';
import { findOsmSurveillance } from './server/publicCameras.ts';
import { localCve } from './server/localCve.ts';
import { localIoc } from './server/localIoc.ts';
import {
  clearIntegrationConfig,
  getIntegrationStatus,
  notifyAttack,
  notifyBlockedIp,
  notifyShieldAlert,
  setAlertPolicy,
  setIntegrationConfig,
  testIntegration,
  type AlertChannel,
} from './server/alertDispatcher.ts';
import { attackSensor, clientIp } from './server/attackSensor.ts';
import {
  authStatus,
  buildOidcAuthorizationUrl,
  clearSessionCookie,
  completeOidcLogin,
  createAdminUser,
  createSession,
  destroySession,
  ensureEnvAdmin,
  hasAdminUser,
  requireAuth,
  sessionFromRequest,
  sessionTokenFromRequest,
  setSessionCookie,
  verifyCredentials,
} from './server/auth.ts';
import {
  countAttackEvents,
  dbStats,
  deleteSensorNode,
  listAttackEvents,
  listDeliveries,
  listWafSync,
  pruneAttackEvents,
  recordSensorHeartbeat,
} from './server/db.ts';
import { domainVerificationStore } from './server/domainVerification.ts';
import type { ThreatSeverity } from './src/types/cyber.ts';
import { defenseEngine, generateFirewallRulesForIp, lookupRdapIpAbuse } from './server/defenseEngine.ts';
import { analyzeImageBuffer } from './server/imageForensics.ts';
import { createRateLimitMiddleware, SlidingWindowRateLimiter } from './server/rateLimiter.ts';
import { attachRealtime, resolveScannerOrigin } from './server/realtime.ts';
import {
  agentCommand,
  getIngestToken,
  ingestRawSensorEvents,
  registerSensorNode,
  rotateIngestToken,
  sensorOverview,
  setSensorAutoBlock,
  setSensorEnabled,
  verifySensorToken,
} from './server/sensorNetwork.ts';
import {
  getWafStatus,
  isWafAutoPushEnabled,
  pushIpToWaf,
  removeIpFromWaf,
  setWafAutoPush,
  syncBlocklistToWaf,
} from './server/wafProviders.ts';
import { scanTargetOrWeb, traceAttackerIp } from './server/scanner.ts';
import { SECURITY_TOOLS, getSecurityTool } from './server/securityStack/catalog.ts';
import { buildSecurityToolConfig, writeSecurityToolConfigs } from './server/securityStack/configs.ts';
import {
  ingestSecurityStackPayload,
  ingestSecurityStackText,
} from './server/securityStack/ingest.ts';
import {
  getSecurityStackSnapshot,
  getSecurityToolLogs,
  restartSecurityTool,
  startSecurityTool,
  stopSecurityTool,
} from './server/securityStack/manager.ts';
import type { SecurityToolId } from './src/types/securityStack.ts';
import { threatMonitor } from './server/threatMonitor.ts';
import { startTlsFingerprintSensor, tlsSensorStatus } from './server/tlsSensor.ts';
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

const authRateLimiter = createRateLimitMiddleware(
  new SlidingWindowRateLimiter(10, 60_000),
  'authentication',
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function requestBaseUrl(req: import('express').Request): string {
  const proto =
    (typeof req.headers['x-forwarded-proto'] === 'string'
      ? req.headers['x-forwarded-proto'].split(',')[0]
      : req.protocol) || 'http';
  return `${proto}://${req.headers.host ?? 'localhost'}`;
}

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
  try {
    writeSecurityToolConfigs();
  } catch (err) {
    console.warn('[security-stack] config generation failed:', getErrorMessage(err));
  }
  ensureEnvAdmin();

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      monitorActive: true,
      realtime: true,
      timestamp: new Date().toISOString(),
    });
  });

  // Authentication and optional OIDC SSO. These routes must stay public.
  app.get('/api/auth/status', (req, res) => {
    return res.json(authStatus(req));
  });

  app.post('/api/auth/setup', authRateLimiter, (req, res) => {
    if (hasAdminUser()) {
      return res.status(409).json({ error: 'An administrator account already exists.' });
    }
    const password = String(req.body?.password ?? '');
    const username = String(req.body?.username ?? 'admin').trim() || 'admin';
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    try {
      const user = createAdminUser(username, password);
      const session = createSession(user, req);
      setSessionCookie(req, res, session.token, session.expiresAt);
      return res.status(201).json({ user });
    } catch (err) {
      return res.status(400).json({ error: getErrorMessage(err) });
    }
  });

  app.post('/api/auth/login', authRateLimiter, (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const password = String(req.body?.password ?? '');
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const user = verifyCredentials(username, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    const session = createSession(user, req);
    setSessionCookie(req, res, session.token, session.expiresAt);
    return res.json({ user });
  });

  app.post('/api/auth/logout', (req, res) => {
    destroySession(sessionTokenFromRequest(req));
    clearSessionCookie(res);
    return res.json({ ok: true });
  });

  app.get('/api/auth/me', requireAuth, (req, res) => {
    return res.json({ user: sessionFromRequest(req) });
  });

  app.get('/api/auth/oidc/start', async (_req, res) => {
    try {
      const url = await buildOidcAuthorizationUrl();
      return res.redirect(url);
    } catch (err) {
      return res.status(503).json({ error: getErrorMessage(err) });
    }
  });

  app.get('/api/auth/oidc/callback', async (req, res) => {
    const code = String(req.query.code ?? '');
    const state = String(req.query.state ?? '');
    if (!code || !state) {
      return res.status(400).json({ error: 'OIDC callback is missing code or state.' });
    }
    try {
      const user = await completeOidcLogin(code, state);
      const session = createSession(user, req);
      setSessionCookie(req, res, session.token, session.expiresAt);
      return res.redirect('/');
    } catch (err) {
      return res.status(401).json({ error: getErrorMessage(err) });
    }
  });

  // Distributed honeypot ingest. Authenticated by a per-deployment sensor token,
  // not by the operator session, so remote VPS agents can ship events.
  app.post('/api/sensors/ingest', (req, res) => {
    if (!verifySensorToken(req)) {
      return res.status(401).json({ error: 'Invalid sensor token.' });
    }
    const sensorId = String(req.body?.sensorId ?? '').trim();
    const events = Array.isArray(req.body?.events) ? req.body.events : [];
    if (!sensorId || events.length === 0) {
      return res.status(400).json({ error: 'sensorId and a non-empty events array are required.' });
    }
    const result = ingestRawSensorEvents(sensorId, events);
    return res.json({ accepted: result.accepted, blocked: result.blocked });
  });

  app.post('/api/sensors/heartbeat', (req, res) => {
    if (!verifySensorToken(req)) {
      return res.status(401).json({ error: 'Invalid sensor token.' });
    }
    const sensorId = String(req.body?.sensorId ?? '').trim();
    if (!sensorId) return res.status(400).json({ error: 'sensorId is required.' });
    registerSensorNode({
      id: sensorId,
      name: String(req.body?.name ?? sensorId),
      region: req.body?.region ? String(req.body.region) : undefined,
    });
    recordSensorHeartbeat(sensorId, 'online');
    return res.json({ ok: true, at: new Date().toISOString() });
  });

  // Every remaining API route requires an authenticated operator session.
  app.use('/api', (req, res, next) => {
    const stackToken = process.env.SENTINEL_STACK_INGEST_TOKEN?.trim();
    if (stackToken && req.path.startsWith('/security-stack/ingest/')) {
      const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
      const provided = String(req.headers['x-sentinel-stack-token'] ?? bearer ?? '');
      if (provided === stackToken) return next();
    }
    return requireAuth(req, res, next);
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

  // Forensic attacker dossier: native GeoIP + Team Cymru DNS + RIR WHOIS + local sensor evidence
  app.get('/api/attacker/:ip', async (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    try {
      const dossier = await buildAttackerDossier(ip);
      return res.json({ ...dossier, defended: defenseEngine.isIpBlocked(ip) });
    } catch (err) {
      return res.status(502).json({ error: getErrorMessage(err) });
    }
  });

  app.get('/api/attacker/:ip/report', async (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    try {
      const dossier = await buildAttackerDossier(ip);
      const format = String(req.query.format ?? 'txt');
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="sentinel-dossier-${ip}.json"`);
        return res.send(JSON.stringify(dossier, null, 2));
      }
      if (format === 'html') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="sentinel-dossier-${ip}.html"`);
        return res.send(dossier.reportHtml);
      }
      if (format === 'eml') {
        const from = getSmtpStatus().from || 'sentinel@localhost';
        const to = Array.isArray(req.query.to) ? req.query.to.map(String) : [];
        res.setHeader('Content-Type', 'message/rfc822');
        res.setHeader('Content-Disposition', `attachment; filename="sentinel-dossier-${ip}.eml"`);
        return res.send(buildDossierEml(dossier, from, to.length ? to : dossier.whois.abuseEmails));
      }
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="sentinel-dossier-${ip}.txt"`);
      return res.send(dossier.reportText);
    } catch (err) {
      return res.status(502).json({ error: getErrorMessage(err) });
    }
  });

  app.post('/api/attacker/:ip/email', async (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    const recipients = Array.isArray(req.body?.recipients)
      ? req.body.recipients.map((value: unknown) => String(value)).filter(Boolean)
      : undefined;
    try {
      const result = await sendForensicDossierForIp(ip, recipients);
      return res.status(result.ok ? 200 : 502).json({
        ok: result.ok,
        detail: result.detail,
        recipients: result.recipients,
        dossier: result.dossier,
      });
    } catch (err) {
      return res.status(502).json({ error: getErrorMessage(err) });
    }
  });

  // Local IOC and offline CVE stores. No remote API is called.
  app.get('/api/intel/local', (_req, res) => {
    return res.json({
      ioc: localIoc.stats(),
      cve: localCve.stats(),
      entries: localIoc.all().slice(0, 500),
    });
  });

  app.post('/api/intel/local', (req, res) => {
    const value = String(req.body?.value ?? '').trim();
    const tags = Array.isArray(req.body?.tags) ? req.body.tags.map(String) : [];
    const result = localIoc.add(value, tags);
    if (!result.ok) return res.status(400).json({ error: result.error });
    return res.json({ ok: true, entry: result.entry, stats: localIoc.stats() });
  });

  app.delete('/api/intel/local/:value', (req, res) => {
    const removed = localIoc.remove(decodeURIComponent(String(req.params.value ?? '')));
    return res.json({ removed, stats: localIoc.stats() });
  });

  app.post('/api/intel/reload', (_req, res) => {
    localIoc.reload();
    localCve.reload();
    cameraRegistry.reload();
    return res.json({ ok: true, ioc: localIoc.stats(), cve: localCve.stats() });
  });

  // Public camera registry. The server never scrapes or calls a camera API.
  app.get('/api/cameras', (_req, res) => {
    return res.json({ cameras: cameraRegistry.list() });
  });

  app.get('/api/cameras/nearby', (req, res) => {
    const lat = Number(req.query.lat);
    const lon = Number(req.query.lon);
    const radius = Number(req.query.radius ?? 10);
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      return res.status(400).json({ error: 'Valid lat and lon are required.' });
    }
    return res.json({
      cameras: cameraRegistry.nearby(lat, lon, Math.min(Math.max(radius, 0.1), 200)),
    });
  });

  // Real OpenStreetMap surveillance nodes near a coordinate. OSM map data is
  // public under ODbL; no private or residential camera feeds are fetched.
  app.get('/api/cameras/osm-nearby', async (req, res) => {
    const lat = Number(req.query.lat);
    const lon = Number(req.query.lon);
    const radius = Number(req.query.radius ?? 1.5);
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
      return res.status(400).json({ error: 'Valid lat and lon are required.' });
    }
    const result = await findOsmSurveillance(lat, lon, radius);
    return res.status(result.ok ? 200 : 502).json(result);
  });

  app.post('/api/cameras', (req, res) => {
    const result = cameraRegistry.add(req.body ?? {});
    if (!result.ok) return res.status(400).json({ error: result.error });
    return res.json({ ok: true, camera: result.camera });
  });

  app.post('/api/cameras/import', (req, res) => {
    const rows = Array.isArray(req.body?.cameras) ? req.body.cameras : [];
    const added = [];
    const errors: Array<{ index: number; error: string }> = [];
    for (let index = 0; index < rows.length; index += 1) {
      const result = cameraRegistry.add(rows[index] ?? {});
      if (result.ok && result.camera) added.push(result.camera);
      else errors.push({ index, error: result.error ?? 'invalid row' });
    }
    return res.json({ ok: errors.length === 0, added, errors });
  });

  app.delete('/api/cameras/:id', (req, res) => {
    const removed = cameraRegistry.remove(String(req.params.id ?? ''));
    return res.json({ removed });
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

  // ---- Control Center: distributed sensors ----
  app.get('/api/sensors', (req, res) => {
    return res.json(sensorOverview(requestBaseUrl(req)));
  });

  app.get('/api/sensors/token', (_req, res) => {
    return res.json({ token: getIngestToken() });
  });

  app.get('/api/sensors/agent-command', (req, res) => {
    const sensorId = String(req.query.id ?? 'vps-fra-1');
    const region = String(req.query.region ?? 'eu-central');
    return res.json({ command: agentCommand(requestBaseUrl(req), sensorId, region) });
  });

  app.post('/api/sensors', (req, res) => {
    const result = registerSensorNode({
      id: String(req.body?.id ?? ''),
      name: String(req.body?.name ?? ''),
      region: req.body?.region ? String(req.body.region) : undefined,
      url: req.body?.url ? String(req.body.url) : undefined,
    });
    if (!result.ok) return res.status(400).json({ error: result.error });
    return res.status(201).json(sensorOverview(requestBaseUrl(req)));
  });

  app.post('/api/sensors/rotate-token', (_req, res) => {
    try {
      const token = rotateIngestToken();
      return res.json({ token });
    } catch (err) {
      return res.status(409).json({ error: getErrorMessage(err) });
    }
  });

  app.post('/api/sensors/auto', (req, res) => {
    if (typeof req.body?.enabled !== 'boolean') {
      return res.status(400).json({ error: 'Boolean "enabled" field required.' });
    }
    setSensorAutoBlock(req.body.enabled);
    return res.json({ enabled: req.body.enabled });
  });

  app.post('/api/sensors/:id/enabled', (req, res) => {
    if (typeof req.body?.enabled !== 'boolean') {
      return res.status(400).json({ error: 'Boolean "enabled" field required.' });
    }
    const updated = setSensorEnabled(String(req.params.id ?? ''), req.body.enabled);
    if (!updated) return res.status(404).json({ error: 'Sensor not found.' });
    return res.json(sensorOverview(requestBaseUrl(req)));
  });

  app.delete('/api/sensors/:id', (req, res) => {
    const removed = deleteSensorNode(String(req.params.id ?? ''));
    return res.json({ removed, ...sensorOverview(requestBaseUrl(req)) });
  });

  // ---- Control Center: edge WAF providers ----
  app.get('/api/waf', (_req, res) => {
    return res.json({ providers: getWafStatus(), autoPush: isWafAutoPushEnabled() });
  });

  app.post('/api/waf/auto', (req, res) => {
    const enabled = req.body?.enabled !== false;
    setWafAutoPush(enabled);
    return res.json({ autoPush: enabled, providers: getWafStatus() });
  });

  app.post('/api/waf/sync', async (_req, res) => {
    const ips = defenseEngine.getState().blockedIps.map((entry) => entry.ip);
    const results = await syncBlocklistToWaf(ips);
    return res.json({ results, synced: ips.length, providers: getWafStatus() });
  });

  app.post('/api/waf/push', async (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    const results = await pushIpToWaf(ip);
    return res.json({ results });
  });

  app.delete('/api/waf/ip/:ip', async (req, res) => {
    const ip = String(req.params.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    const results = await removeIpFromWaf(ip);
    return res.json({ results });
  });

  app.get('/api/waf/log', (_req, res) => {
    return res.json({ log: listWafSync(80) });
  });

  // ---- Control Center: alert integrations ----
  app.get('/api/integrations', (_req, res) => {
    return res.json({ ...getIntegrationStatus(), smtp: getSmtpStatus() });
  });

  app.post('/api/integrations/policy', (req, res) => {
    const minSeverity = req.body?.minSeverity;
    if (
      minSeverity !== undefined &&
      !['CRITICAL', 'HIGH', 'ELEVATED', 'CLEAN'].includes(String(minSeverity))
    ) {
      return res.status(400).json({ error: 'Invalid minimum severity.' });
    }
    setAlertPolicy({
      minSeverity: minSeverity ? (String(minSeverity) as 'CRITICAL' | 'HIGH' | 'ELEVATED' | 'CLEAN') : undefined,
      notifyOnBlock: typeof req.body?.notifyOnBlock === 'boolean' ? req.body.notifyOnBlock : undefined,
    });
    return res.json(getIntegrationStatus());
  });

  app.post('/api/integrations/smtp', (req, res) => {
    const result = setSmtpConfig(req.body ?? {});
    if (!result.ok) return res.status(400).json({ error: result.error });
    return res.json(getSmtpStatus());
  });

  app.delete('/api/integrations/smtp', (_req, res) => {
    clearSmtpConfig();
    return res.json(getSmtpStatus());
  });

  app.post('/api/integrations/smtp/test', async (req, res) => {
    const to = String(req.body?.to ?? '').trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) {
      return res.status(400).json({ error: 'A valid recipient email is required.' });
    }
    return res.json(await testSmtp(to));
  });

  app.post('/api/integrations/:channel', (req, res) => {
    const channel = String(req.params.channel ?? '') as AlertChannel;
    if (!['slack', 'telegram', 'siem'].includes(channel)) {
      return res.status(400).json({ error: 'Unknown integration channel.' });
    }
    const result = setIntegrationConfig(channel, req.body ?? {});
    if (!result.ok) return res.status(400).json({ error: result.error });
    return res.json(getIntegrationStatus());
  });

  app.delete('/api/integrations/:channel', (req, res) => {
    const channel = String(req.params.channel ?? '') as AlertChannel;
    if (!['slack', 'telegram', 'siem'].includes(channel)) {
      return res.status(400).json({ error: 'Unknown integration channel.' });
    }
    clearIntegrationConfig(channel);
    return res.json(getIntegrationStatus());
  });

  app.post('/api/integrations/:channel/test', async (req, res) => {
    const channel = String(req.params.channel ?? '') as AlertChannel;
    if (!['slack', 'telegram', 'siem'].includes(channel)) {
      return res.status(400).json({ error: 'Unknown integration channel.' });
    }
    return res.json(await testIntegration(channel));
  });

  app.get('/api/deliveries', (_req, res) => {
    return res.json({ deliveries: listDeliveries(80) });
  });

  app.post('/api/abuse/send', async (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    if (!isValidIpv4(ip)) return res.status(400).json({ error: 'Valid IPv4 address required.' });
    const recipients = Array.isArray(req.body?.recipients)
      ? req.body.recipients.map((value: unknown) => String(value))
      : undefined;
    try {
      return res.json(await sendAbuseReportForIp(ip, recipients));
    } catch (err) {
      return res.status(502).json({ error: getErrorMessage(err) });
    }
  });

  // ---- Control Center: local event store ----
  app.get('/api/data/stats', (_req, res) => {
    return res.json({ ...dbStats(), totalEvents: countAttackEvents() });
  });

  app.get('/api/data/events', (req, res) => {
    const events = listAttackEvents({
      limit: Number(req.query.limit ?? 100),
      offset: Number(req.query.offset ?? 0),
      ip: req.query.ip ? String(req.query.ip) : undefined,
      source: req.query.source ? String(req.query.source) : undefined,
      category: req.query.category ? String(req.query.category) : undefined,
      since: req.query.since ? String(req.query.since) : undefined,
    });
    return res.json({ events });
  });

  app.post('/api/data/prune', (req, res) => {
    const days = Number(req.body?.days ?? 30);
    if (!Number.isFinite(days) || days < 1) {
      return res.status(400).json({ error: 'Retention days must be a positive number.' });
    }
    const deleted = pruneAttackEvents(days);
    return res.json({ deleted, stats: dbStats() });
  });

  app.get('/api/data/export', (req, res) => {
    const format = String(req.query.format ?? 'json');
    const events = listAttackEvents({ limit: 1000 });
    if (format === 'csv') {
      const header = [
        'id',
        'ts',
        'ip',
        'method',
        'path',
        'category',
        'severity',
        'action',
        'source',
        'asn',
        'subnet',
        'ja3',
        'tlsh',
        'detail',
      ];
      const escape = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
      const csv = [
        header.join(','),
        ...events.map((event) =>
          header.map((key) => escape((event as unknown as Record<string, unknown>)[key])).join(','),
        ),
      ].join('\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="sentinel-events.csv"');
      return res.send(csv);
    }
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="sentinel-events.json"');
    return res.send(JSON.stringify(events, null, 2));
  });

  app.get('/api/detection/config', (_req, res) => {
    return res.json(attackSensor.getDetectionConfig());
  });

  app.get('/api/system', (req, res) => {
    return res.json({
      uptimeSeconds: Math.floor(process.uptime()),
      node: process.version,
      pid: process.pid,
      memory: process.memoryUsage(),
      auth: authStatus(req),
      db: dbStats(),
      waf: getWafStatus(),
      integrations: getIntegrationStatus(),
      smtp: getSmtpStatus(),
      sensors: sensorOverview(requestBaseUrl(req)),
      tlsSensor: tlsSensorStatus(),
    });
  });

  const stackIngestAuth = (
    req: import('express').Request,
    res: import('express').Response,
    next: import('express').NextFunction,
  ) => {
    const expected = process.env.SENTINEL_STACK_INGEST_TOKEN?.trim();
    if (expected) {
      const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
      const provided = String(req.headers['x-sentinel-stack-token'] ?? bearer ?? '');
      if (provided !== expected) {
        return res.status(401).json({ error: 'Invalid security-stack ingest token.' });
      }
      return next();
    }
    if (sessionFromRequest(req)) return next();
    return res.status(401).json({
      error: 'Set SENTINEL_STACK_INGEST_TOKEN or authenticate before sending stack events.',
    });
  };

  app.get('/api/security-stack', requireAuth, async (_req, res) => {
    return res.json(await getSecurityStackSnapshot());
  });

  app.get('/api/security-stack/tools', requireAuth, (_req, res) => {
    return res.json({ tools: SECURITY_TOOLS });
  });

  app.post('/api/security-stack/configs', requireAuth, (_req, res) => {
    return res.json({ written: writeSecurityToolConfigs() });
  });

  app.get('/api/security-stack/:id/config', requireAuth, (req, res) => {
    const tool = getSecurityTool(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Unknown security tool.' });
    return res.json(buildSecurityToolConfig(tool.id));
  });

  app.get('/api/security-stack/:id/logs', requireAuth, async (req, res) => {
    const tool = getSecurityTool(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Unknown security tool.' });
    const tail = Number(req.query.tail ?? 80);
    return res.json({ toolId: tool.id, lines: await getSecurityToolLogs(tool.id, tail) });
  });

  app.post('/api/security-stack/:id/start', requireAuth, async (req, res) => {
    const tool = getSecurityTool(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Unknown security tool.' });
    return res.json(await startSecurityTool(tool.id));
  });

  app.post('/api/security-stack/:id/stop', requireAuth, async (req, res) => {
    const tool = getSecurityTool(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Unknown security tool.' });
    return res.json(await stopSecurityTool(tool.id));
  });

  app.post('/api/security-stack/:id/restart', requireAuth, async (req, res) => {
    const tool = getSecurityTool(req.params.id);
    if (!tool) return res.status(404).json({ error: 'Unknown security tool.' });
    return res.json(await restartSecurityTool(tool.id));
  });

  app.post(
    '/api/security-stack/ingest/:source',
    express.text({ type: ['application/x-ndjson', 'text/*'], limit: '20mb' }),
    stackIngestAuth,
    async (req, res) => {
      const source = req.params.source as SecurityToolId;
      if (!getSecurityTool(source)) {
        return res.status(404).json({ error: `Unknown ingest source: ${source}` });
      }
      try {
        const result =
          typeof req.body === 'string'
            ? await ingestSecurityStackText(source, req.body)
            : await ingestSecurityStackPayload(source, req.body);
        return res.json(result);
      } catch (err) {
        return res.status(400).json({ error: 'Invalid security-stack payload', details: getErrorMessage(err) });
      }
    },
  );

  app.post('/api/defense/block-ip', async (req, res) => {
    const ip = String(req.body?.ip ?? '').trim();
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
    const requestedSeverity = String(req.body?.severity ?? '').toUpperCase();
    const severity: ThreatSeverity | undefined = ['CRITICAL', 'HIGH', 'ELEVATED'].includes(
      requestedSeverity,
    )
      ? (requestedSeverity as ThreatSeverity)
      : undefined;
    if (!isValidIpv4(ip)) {
      return res.status(400).json({ error: 'Valid IPv4 address required.' });
    }
    try {
      const entry = await defenseEngine.defendAttackerIp(ip, reason, severity);
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
      if (shield.status === 'alert') void notifyShieldAlert(shield);
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

  defenseEngine.onBlock((entry) => {
    if (isWafAutoPushEnabled()) void pushIpToWaf(entry.ip);
    void notifyBlockedIp(entry);
    void maybeAutoSendAbuseReport(entry);
  });

  startTlsFingerprintSensor({ port: Number(process.env.SENTINEL_TLS_SENSOR_PORT) || 0 });

  attackSensor.setBroadcast((event, alert) => {
    io.emit('attack:event', event);
    if (alert && isValidIpv4(event.ip)) {
      io.emit('defense:alert', {
        event,
        blocked: true,
        firewallRules: generateFirewallRulesForIp(event.ip),
      });
    }
    void notifyAttack(event, Boolean(alert));
  });

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelGlobe Cyber Threat Monitor listening on http://localhost:${PORT}`);
    console.log('Realtime Socket.io scanning channel ready at /socket.io');
  });
}

startServer();
