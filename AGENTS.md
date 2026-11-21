# SentinelGlobe — Agent Notes

## Commands
- Dev server (Express + Vite middleware + Socket.IO): `npm run dev` (runs `tsx server.ts`, port 3000)
- Typecheck: `npm run lint` (`tsc --noEmit`)
- Build: `npm run build` (`vite build`)
- Tests: `npx tsx --test server/*.test.ts src/utils/*.test.ts`

## Architecture
- `server.ts` mounts REST APIs, the NDJSON streaming endpoint `/api/scan/stream`, and `attachRealtime(httpServer)`.
- `server/realtime.ts` owns Socket.IO events (`scan:start`, `scan:progress`, `scan:log`, `scan:geo`, `scan:result`, `scan:error`) and emits early target geolocation before deep modules finish.
- `server/orchestrator.ts` runs modules in waves. `normalizeSelectedModules()` defaults to all modules; active probes are gated by `domainVerificationStore.isDomainVerified()` and skipped with a reason until ownership is proven.
- `server/domainVerification.ts` performs real DNS TXT / HTTP file verification; never fake it.
- `server/modules/headersModule.ts` follows the full redirect chain (`redirect: 'follow'`, final URL/origin), audits the final response headers, and classifies cookies: session/auth cookies missing Secure/HttpOnly are Critical; tracking cookies such as `_ga`/`NID` are Info; SameSite-only gaps are High.
- `server/findingsBuilder.ts` detects Google-managed edges (`Server: gws` or AS15169/Google ASN) and downgrades missing-header findings to Info. Do not silently treat an upstream-managed header as an origin vulnerability.
- `server/scanner.ts` wraps every orchestrator result with `applyRiskScore()`; `server/findingsBuilder.ts` owns the deterministic score (`computeRiskScore`, weights Critical 40 / High 20 / Medium 8 / Low 3, verdict floor, cap 100). `TargetScannerPanel` renders the score breakdown, scan coverage, and full findings list, and exports JSON/PDF via `src/utils/reportExport.ts`. `headersModule` also performs a real OPTIONS probe for CORS reflection/credentials and advertised HTTP methods; risky CORS and TRACE/TRACK become findings.
- `server/techStack.ts` fingerprints servers/frameworks/CPEs from real headers, banners and HTML; `filterContextualCves()` keeps only CVEs whose CPE/product/family matches the observed stack and records `stackMatch` confidence.
- `server/tlsFingerprint.ts` parses a real TLS ClientHello into JA3/JA4/curves/signature algorithms/SNI/ALPN. `server/tlsSensor.ts` exposes the raw TCP sensor; enable it with `SENTINEL_TLS_SENSOR_PORT=<port>` (0/unset disables). `sensor-agent/agent.mjs` mirrors the parser and uses `SENSOR_TLS_PORT`.
- `server/wafProviders.ts` is local-only: it renders nginx/iptables artifacts under `data/enforcement/` and never calls a cloud WAF. `/api/waf` reports the local provider; `/api/waf/auto` toggles enforcement export.
- `server/alertDispatcher.ts` writes alerts to the local ledger; no Slack/Telegram/SIEM webhooks.
- `server/attackerDossier.ts` builds the forensic IP dossier (native geo/ASN/WHOIS, local IOC and sensor evidence, SHA-256 chain-of-custody). `server/abuseMailer.ts` sends it over operator SMTP; there is no Gmail API path.
- `server/localIoc.ts` / `server/localCve.ts` / `server/nativeIntel.ts` load operator-supplied offline IOC, CVE and intel mirrors. Empty mirrors are reported as empty, never filled with synthetic data.
- `server/publicIp.ts` discovers the host public IP over STUN; `server/cameraRegistry.ts` stores operator-registered public camera feeds under `data/cameras/`.
- `src/components/ThreatGlobe3D.tsx` renders the offline Natural Earth globe with `react-globe.gl`; `LiveThreatMap` toggles between it and Leaflet.
- `server/sensorNetwork.ts` owns distributed sensor registration, token rotation, heartbeat, per-node `enabled` state, and agent command generation.
- Frontend realtime state: `src/hooks/useScanSocket.ts`; lab UI: `src/components/LiveThreatMap.tsx`, `ScanProgressBar`, `LiveScanTerminal`, `DomainVerificationPanel`, `SeverityCharts`, `EthicalBanner`; translations in `src/i18n/labTranslations.ts`.

## Gotchas
- CARTO dark basemaps now return "API KEY REQUIRED" tiles. `LiveThreatMap` uses Esri `World_Dark_Gray_Base` tiles (`{z}/{y}/{x}` order).
- Recharts needs `react-is`; Vite 8/Rolldown fails the build without it.
- Tests use `node:test` via `tsx`; there is no Jest/Vitest setup.
- `package-lock.json` is untracked in this workspace; `bun.lock` is the committed lockfile.

## Security stack
- `security-stack/docker-compose.yml` runs real upstream images. Profiles: `core`, `nids`, `honeypot`, `siem`, `deception`, `ics`, `fleet`, `response`.
- `server/securityStack/manager.ts` starts/stops containers and writes `security-stack/generated/` configs. `writeSecurityToolConfigs()` also runs at server startup.
- Suricata config is mounted at `/tmp/sentinel/suricata.yaml`; mounting it under `/etc/suricata` makes the image entrypoint fail its recursive chown on a read-only file.
- OpenCanary config must be mounted at `/etc/opencanaryd/opencanary.conf` and use `"class": "PyLogger"`; `opencanary.logger.JsonLogger` does not exist upstream.
- Zeek site policy must only load scripts that exist in the image. `policy/misc/scan` was removed; SQLi detection is `policy/protocols/http/detect-sql-injection`.
- Ingest auth: `Authorization: Bearer $SENTINEL_STACK_INGEST_TOKEN`. NDJSON bodies need `Content-Type: application/x-ndjson`.
- Public camera lookup has two real sources: operator-imported streams in `data/cameras/cameras.json` and live OpenStreetMap surveillance nodes via `GET /api/cameras/osm-nearby`. The OSM parser drops indoor/doorbell/private/residential cameras and converts YouTube watch URLs to embeds.
