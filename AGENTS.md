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
- Frontend realtime state: `src/hooks/useScanSocket.ts`; lab UI: `src/components/LiveThreatMap.tsx`, `ScanProgressBar`, `LiveScanTerminal`, `DomainVerificationPanel`, `SeverityCharts`, `EthicalBanner`; translations in `src/i18n/labTranslations.ts`.

## Gotchas
- CARTO dark basemaps now return "API KEY REQUIRED" tiles. `LiveThreatMap` uses Esri `World_Dark_Gray_Base` tiles (`{z}/{y}/{x}` order).
- Recharts needs `react-is`; Vite 8/Rolldown fails the build without it.
- Tests use `node:test` via `tsx`; there is no Jest/Vitest setup.
- `package-lock.json` is untracked in this workspace; `bun.lock` is the committed lockfile.
