import type { SecurityToolId } from '../../src/types/securityStack.ts';
import { SECURITY_TOOLS } from './catalog.ts';
import { getDockerAvailability, getSecurityToolStatus, startDockerDaemon, startSecurityTool } from './manager.ts';

const ENABLED = process.env.SENTINEL_AUTOSTART_STACK !== 'false';
const DEFAULT_TOOLS = SECURITY_TOOLS.filter((tool) => tool.deployment !== 'appliance')
  .map((tool) => tool.id)
  .join(',');
const TARGETS = (process.env.SENTINEL_AUTOSTART_TOOLS ?? DEFAULT_TOOLS)
  .split(',')
  .map((value) => value.trim())
  .filter((value): value is SecurityToolId => SECURITY_TOOLS.some((tool) => tool.id === value));

const RETRY_MS = Number(process.env.SENTINEL_STACK_RETRY_MS) || 30 * 1000;
const DOCKER_RETRY_MS = Number(process.env.SENTINEL_DOCKER_RETRY_MS) || 30 * 1000;
const lastAttempt = new Map<SecurityToolId, number>();
let timer: NodeJS.Timeout | null = null;
let busy = false;
let lastDockerAttempt = 0;
let dockerReady = false;

async function ensureDocker(): Promise<boolean> {
  const availability = await getDockerAvailability().catch(() => null);
  if (!availability) return false;
  if (availability.ok) {
    if (!dockerReady) console.log('[security-stack] Docker is ready; auto-managing the security stack.');
    dockerReady = true;
    return true;
  }
  dockerReady = false;
  if (!availability.cliInstalled) {
    console.warn('[security-stack] Docker CLI is missing:', availability.detail);
    return false;
  }
  if (Date.now() - lastDockerAttempt < DOCKER_RETRY_MS) return false;
  lastDockerAttempt = Date.now();
  console.log('[security-stack] Docker daemon is not reachable; starting it automatically…');
  const started = await startDockerDaemon().catch((error) => ({
    ok: false,
    detail: error instanceof Error ? error.message : String(error),
  }));
  if (started.ok) {
    dockerReady = true;
    console.log('[security-stack]', started.detail);
    return true;
  }
  console.warn('[security-stack] Docker auto-start failed:', started.detail);
  return false;
}

async function ensureOnce(): Promise<void> {
  if (busy) return;
  busy = true;
  try {
    if (!(await ensureDocker())) return;
    for (const id of TARGETS) {
      const status = await getSecurityToolStatus(id).catch(() => null);
      if (!status || status.state === 'running' || status.state === 'host-managed') continue;
      const last = lastAttempt.get(id) ?? 0;
      if (Date.now() - last < RETRY_MS) continue;
      lastAttempt.set(id, Date.now());
      await startSecurityTool(id).catch(() => undefined);
    }
  } finally {
    busy = false;
  }
}

export function startSecurityStackSupervisor(): void {
  if (!ENABLED || timer || TARGETS.length === 0) return;
  setTimeout(() => void ensureOnce(), 1_500);
  timer = setInterval(() => void ensureOnce(), 30_000);
}
