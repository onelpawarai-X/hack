import type { SecurityToolId } from '../../src/types/securityStack.ts';
import { SECURITY_TOOLS } from './catalog.ts';
import { getSecurityToolStatus, startSecurityTool } from './manager.ts';

const ENABLED = process.env.SENTINEL_AUTOSTART_STACK !== 'false';
const DEFAULT_TOOLS = SECURITY_TOOLS.filter((tool) => tool.deployment !== 'appliance')
  .map((tool) => tool.id)
  .join(',');
const TARGETS = (process.env.SENTINEL_AUTOSTART_TOOLS ?? DEFAULT_TOOLS)
  .split(',')
  .map((value) => value.trim())
  .filter((value): value is SecurityToolId => SECURITY_TOOLS.some((tool) => tool.id === value));

const RETRY_MS = Number(process.env.SENTINEL_STACK_RETRY_MS) || 5 * 60 * 1000;
const lastAttempt = new Map<SecurityToolId, number>();
let timer: NodeJS.Timeout | null = null;
let busy = false;

async function ensureOnce(): Promise<void> {
  if (busy) return;
  busy = true;
  try {
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
  setTimeout(() => void ensureOnce(), 8_000);
  timer = setInterval(() => void ensureOnce(), 60_000);
}
