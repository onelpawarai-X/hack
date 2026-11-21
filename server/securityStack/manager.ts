import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type {
  SecurityStackSnapshot,
  SecurityToolId,
  SecurityToolStatus,
} from '../../src/types/securityStack.ts';
import { SECURITY_TOOLS, getSecurityTool, toolServiceName } from './catalog.ts';
import { db } from '../db.ts';
import { getSecurityStackPaths, writeSecurityToolConfigs } from './configs.ts';

const execFileAsync = promisify(execFile);
const paths = getSecurityStackPaths();

async function dockerAvailable(): Promise<{ ok: boolean; version?: string; detail: string }> {
  try {
    const { stdout } = await execFileAsync('docker', ['info', '--format', '{{.ServerVersion}}'], {
      timeout: 5000,
    });
    return { ok: true, version: stdout.trim(), detail: 'Docker daemon reachable.' };
  } catch (error) {
    try {
      const { stdout } = await execFileAsync(
        'sudo',
        ['-n', 'docker', 'info', '--format', '{{.ServerVersion}}'],
        { timeout: 5000 },
      );
      return {
        ok: true,
        version: stdout.trim(),
        detail: 'Docker daemon reachable via passwordless sudo.',
      };
    } catch (sudoError) {
      return {
        ok: false,
        detail:
          error instanceof Error && 'code' in error && error.code === 'ENOENT'
            ? 'Docker CLI is not installed.'
            : `Docker daemon unavailable: ${sudoError instanceof Error ? sudoError.message : 'unknown error'}`,
      };
    }
  }
}

async function docker(args: string[], timeout = 30_000): Promise<{ ok: boolean; out: string; err?: string }> {
  try {
    const { stdout, stderr } = await execFileAsync('docker', args, { timeout });
    return { ok: true, out: stdout.trim(), err: stderr.trim() };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'docker command failed';
    const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
    if (code === 'EACCES' || /permission denied/i.test(message)) {
      try {
        const { stdout, stderr } = await execFileAsync('sudo', ['-n', 'docker', ...args], { timeout });
        return { ok: true, out: stdout.trim(), err: stderr.trim() };
      } catch (sudoError) {
        return {
          ok: false,
          out: '',
          err: sudoError instanceof Error ? sudoError.message : 'sudo docker failed',
        };
      }
    }
    return { ok: false, out: '', err: message };
  }
}

function ensureLogPlaceholders(): void {
  const files = [
    'auth.log',
    'fail2ban.log',
    'nginx/access.log',
    'nginx/error.log',
    'suricata/fast.log',
    'suricata/eve.json',
    'zeek/notice.log',
    'cowrie/cowrie.json',
    'opencanary/opencanary.log',
    'conpot/conpot.json',
    'beelzebub/beelzebub.log',
  ];
  for (const relative of files) {
    const absolute = path.resolve(paths.logs, relative);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    if (!fs.existsSync(absolute)) fs.writeFileSync(absolute, '', 'utf8');
  }
}

async function hasBinary(binary: string): Promise<boolean> {
  try {
    await execFileAsync('which', [binary], { timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

function composeArgs(profile: string, command: string[]): string[] {
  return ['compose', '-f', paths.composeFile, '--profile', profile, ...command];
}

async function inspectContainer(id: SecurityToolId): Promise<{
  state: string;
  health?: string;
  image?: string;
} | null> {
  const name = toolServiceName(id);
  const { ok, out } = await docker([
    'inspect',
    name,
    '--format',
    '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Config.Image}}',
  ]);
  if (!ok || !out) return null;
  const [state, health, image] = out.split('|');
  return { state, health: health || undefined, image: image || undefined };
}

export async function getSecurityToolStatus(id: SecurityToolId): Promise<SecurityToolStatus> {
  const tool = getSecurityTool(id);
  if (!tool) throw new Error(`Unknown security tool: ${id}`);
  const checkedAt = new Date().toISOString();
  const base: SecurityToolStatus = {
    id: tool.id,
    name: tool.name,
    category: tool.category,
    deployment: tool.deployment,
    state: 'unavailable',
    detail: '',
    containerName: toolServiceName(id),
    image: tool.image,
    ports: tool.defaultPorts,
    lastCheckedAt: checkedAt,
  };

  if (tool.deployment === 'appliance') {
    return {
      ...base,
      state: 'host-managed',
      detail: `${tool.name} is a dedicated appliance/OS image. Deploy it on its own host and forward logs to /api/security-stack/ingest/${tool.id}.`,
    };
  }

  const dockerState = await dockerAvailable();
  if (dockerState.ok) {
    const container = await inspectContainer(id);
    if (container) {
      const state =
        container.state === 'running'
          ? 'running'
          : container.state === 'exited' || container.state === 'created'
            ? 'stopped'
            : 'error';
      return {
        ...base,
        state,
        health: container.health,
        image: container.image || tool.image,
        detail:
          state === 'running'
            ? `Container ${toolServiceName(id)} is ${container.state}${container.health ? ` (${container.health})` : ''}.`
            : `Container ${toolServiceName(id)} is ${container.state}.`,
        logTail: state === 'running' ? await getSecurityToolLogs(id, 20) : undefined,
      };
    }
  }

  if (tool.deployment === 'hybrid' && tool.hostBinary && (await hasBinary(tool.hostBinary))) {
    return {
      ...base,
      state: 'host-managed',
      detail: `${tool.hostBinary} is installed on the host; Docker container is not running.`,
    };
  }

  return {
    ...base,
    state: dockerState.ok ? 'stopped' : 'unavailable',
    detail: dockerState.ok
      ? `${tool.name} container is not running. Start it from the Security Stack panel.`
      : dockerState.detail,
  };
}

function stackEventCounts(): { ingested: number; blocked: number } {
  try {
    const placeholders = SECURITY_TOOLS.map(() => '?').join(',');
    const row = db
      .prepare(
        `SELECT COUNT(*) AS ingested,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked
         FROM attack_events WHERE sensor_id IN (${placeholders})`,
      )
      .get(...SECURITY_TOOLS.map((tool) => tool.id)) as
      | { ingested: number; blocked: number | null }
      | undefined;
    return { ingested: Number(row?.ingested ?? 0), blocked: Number(row?.blocked ?? 0) };
  } catch {
    return { ingested: 0, blocked: 0 };
  }
}

export async function getSecurityStackSnapshot(): Promise<SecurityStackSnapshot> {
  const dockerState = await dockerAvailable();
  const tools = await Promise.all(SECURITY_TOOLS.map((tool) => getSecurityToolStatus(tool.id)));
  const counts = stackEventCounts();
  const summary = {
    total: tools.length,
    running: tools.filter((tool) => tool.state === 'running').length,
    stopped: tools.filter((tool) => tool.state === 'stopped').length,
    unavailable: tools.filter((tool) => tool.state === 'unavailable').length,
    hostManaged: tools.filter((tool) => tool.state === 'host-managed').length,
    honeypots: tools.filter((tool) =>
      ['honeypot', 'deception'].includes(tool.category),
    ).length,
    detectors: tools.filter((tool) =>
      ['nids', 'hids-siem', 'log-response'].includes(tool.category),
    ).length,
    ingestedEvents: counts.ingested,
    blockedByStack: counts.blocked,
  };
  return {
    generatedAt: new Date().toISOString(),
    docker: {
      available: dockerState.ok,
      version: dockerState.version,
      detail: dockerState.detail,
    },
    tools,
    summary,
    ingest: {
      tokenConfigured: Boolean(process.env.SENTINEL_STACK_INGEST_TOKEN),
      endpoints: SECURITY_TOOLS.map((tool) => ({
        source: tool.id,
        path: `/api/security-stack/ingest/${tool.id}`,
        formats: tool.ingestFormats,
      })),
    },
  };
}

export async function startSecurityTool(
  id: SecurityToolId,
): Promise<{ ok: boolean; detail: string; status?: SecurityToolStatus }> {
  const tool = getSecurityTool(id);
  if (!tool) return { ok: false, detail: `Unknown tool: ${id}` };
  if (tool.deployment === 'appliance') {
    return {
      ok: false,
      detail: `${tool.name} is an appliance/OS image and cannot be started as a container. See ${tool.configPath}.`,
    };
  }
  const dockerState = await dockerAvailable();
  if (!dockerState.ok) {
    return { ok: false, detail: dockerState.detail };
  }
  writeSecurityToolConfigs(id);
  ensureLogPlaceholders();
  const logDir = path.resolve(paths.logs, id);
  fs.mkdirSync(logDir, { recursive: true });
  try {
    fs.chmodSync(logDir, 0o777);
  } catch {
    await execFileAsync('sudo', ['-n', 'chmod', '-R', '777', logDir], { timeout: 5000 }).catch(
      () => undefined,
    );
  }
  const profile = tool.profiles[0] ?? 'core';
  const service = tool.composeService ?? tool.id;
  const result = await docker(
    composeArgs(profile, ['up', '-d', '--no-deps', '--force-recreate', service]),
    120_000,
  );
  if (!result.ok) {
    return {
      ok: false,
      detail: `docker compose failed: ${result.err ?? result.out}`,
    };
  }
  return {
    ok: true,
    detail: `${tool.name} start requested with profile ${profile}.`,
    status: await getSecurityToolStatus(id),
  };
}

export async function stopSecurityTool(
  id: SecurityToolId,
): Promise<{ ok: boolean; detail: string; status?: SecurityToolStatus }> {
  const tool = getSecurityTool(id);
  if (!tool) return { ok: false, detail: `Unknown tool: ${id}` };
  if (tool.deployment === 'appliance') {
    return { ok: false, detail: `${tool.name} is appliance-managed; stop it on its dedicated host.` };
  }
  const result = await docker(['stop', toolServiceName(id)], 60_000);
  if (!result.ok) return { ok: false, detail: result.err ?? 'docker stop failed' };
  return { ok: true, detail: `${tool.name} stopped.`, status: await getSecurityToolStatus(id) };
}

export async function restartSecurityTool(
  id: SecurityToolId,
): Promise<{ ok: boolean; detail: string; status?: SecurityToolStatus }> {
  const stopped = await stopSecurityTool(id);
  if (!stopped.ok) return stopped;
  return startSecurityTool(id);
}

export async function getSecurityToolLogs(id: SecurityToolId, tail = 80): Promise<string[]> {
  const tool = getSecurityTool(id);
  if (!tool) return [`Unknown tool: ${id}`];
  const result = await docker(
    ['logs', '--tail', String(Math.min(Math.max(tail, 1), 500)), toolServiceName(id)],
    15_000,
  );
  if (!result.ok) return [`log unavailable: ${result.err ?? 'docker error'}`];
  const combined = `${result.out}\n${result.err ?? ''}`.trim();
  return combined ? combined.split(/\r?\n/).slice(-tail) : ['No log lines yet.'];
}

export async function getDockerAvailability() {
  return dockerAvailable();
}
