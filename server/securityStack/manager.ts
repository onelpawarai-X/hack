import { execFile, spawn } from 'node:child_process';
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

import {
  detectServerlessSandbox,
  ensureBundledDockerCli,
  ensureSandboxComposeOverride,
  findCrunBinary,
  findDockerBinary,
  findDockerdBinary,
  getConfiguredDockerHost,
  getDockerExecEnv,
  prepareSandboxCgroups,
  probeComposeAvailable,
  resolveBundledDaemonRuntimePaths,
} from './dockerEnv.ts';

const execFileAsync = promisify(execFile);
const paths = getSecurityStackPaths();

type DockerAvailability = {
  ok: boolean;
  cliInstalled: boolean;
  daemonReachable: boolean;
  composeAvailable: boolean;
  cliPath?: string;
  remoteHost?: string | null;
  serverlessSandbox?: boolean;
  nativeFallbackActive?: boolean;
  version?: string;
  detail: string;
  hint?: string;
};

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function errorCode(error: unknown): string {
  return error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
}

async function probeDockerInfo(cliPath: string, useSudo: boolean): Promise<string> {
  const env = getDockerExecEnv();
  const { stdout } = useSudo
    ? await execFileAsync('sudo', ['-n', cliPath, 'info', '--format', '{{.ServerVersion}}'], {
        env,
        timeout: 5000,
      })
    : await execFileAsync(cliPath, ['info', '--format', '{{.ServerVersion}}'], {
        env,
        timeout: 5000,
      });
  return stdout.trim();
}

async function dockerAvailable(): Promise<DockerAvailability> {
  const cliPath = findDockerBinary();
  const remoteHost = getConfiguredDockerHost();
  const sandbox = detectServerlessSandbox();

  if (!cliPath) {
    return {
      ok: false,
      cliInstalled: false,
      daemonReachable: false,
      composeAvailable: false,
      remoteHost,
      serverlessSandbox: sandbox.isServerlessSandbox,
      nativeFallbackActive: sandbox.isServerlessSandbox,
      detail: 'Docker CLI is not installed on this host.',
      hint: 'Click "Setup Docker" to download the static Docker CLI + Compose v2 automatically.',
    };
  }

  const composeAvailable = await probeComposeAvailable();

  let directError: unknown = null;
  try {
    const version = await probeDockerInfo(cliPath, false);
    return {
      ok: true,
      cliInstalled: true,
      daemonReachable: true,
      composeAvailable,
      cliPath,
      remoteHost,
      serverlessSandbox: sandbox.isServerlessSandbox,
      nativeFallbackActive: false,
      version,
      detail: remoteHost
        ? `Remote Docker Engine reachable (${remoteHost}).`
        : 'Docker daemon reachable.',
    };
  } catch (error) {
    directError = error;
  }

  if (!remoteHost && (await hasBinary('sudo'))) {
    try {
      const version = await probeDockerInfo(cliPath, true);
      return {
        ok: true,
        cliInstalled: true,
        daemonReachable: true,
        composeAvailable,
        cliPath,
        remoteHost,
        serverlessSandbox: sandbox.isServerlessSandbox,
        nativeFallbackActive: false,
        version,
        detail: 'Docker daemon reachable via passwordless sudo.',
      };
    } catch {
      // Fall through to the actionable error below.
    }
  }

  const message = errorText(directError);
  const permissionDenied =
    errorCode(directError) === 'EACCES' || /permission denied|access is denied/i.test(message);
  if (permissionDenied) {
    return {
      ok: false,
      cliInstalled: true,
      daemonReachable: true,
      composeAvailable,
      cliPath,
      remoteHost,
      serverlessSandbox: sandbox.isServerlessSandbox,
      detail: 'Docker CLI is installed, but this user cannot access /var/run/docker.sock.',
      hint: 'Run: sudo usermod -aG docker $USER && newgrp docker. Then restart SentinelGlobe.',
    };
  }

  if (sandbox.isServerlessSandbox && !remoteHost) {
    const daemonReadyBinary = Boolean(findDockerdBinary());
    return {
      ok: false,
      cliInstalled: true,
      daemonReachable: false,
      composeAvailable,
      cliPath,
      remoteHost: null,
      serverlessSandbox: true,
      nativeFallbackActive: true,
      detail: daemonReadyBinary
        ? `Bundled Docker CLI + Engine (${cliPath}) is ready; local dockerd daemon is stopped or starting.`
        : `Docker CLI is installed at ${cliPath}; press "Setup Docker" to bundle local dockerd Engine.`,
      hint: daemonReadyBinary
        ? 'Press "Start Docker" (auto-starts in a few seconds).'
        : 'Press "Setup Docker" to download bundled dockerd + crun runtime.',
    };
  }

  if (remoteHost) {
    return {
      ok: false,
      cliInstalled: true,
      daemonReachable: false,
      composeAvailable,
      cliPath,
      remoteHost,
      serverlessSandbox: sandbox.isServerlessSandbox,
      nativeFallbackActive: sandbox.isServerlessSandbox,
      detail: `Docker CLI is installed, but remote Docker Engine (${remoteHost}) is unreachable: ${message}`,
      hint: 'Verify DOCKER_HOST URL, firewall rules, and that the remote dockerd TLS/TCP socket is listening.',
    };
  }

  if (/cannot connect|is the docker daemon running|connect: no such file|docker\.sock/i.test(message)) {
    return {
      ok: false,
      cliInstalled: true,
      daemonReachable: false,
      composeAvailable,
      cliPath,
      remoteHost,
      serverlessSandbox: false,
      detail: 'Docker CLI is installed, but the Docker daemon is not running.',
      hint: 'Press "Start Docker", or run: sudo systemctl start docker',
    };
  }

  return {
    ok: false,
    cliInstalled: true,
    daemonReachable: false,
    composeAvailable,
    cliPath,
    remoteHost,
    serverlessSandbox: sandbox.isServerlessSandbox,
    detail: `Docker CLI is installed, but the daemon is unavailable: ${message}`,
    hint: 'Press "Start Docker", or run: sudo systemctl start docker',
  };
}

async function docker(args: string[], timeout = 30_000): Promise<{ ok: boolean; out: string; err?: string }> {
  const cliPath = findDockerBinary();
  if (!cliPath) {
    return { ok: false, out: '', err: 'Docker CLI binary is not installed.' };
  }
  const env = getDockerExecEnv();
  try {
    const { stdout, stderr } = await execFileAsync(cliPath, args, { env, timeout });
    return { ok: true, out: stdout.trim(), err: stderr.trim() };
  } catch (error) {
    const message = errorText(error);
    const code = errorCode(error);
    if (!getConfiguredDockerHost() && (code === 'EACCES' || /permission denied/i.test(message))) {
      try {
        const { stdout, stderr } = await execFileAsync('sudo', ['-n', cliPath, ...args], {
          env,
          timeout,
        });
        return { ok: true, out: stdout.trim(), err: stderr.trim() };
      } catch (sudoError) {
        return {
          ok: false,
          out: '',
          err: `Docker socket permission denied and sudo fallback failed: ${errorText(sudoError)}`,
        };
      }
    }
    return { ok: false, out: '', err: message };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function startDockerDaemon(): Promise<{ ok: boolean; detail: string }> {
  const current = await dockerAvailable();
  if (current.ok) {
    return { ok: true, detail: `Docker ${current.version ?? ''} is already running.`.trim() };
  }
  if (current.remoteHost) {
    return {
      ok: false,
      detail: `Remote DOCKER_HOST (${current.remoteHost}) is unreachable. Clear remote host to use the built-in local Docker Engine.`,
    };
  }

  // Ensure full bundled Docker runtime (docker + dockerd + containerd + crun + compose)
  if (!findDockerBinary() || !findDockerdBinary()) {
    await ensureBundledDockerCli().catch(() => undefined);
  }

  const sandbox = detectServerlessSandbox();
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const hasSudo = !isRoot && (await hasBinary('sudo'));
  const run = async (command: string, args: string[], timeout = 30_000) => {
    try {
      const { stdout, stderr } = await execFileAsync(command, args, { timeout });
      return `${stdout}\n${stderr}`.trim();
    } catch (error) {
      return errorText(error);
    }
  };

  if (!sandbox.isServerlessSandbox) {
    for (const [command, args] of [
      ['systemctl', ['start', 'docker']],
      ['service', ['docker', 'start']],
    ] as const) {
      if (!(await hasBinary(command))) continue;
      if (isRoot) await run(command, [...args]);
      else if (hasSudo) await run('sudo', ['-n', command, ...args]);
      const after = await dockerAvailable();
      if (after.ok) {
        return { ok: true, detail: `Docker daemon started with ${command} ${args.join(' ')}.` };
      }
    }
  }

  const dockerdBin = findDockerdBinary();
  if (!dockerdBin) {
    return {
      ok: false,
      detail: 'Bundled dockerd binary is missing. Click "Setup Docker" to download the engine.',
    };
  }

  if (!isRoot && !hasSudo) {
    return {
      ok: false,
      detail: 'Starting local dockerd requires root or passwordless sudo privileges.',
    };
  }

  if (sandbox.isServerlessSandbox) {
    await prepareSandboxCgroups();
  }

  const rt = resolveBundledDaemonRuntimePaths();
  fs.mkdirSync(rt.dataRoot, { recursive: true });
  fs.mkdirSync(rt.execRoot, { recursive: true });
  fs.mkdirSync(path.dirname(rt.socketPath), { recursive: true });
  fs.mkdirSync(path.dirname(rt.logPath), { recursive: true });
  fs.rmSync(rt.pidFile, { force: true });
  fs.rmSync(rt.socketPath, { force: true });

  const hasIptables = await hasBinary('iptables');
  const crunBin = findCrunBinary();
  const useSandboxFlags = sandbox.isServerlessSandbox || !hasIptables;
  const daemonArgs = [
    `--data-root=${rt.dataRoot}`,
    `--exec-root=${rt.execRoot}`,
    `--pidfile=${rt.pidFile}`,
    `--host=unix://${rt.socketPath}`,
    ...(useSandboxFlags
      ? [
          '--storage-driver=vfs',
          '--iptables=false',
          '--ip-masq=false',
          '--ip6tables=false',
          '--bridge=none',
          ...(crunBin ? [`--add-runtime=crun=${crunBin}`, '--default-runtime=crun'] : []),
        ]
      : []),
  ];

  const fd = fs.openSync(rt.logPath, 'a');
  try {
    const child = spawn(isRoot ? dockerdBin : 'sudo', isRoot ? daemonArgs : ['-n', dockerdBin, ...daemonArgs], {
      detached: true,
      env: getDockerExecEnv(),
      stdio: ['ignore', fd, fd],
    });
    child.unref();
  } finally {
    fs.closeSync(fd);
  }

  for (let attempt = 0; attempt < 30; attempt += 1) {
    await sleep(500);
    const after = await dockerAvailable();
    if (after.ok) {
      return {
        ok: true,
        detail: `Docker Engine ${after.version ?? ''} started locally inside this host (${useSandboxFlags ? 'sandbox crun+vfs' : 'native'}).`.trim(),
      };
    }
  }

  let tailErr = '';
  try {
    const lines = fs.readFileSync(rt.logPath, 'utf8').trim().split(/\r?\n/);
    tailErr = lines.slice(-3).join(' | ');
  } catch {
    // Ignore log read errors.
  }

  return {
    ok: false,
    detail: `Docker daemon failed to become ready (${rt.logPath})${tailErr ? `: ${tailErr}` : ''}`,
  };
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
  if (binary === 'docker') {
    return Boolean(findDockerBinary());
  }
  if (binary === 'dockerd') {
    return Boolean(findDockerdBinary());
  }
  try {
    await execFileAsync('which', [binary], { env: getDockerExecEnv(), timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

function composeArgs(profile: string, command: string[]): string[] {
  const sandbox = detectServerlessSandbox();
  if (sandbox.isServerlessSandbox && !getConfiguredDockerHost()) {
    const overrideFile = ensureSandboxComposeOverride();
    return ['compose', '-f', paths.composeFile, '-f', overrideFile, '--profile', profile, ...command];
  }
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
        logTail:
          state === 'running' || state === 'error'
            ? await getSecurityToolLogs(id, state === 'error' ? 12 : 20)
            : undefined,
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
      : 'Docker Engine is starting or stopped; press Start Docker.',
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
      cliInstalled: dockerState.cliInstalled,
      daemonReachable: dockerState.daemonReachable,
      composeAvailable: dockerState.composeAvailable,
      cliPath: dockerState.cliPath,
      remoteHost: dockerState.remoteHost,
      serverlessSandbox: dockerState.serverlessSandbox,
      nativeFallbackActive: dockerState.nativeFallbackActive,
      version: dockerState.version,
      detail: dockerState.detail,
      hint: dockerState.hint,
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
    180_000,
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
  if (!result.ok) {
    const err = result.err ?? '';
    if (/ENOENT|not installed|permission denied|Cannot connect|docker\.sock|daemon/i.test(err)) {
      const state = await dockerAvailable();
      return [`${state.detail}${state.hint ? ` ${state.hint}` : ''}`];
    }
    if (/No such (object|container)|not found/i.test(err)) {
      return [`${tool.name} container is not running. Press Start first.`];
    }
    return [`log unavailable: ${err || 'docker error'}`];
  }
  const combined = `${result.out}\n${result.err ?? ''}`.trim();
  return combined ? combined.split(/\r?\n/).slice(-tail) : ['No log lines yet.'];
}

export async function getDockerAvailability() {
  return dockerAvailable();
}
