import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { ensureDockerCli } from '../../scripts/ensure-docker-cli.mjs';
import { deleteConfig, getConfig, setConfig } from '../db.ts';

const execFileAsync = promisify(execFile);

export const CONFIG_DOCKER_HOST_KEY = 'security_stack_docker_host';

const FORBIDDEN_DOCKER_HOST_CHARS = /[\s;|&$`\\'"<>\u0000]/;

export function isExecutableFile(filePath: string): boolean {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return false;
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function bundledDockerRoots(): string[] {
  const roots = [
    process.env.SENTINEL_DOCKER_BIN_DIR?.trim(),
    path.resolve(process.cwd(), '.sentinel-docker'),
    path.resolve(os.tmpdir(), '.sentinel-docker'),
  ].filter((value): value is string => Boolean(value));
  return [...new Set(roots)];
}

export function findBinaryNamed(name: string, extraDirs: string[] = []): string | null {
  const terminalBin = path.resolve(process.cwd(), 'data', 'terminal', 'bin');
  const candidates: string[] = [];

  for (const dir of extraDirs) {
    if (dir) candidates.push(path.join(dir, name));
  }
  for (const root of bundledDockerRoots()) {
    candidates.push(path.join(root, 'bin', name));
  }
  for (const dir of (process.env.PATH ?? '').split(':')) {
    if (!dir) continue;
    if (path.resolve(dir) === terminalBin) continue;
    candidates.push(path.join(dir, name));
  }
  for (const sysDir of ['/usr/local/bin', '/usr/bin', '/bin']) {
    candidates.push(path.join(sysDir, name));
  }

  for (const candidate of candidates) {
    if (isExecutableFile(candidate)) return candidate;
  }
  return null;
}

export function findDockerBinary(extraDirs: string[] = []): string | null {
  return findBinaryNamed('docker', extraDirs);
}

export function findDockerdBinary(extraDirs: string[] = []): string | null {
  return findBinaryNamed('dockerd', extraDirs);
}

export function findCrunBinary(extraDirs: string[] = []): string | null {
  return findBinaryNamed('crun', extraDirs);
}

export function findBundledDockerConfigDir(): string | null {
  for (const root of bundledDockerRoots()) {
    const configDir = path.join(root, 'config');
    const plugin = path.join(configDir, 'cli-plugins', 'docker-compose');
    if (isExecutableFile(plugin)) return configDir;
  }
  return null;
}

export function hasComposePluginInstalled(): boolean {
  if (findBundledDockerConfigDir()) return true;
  const standardPaths = [
    path.join(os.homedir(), '.docker', 'cli-plugins', 'docker-compose'),
    '/usr/libexec/docker/cli-plugins/docker-compose',
    '/usr/local/lib/docker/cli-plugins/docker-compose',
    '/usr/lib/docker/cli-plugins/docker-compose',
  ];
  return standardPaths.some((candidate) => isExecutableFile(candidate));
}

export function resolveLocalDockerSocketPath(): string {
  const defaultSock = '/var/run/docker.sock';
  const fallbackSock = path.join(os.tmpdir(), '.sentinel-docker', 'docker.sock');
  if (fs.existsSync(defaultSock)) return defaultSock;
  if (fs.existsSync(fallbackSock)) return fallbackSock;
  try {
    fs.accessSync('/var/run', fs.constants.W_OK);
    return defaultSock;
  } catch {
    return fallbackSock;
  }
}

export function resolveBundledDaemonRuntimePaths(): {
  dataRoot: string;
  execRoot: string;
  pidFile: string;
  socketPath: string;
  logPath: string;
} {
  const base = path.join(os.tmpdir(), '.sentinel-docker');
  return {
    dataRoot: path.join(base, 'data'),
    execRoot: path.join(base, 'run'),
    pidFile: path.join(base, 'dockerd.pid'),
    socketPath: resolveLocalDockerSocketPath(),
    logPath: path.resolve(process.cwd(), 'security-stack', 'logs', 'dockerd.log'),
  };
}

export function validateDockerHost(
  raw: string,
): { ok: true; value: string } | { ok: false; error: string } {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) {
    return { ok: true, value: '' };
  }
  if (trimmed.length > 512) {
    return { ok: false, error: 'DOCKER_HOST value is too long.' };
  }
  if (FORBIDDEN_DOCKER_HOST_CHARS.test(trimmed)) {
    return { ok: false, error: 'DOCKER_HOST contains invalid whitespace or shell characters.' };
  }
  if (trimmed.startsWith('unix://')) {
    const sockPath = trimmed.slice('unix://'.length);
    if (!sockPath.startsWith('/') || sockPath.includes('..') || sockPath.length < 2) {
      return { ok: false, error: 'unix:// DOCKER_HOST must be a safe absolute socket path.' };
    }
    return { ok: true, value: trimmed };
  }
  if (trimmed.startsWith('tcp://') || trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    try {
      const normalized = trimmed.replace(/^tcp:\/\//, 'http://');
      const url = new URL(normalized);
      if (!url.hostname) {
        return { ok: false, error: 'DOCKER_HOST hostname is required.' };
      }
      if (url.port) {
        const portNum = Number(url.port);
        if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
          return { ok: false, error: 'DOCKER_HOST port must be between 1 and 65535.' };
        }
      }
      if (url.pathname && url.pathname !== '/') {
        return { ok: false, error: 'tcp:// DOCKER_HOST must not include a URL path.' };
      }
      return { ok: true, value: trimmed };
    } catch {
      return { ok: false, error: 'Invalid tcp:// DOCKER_HOST URL format.' };
    }
  }
  if (trimmed.startsWith('ssh://')) {
    const rest = trimmed.slice('ssh://'.length);
    if (!/^[a-zA-Z0-9._-]+(?:@[a-zA-Z0-9._-]+)?(?::\d{1,5})?$/.test(rest)) {
      return { ok: false, error: 'Invalid ssh:// DOCKER_HOST format (expected ssh://user@host[:port]).' };
    }
    return { ok: true, value: trimmed };
  }
  return {
    ok: false,
    error: 'DOCKER_HOST must start with tcp://, unix://, or ssh:// (or leave blank for local engine).',
  };
}

export function getConfiguredDockerHost(): string | null {
  try {
    const fromDb = getConfig(CONFIG_DOCKER_HOST_KEY);
    if (fromDb && fromDb.trim()) return fromDb.trim();
  } catch {
    // Ignore DB read issues if called before schema initialization.
  }
  const fromEnv = process.env.DOCKER_HOST?.trim();
  return fromEnv || null;
}

export function setConfiguredDockerHost(
  raw: string,
): { ok: true; dockerHost: string | null } | { ok: false; error: string } {
  const checked = validateDockerHost(raw);
  if (!checked.ok) return checked;
  if (!checked.value) {
    deleteConfig(CONFIG_DOCKER_HOST_KEY);
    return { ok: true, dockerHost: null };
  }
  setConfig(CONFIG_DOCKER_HOST_KEY, checked.value);
  return { ok: true, dockerHost: checked.value };
}

export function detectDefaultCaptureInterface(netClassDir = '/sys/class/net'): string {
  try {
    const entries = fs.readdirSync(netClassDir).filter((name) => name && name !== 'lo');
    if (entries.includes('eth0')) return 'eth0';
    for (const prefix of ['eth', 'ens', 'enp', 'wlan']) {
      const match = entries.filter((name) => name.startsWith(prefix)).sort();
      if (match.length > 0) return match[match.length - 1];
    }
    if (entries.length > 0) return entries.sort()[0];
  } catch {
    // Ignore sysfs read errors in non-Linux environments.
  }
  return 'eth0';
}

export function getDockerExecEnv(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const terminalBin = path.resolve(process.cwd(), 'data', 'terminal', 'bin');
  const bundledBinDirs = bundledDockerRoots().map((root) => path.join(root, 'bin'));
  const existingPathParts = (baseEnv.PATH ?? '')
    .split(':')
    .filter((entry) => entry && path.resolve(entry) !== terminalBin);

  const mergedPath = [...new Set([...bundledBinDirs, ...existingPathParts, '/usr/local/bin', '/usr/bin', '/bin'])].join(':');
  const env: NodeJS.ProcessEnv = {
    ...baseEnv,
    PATH: mergedPath,
  };

  if (!baseEnv.SENTINEL_CAPTURE_IFACE) {
    env.SENTINEL_CAPTURE_IFACE = detectDefaultCaptureInterface();
  }

  if (!baseEnv.DOCKER_CONFIG) {
    const bundledConfig = findBundledDockerConfigDir();
    if (bundledConfig) {
      env.DOCKER_CONFIG = bundledConfig;
    }
  }

  const remoteHost = getConfiguredDockerHost();
  if (remoteHost) {
    env.DOCKER_HOST = remoteHost;
  } else if (!baseEnv.DOCKER_HOST) {
    const localSock = resolveLocalDockerSocketPath();
    if (localSock !== '/var/run/docker.sock' && fs.existsSync(localSock)) {
      env.DOCKER_HOST = `unix://${localSock}`;
    }
  }

  return env;
}

export function detectServerlessSandbox(opts?: {
  procVersion?: string;
  hasDockerSock?: boolean;
  cgroupEntries?: string[];
  env?: NodeJS.ProcessEnv;
}): { isServerlessSandbox: boolean; reason?: string } {
  const env = opts?.env ?? process.env;
  let procVersion = opts?.procVersion ?? '';
  if (!procVersion) {
    try {
      procVersion = fs.readFileSync('/proc/version', 'utf8');
    } catch {
      procVersion = '';
    }
  }
  if (/gvisor/i.test(procVersion)) {
    return {
      isServerlessSandbox: true,
      reason: 'gVisor container kernel',
    };
  }

  const isCloudRun = Boolean(env.K_SERVICE || env.K_REVISION || env.CLOUD_RUN_JOB);
  if (isCloudRun) {
    return {
      isServerlessSandbox: true,
      reason: 'Cloud Run serverless container',
    };
  }

  const hasDockerSock = opts?.hasDockerSock ?? fs.existsSync('/var/run/docker.sock');
  if (hasDockerSock) {
    return { isServerlessSandbox: false };
  }

  let cgroupEntries = opts?.cgroupEntries;
  if (!cgroupEntries) {
    try {
      cgroupEntries = fs.readdirSync('/sys/fs/cgroup');
    } catch {
      cgroupEntries = [];
    }
  }
  const isContainer = fs.existsSync('/.dockerenv') || Boolean(env.container);
  if (isContainer && cgroupEntries.length === 0) {
    return {
      isServerlessSandbox: true,
      reason: 'Container sandbox without pre-mounted cgroups',
    };
  }

  return { isServerlessSandbox: false };
}

export async function prepareSandboxCgroups(): Promise<void> {
  if (typeof process.getuid === 'function' && process.getuid() !== 0) return;
  try {
    if (!fs.existsSync('/sys/fs/cgroup/devices/cgroup.procs')) {
      fs.mkdirSync('/sys/fs/cgroup', { recursive: true });
      await execFileAsync('mount', ['-t', 'tmpfs', '-o', 'uid=0,gid=0,mode=0755', 'cgroup', '/sys/fs/cgroup'], {
        timeout: 4000,
      }).catch(() => undefined);
    }
    for (const sub of ['cpu', 'cpuacct', 'cpuset', 'devices', 'memory', 'pids']) {
      const target = `/sys/fs/cgroup/${sub}`;
      fs.mkdirSync(target, { recursive: true });
      if (!fs.existsSync(path.join(target, 'cgroup.procs'))) {
        await execFileAsync('mount', ['-t', 'cgroup', '-o', sub, 'cgroup', target], {
          timeout: 4000,
        }).catch(() => undefined);
      }
    }
  } catch {
    // Non-fatal: crun uses --cgroup-manager=disabled in sandbox mode.
  }
}

export function buildSandboxComposeOverrideYaml(): string {
  const hostOverrideServices = [
    'wazuh-manager',
    'cowrie',
    'opencanary',
    'conpot',
    'beelzebub',
    'hfish',
  ];
  const lines = [
    '# Auto-generated override for bundled sandbox dockerd (--bridge=none)',
    'services:',
  ];
  for (const service of hostOverrideServices) {
    lines.push(`  ${service}:`);
    lines.push('    network_mode: host');
    lines.push('    ports: !reset []');
  }
  return `${lines.join('\n')}\n`;
}

export function ensureSandboxComposeOverride(): string {
  const overridePath = path.resolve(
    process.cwd(),
    'security-stack',
    'generated',
    'docker-compose.sandbox.yml',
  );
  fs.mkdirSync(path.dirname(overridePath), { recursive: true });
  const content = buildSandboxComposeOverrideYaml();
  if (!fs.existsSync(overridePath) || fs.readFileSync(overridePath, 'utf8') !== content) {
    fs.writeFileSync(overridePath, content, 'utf8');
  }
  return overridePath;
}

export async function probeComposeAvailable(): Promise<boolean> {
  const cli = findDockerBinary();
  if (!cli) return false;
  try {
    const { stdout } = await execFileAsync(cli, ['compose', 'version'], {
      env: getDockerExecEnv(),
      timeout: 5000,
    });
    return /docker compose/i.test(stdout);
  } catch {
    return false;
  }
}

export async function ensureBundledDockerCli(force = false): Promise<{
  ok: boolean;
  cliPath?: string;
  daemonPath?: string;
  crunPath?: string;
  composeAvailable?: boolean;
  detail: string;
}> {
  if (!force) {
    const existingCli = findDockerBinary();
    const existingDaemon = findDockerdBinary();
    if (existingCli && existingDaemon && hasComposePluginInstalled()) {
      const composeOk = await probeComposeAvailable();
      return {
        ok: true,
        cliPath: existingCli,
        daemonPath: existingDaemon,
        crunPath: findCrunBinary() ?? undefined,
        composeAvailable: composeOk,
        detail: `Docker Engine + CLI ready at ${existingCli}${composeOk ? ' with Compose v2' : ''}.`,
      };
    }
  }
  const res = await ensureDockerCli({ force });
  return {
    ok: res.ok,
    cliPath: res.cliPath,
    daemonPath: res.daemonPath,
    crunPath: res.crunPath,
    composeAvailable: res.composeAvailable,
    detail: res.detail,
  };
}
