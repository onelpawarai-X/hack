#!/usr/bin/env node
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const DEFAULT_DOCKER_VERSION = '29.10.0';
const DEFAULT_CRUN_VERSION = '1.31';
const COMPOSE_RELEASE_URL = 'https://github.com/docker/compose/releases/latest/download';

function mapArch(nodeArch) {
  if (nodeArch === 'x64') return { docker: 'x86_64', crun: 'amd64' };
  if (nodeArch === 'arm64') return { docker: 'aarch64', crun: 'arm64' };
  return null;
}

function isExecutable(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return false;
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findSystemBinary(name) {
  const pathEnv = process.env.PATH ?? '';
  const terminalBin = path.resolve(process.cwd(), 'data', 'terminal', 'bin');
  for (const dir of pathEnv.split(':')) {
    if (!dir) continue;
    if (path.resolve(dir) === terminalBin) continue;
    const candidate = path.join(dir, name);
    if (isExecutable(candidate)) return candidate;
  }
  for (const fallback of ['/usr/local/bin', '/usr/bin', '/bin']) {
    const candidate = path.join(fallback, name);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

async function resolveLatestDockerTarball(arch) {
  const indexUrl = `https://download.docker.com/linux/static/stable/${arch}/`;
  try {
    const response = await fetch(indexUrl, { signal: AbortSignal.timeout(12_000) });
    if (response.ok) {
      const html = await response.text();
      const matches = [...html.matchAll(/docker-(\d+)\.(\d+)\.(\d+)\.tgz/g)];
      if (matches.length > 0) {
        matches.sort((a, b) => {
          for (let i = 1; i <= 3; i += 1) {
            const diff = Number(a[i]) - Number(b[i]);
            if (diff !== 0) return diff;
          }
          return 0;
        });
        const best = matches[matches.length - 1];
        return `${indexUrl}${best[0]}`;
      }
    }
  } catch {
    // Fall back to known static release tarball URL.
  }
  return `${indexUrl}docker-${DEFAULT_DOCKER_VERSION}.tgz`;
}

async function resolveLatestCrunUrl(crunArch) {
  try {
    const response = await fetch('https://github.com/containers/crun/releases/latest', {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
      headers: { 'User-Agent': 'SentinelGlobe-DockerSetup/1.0' },
    });
    const loc = response.headers.get('location') ?? '';
    const match = loc.match(/\/tag\/v?(\d+\.\d+(?:\.\d+)?)/);
    if (match?.[1]) {
      return `https://github.com/containers/crun/releases/download/${match[1]}/crun-${match[1]}-linux-${crunArch}`;
    }
  } catch {
    // Fall back to pinned tested release.
  }
  return `https://github.com/containers/crun/releases/download/${DEFAULT_CRUN_VERSION}/crun-${DEFAULT_CRUN_VERSION}-linux-${crunArch}`;
}

async function downloadToFile(url, destPath, timeoutMs = 120_000) {
  const response = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'User-Agent': 'SentinelGlobe-DockerSetup/1.0' },
  });
  if (!response.ok || !response.body) {
    throw new Error(`HTTP ${response.status} downloading ${url}`);
  }
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  const readable = Readable.fromWeb(response.body);
  const writable = fs.createWriteStream(destPath);
  await pipeline(readable, writable);
}

function resolveWritableTargetDir(preferredDir) {
  const candidates = [
    preferredDir,
    process.env.SENTINEL_DOCKER_BIN_DIR,
    path.resolve(process.cwd(), '.sentinel-docker'),
    path.resolve(os.tmpdir(), '.sentinel-docker'),
  ].filter(Boolean);

  for (const dir of candidates) {
    try {
      const binDir = path.join(dir, 'bin');
      const pluginDir = path.join(dir, 'config', 'cli-plugins');
      fs.mkdirSync(binDir, { recursive: true });
      fs.mkdirSync(pluginDir, { recursive: true });
      const probe = path.join(dir, `.write-probe-${process.pid}`);
      fs.writeFileSync(probe, 'ok');
      fs.unlinkSync(probe);
      return dir;
    } catch {
      // Try next candidate directory.
    }
  }
  throw new Error('No writable directory available for bundled Docker runtime.');
}

async function checkBinaryVersion(binaryPath, args = ['--version'], dockerConfigDir) {
  try {
    const env = {
      ...process.env,
      ...(dockerConfigDir ? { DOCKER_CONFIG: dockerConfigDir } : {}),
    };
    const { stdout } = await execFileAsync(binaryPath, args, { env, timeout: 8000 });
    return Boolean(stdout.trim());
  } catch {
    return false;
  }
}

/**
 * Installs full static Docker Engine + CLI (docker, dockerd, containerd, runc),
 * static crun OCI runtime (configured with --cgroup-manager=disabled for container sandboxes),
 * and Docker Compose v2 CLI plugin without requiring root package managers or apt-get.
 *
 * @param {{ targetDir?: string; force?: boolean }} [opts]
 */
export async function ensureDockerCli({ targetDir, force = false } = {}) {
  if (process.platform !== 'linux') {
    return {
      ok: true,
      skipped: true,
      detail: `Skipped static Linux Docker runtime install on ${process.platform}.`,
    };
  }
  const arch = mapArch(process.arch);
  if (!arch) {
    return {
      ok: false,
      detail: `Unsupported CPU architecture for static Docker runtime: ${process.arch}`,
    };
  }

  const baseDir = resolveWritableTargetDir(targetDir);
  const binDir = path.join(baseDir, 'bin');
  const configDir = path.join(baseDir, 'config');
  const pluginDir = path.join(configDir, 'cli-plugins');

  const bundledDocker = path.join(binDir, 'docker');
  const bundledDockerd = path.join(binDir, 'dockerd');
  const bundledContainerd = path.join(binDir, 'containerd');
  const bundledCrunReal = path.join(binDir, 'crun-real');
  const bundledCrun = path.join(binDir, 'crun');
  const bundledCompose = path.join(pluginDir, 'docker-compose');

  let cliPath = isExecutable(bundledDocker) ? bundledDocker : findSystemBinary('docker');
  let daemonPath = isExecutable(bundledDockerd) ? bundledDockerd : findSystemBinary('dockerd');
  let installedEngine = false;
  let installedCompose = false;
  let installedCrun = false;

  const engineComplete =
    !force &&
    isExecutable(bundledDocker) &&
    isExecutable(bundledDockerd) &&
    isExecutable(bundledContainerd) &&
    (await checkBinaryVersion(bundledDocker, ['--version'])) &&
    (await checkBinaryVersion(bundledDockerd, ['--version']));

  if (!engineComplete) {
    const tmpWork = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-docker-engine-'));
    try {
      const tgzPath = path.join(tmpWork, 'docker.tgz');
      const tarballUrl = await resolveLatestDockerTarball(arch.docker);
      console.log(`[docker-bundle] Downloading static Docker Engine (${arch.docker}) from ${tarballUrl}...`);
      await downloadToFile(tarballUrl, tgzPath, 180_000);
      await execFileAsync('tar', ['-xzf', tgzPath, '-C', binDir, '--strip-components=1'], {
        timeout: 90_000,
      });
      for (const entry of fs.readdirSync(binDir)) {
        const full = path.join(binDir, entry);
        try {
          if (fs.statSync(full).isFile()) fs.chmodSync(full, 0o755);
        } catch {
          // Ignore chmod issue on non-regular entries.
        }
      }
      cliPath = bundledDocker;
      daemonPath = bundledDockerd;
      installedEngine = true;
      console.log(`[docker-bundle] Installed Docker CLI + Engine binaries -> ${binDir}`);
    } finally {
      fs.rmSync(tmpWork, { recursive: true, force: true });
    }
  }

  const crunComplete =
    !force &&
    isExecutable(bundledCrunReal) &&
    isExecutable(bundledCrun) &&
    (await checkBinaryVersion(bundledCrunReal, ['--version']));

  if (!crunComplete) {
    const tmpCrun = path.join(os.tmpdir(), `crun-${process.pid}-${Date.now()}`);
    const crunUrl = await resolveLatestCrunUrl(arch.crun);
    try {
      console.log(`[docker-bundle] Downloading static crun OCI runtime (${arch.crun})...`);
      await downloadToFile(crunUrl, tmpCrun, 90_000);
      fs.copyFileSync(tmpCrun, bundledCrunReal);
      fs.chmodSync(bundledCrunReal, 0o755);
      const wrapperBody = `#!/bin/sh\nexec "${bundledCrunReal}" --cgroup-manager=disabled "$@"\n`;
      fs.writeFileSync(bundledCrun, wrapperBody, { mode: 0o755 });
      fs.chmodSync(bundledCrun, 0o755);
      installedCrun = true;
      console.log(`[docker-bundle] Installed crun OCI runtime -> ${bundledCrun}`);
    } catch (err) {
      console.warn(
        `[docker-bundle] Optional crun download skipped: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      fs.rmSync(tmpCrun, { force: true });
    }
  }

  const composeComplete =
    !force &&
    isExecutable(bundledCompose) &&
    (await checkBinaryVersion(cliPath || bundledDocker, ['compose', 'version'], configDir));

  if (!composeComplete) {
    const tmpCompose = path.join(os.tmpdir(), `docker-compose-${process.pid}-${Date.now()}`);
    const composeUrl = `${COMPOSE_RELEASE_URL}/docker-compose-linux-${arch.docker}`;
    try {
      console.log(`[docker-bundle] Downloading static Docker Compose v2 (${arch.docker})...`);
      await downloadToFile(composeUrl, tmpCompose, 120_000);
      fs.copyFileSync(tmpCompose, bundledCompose);
      fs.chmodSync(bundledCompose, 0o755);
      installedCompose = true;
      console.log(`[docker-bundle] Installed Docker Compose plugin -> ${bundledCompose}`);

      try {
        const homePlugins = path.join(os.homedir(), '.docker', 'cli-plugins');
        fs.mkdirSync(homePlugins, { recursive: true });
        const homeCompose = path.join(homePlugins, 'docker-compose');
        fs.copyFileSync(bundledCompose, homeCompose);
        fs.chmodSync(homeCompose, 0o755);
      } catch {
        // Non-fatal if $HOME is read-only; DOCKER_CONFIG resolves it.
      }
    } finally {
      fs.rmSync(tmpCompose, { force: true });
    }
  }

  const finalCliOk = isExecutable(cliPath || bundledDocker);
  const finalDaemonOk = isExecutable(daemonPath || bundledDockerd);
  const finalComposeOk = await checkBinaryVersion(cliPath || bundledDocker, ['compose', 'version'], configDir);

  return {
    ok: finalCliOk && finalDaemonOk,
    cliPath: cliPath || bundledDocker,
    daemonPath: daemonPath || bundledDockerd,
    crunPath: isExecutable(bundledCrun) ? bundledCrun : undefined,
    configDir,
    composeAvailable: finalComposeOk,
    installedEngine,
    installedCrun,
    installedCompose,
    detail: `Docker Engine + CLI ready at ${binDir}${finalComposeOk ? ' with Compose v2' : ''}.`,
  };
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (invokedDirectly) {
  const strict = process.argv.includes('--strict');
  const force = process.argv.includes('--force');
  ensureDockerCli({ force })
    .then((result) => {
      console.log(`[docker-bundle] ${result.detail}`);
      if (strict && !result.ok) process.exit(1);
    })
    .catch((error) => {
      const msg = error instanceof Error ? error.message : String(error);
      console.warn(`[docker-bundle] Setup warning: ${msg}`);
      if (strict) process.exit(1);
    });
}
