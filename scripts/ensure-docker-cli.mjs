#!/usr/bin/env node
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const DEFAULT_DOCKER_VERSION = '28.1.1';
const COMPOSE_RELEASE_URL = 'https://github.com/docker/compose/releases/latest/download';

function mapArch(nodeArch) {
  if (nodeArch === 'x64') return 'x86_64';
  if (nodeArch === 'arm64') return 'aarch64';
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

async function downloadToFile(url, destPath, timeoutMs = 60_000) {
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
  throw new Error('No writable directory available for bundled Docker CLI.');
}

async function checkDockerRuns(binaryPath, dockerConfigDir) {
  try {
    const env = {
      ...process.env,
      ...(dockerConfigDir ? { DOCKER_CONFIG: dockerConfigDir } : {}),
    };
    const { stdout } = await execFileAsync(binaryPath, ['--version'], { env, timeout: 8000 });
    return Boolean(stdout.trim());
  } catch {
    return false;
  }
}

async function checkComposeRuns(binaryPath, dockerConfigDir) {
  try {
    const env = {
      ...process.env,
      ...(dockerConfigDir ? { DOCKER_CONFIG: dockerConfigDir } : {}),
    };
    const { stdout } = await execFileAsync(binaryPath, ['compose', 'version'], {
      env,
      timeout: 8000,
    });
    return /docker compose/i.test(stdout);
  } catch {
    return false;
  }
}

/**
 * @param {{ targetDir?: string; force?: boolean }} [opts]
 */
export async function ensureDockerCli({ targetDir, force = false } = {}) {
  if (process.platform !== 'linux') {
    return {
      ok: true,
      skipped: true,
      detail: `Skipped static Linux Docker CLI install on ${process.platform}.`,
    };
  }
  const arch = mapArch(process.arch);
  if (!arch) {
    return {
      ok: false,
      detail: `Unsupported CPU architecture for static Docker CLI: ${process.arch}`,
    };
  }

  const baseDir = resolveWritableTargetDir(targetDir);
  const binDir = path.join(baseDir, 'bin');
  const configDir = path.join(baseDir, 'config');
  const pluginDir = path.join(configDir, 'cli-plugins');
  const bundledDocker = path.join(binDir, 'docker');
  const bundledCompose = path.join(pluginDir, 'docker-compose');

  const systemDocker = findSystemBinary('docker');
  let cliPath = !force && isExecutable(bundledDocker) ? bundledDocker : systemDocker;
  let installedDocker = false;
  let installedCompose = false;

  if (!cliPath || !(await checkDockerRuns(cliPath))) {
    const tmpWork = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-docker-cli-'));
    try {
      const tgzPath = path.join(tmpWork, 'docker.tgz');
      const tarballUrl = await resolveLatestDockerTarball(arch);
      console.log(`[docker-cli] Downloading static Docker CLI (${arch}) from ${tarballUrl}...`);
      await downloadToFile(tarballUrl, tgzPath, 90_000);
      await execFileAsync(
        'tar',
        ['-xzf', tgzPath, '-C', tmpWork, '--strip-components=1', 'docker/docker'],
        { timeout: 45_000 },
      );
      const extracted = path.join(tmpWork, 'docker');
      if (!fs.existsSync(extracted)) {
        throw new Error('Extracted tarball did not contain docker/docker client binary.');
      }
      fs.copyFileSync(extracted, bundledDocker);
      fs.chmodSync(bundledDocker, 0o755);
      cliPath = bundledDocker;
      installedDocker = true;
      console.log(`[docker-cli] Installed static Docker CLI -> ${bundledDocker}`);
    } finally {
      fs.rmSync(tmpWork, { recursive: true, force: true });
    }
  }

  const activeConfigDir = isExecutable(bundledCompose) ? configDir : undefined;
  const composeOk = !force && (await checkComposeRuns(cliPath, activeConfigDir || configDir));
  if (!composeOk) {
    const tmpCompose = path.join(os.tmpdir(), `docker-compose-${process.pid}-${Date.now()}`);
    const composeUrl = `${COMPOSE_RELEASE_URL}/docker-compose-linux-${arch}`;
    try {
      console.log(`[docker-cli] Downloading static Docker Compose v2 (${arch})...`);
      await downloadToFile(composeUrl, tmpCompose, 90_000);
      fs.copyFileSync(tmpCompose, bundledCompose);
      fs.chmodSync(bundledCompose, 0o755);
      installedCompose = true;
      console.log(`[docker-cli] Installed Docker Compose plugin -> ${bundledCompose}`);

      // Also mirror into ~/.docker/cli-plugins when writable so standard docker invocations find it automatically
      try {
        const homePlugins = path.join(os.homedir(), '.docker', 'cli-plugins');
        fs.mkdirSync(homePlugins, { recursive: true });
        const homeCompose = path.join(homePlugins, 'docker-compose');
        fs.copyFileSync(bundledCompose, homeCompose);
        fs.chmodSync(homeCompose, 0o755);
      } catch {
        // Non-fatal if $HOME is read-only; DOCKER_CONFIG handles it.
      }
    } finally {
      fs.rmSync(tmpCompose, { force: true });
    }
  }

  const finalComposeOk = await checkComposeRuns(cliPath, configDir);
  return {
    ok: isExecutable(cliPath),
    cliPath,
    configDir,
    composeAvailable: finalComposeOk,
    installedDocker,
    installedCompose,
    detail: `Docker CLI ready at ${cliPath}${finalComposeOk ? ' with Compose v2' : ''}.`,
  };
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (invokedDirectly) {
  const strict = process.argv.includes('--strict');
  const force = process.argv.includes('--force');
  ensureDockerCli({ force })
    .then((result) => {
      console.log(`[docker-cli] ${result.detail}`);
      if (strict && !result.ok) process.exit(1);
    })
    .catch((error) => {
      const msg = error instanceof Error ? error.message : String(error);
      console.warn(`[docker-cli] Setup warning: ${msg}`);
      if (strict) process.exit(1);
    });
}
