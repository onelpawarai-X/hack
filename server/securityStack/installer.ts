import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  detectServerlessSandbox,
  ensureBundledDockerCli,
  getConfiguredDockerHost,
} from './dockerEnv.ts';
import { getDockerAvailability, startDockerDaemon } from './manager.ts';

const execFileAsync = promisify(execFile);

async function run(command: string, args: string[], timeout = 300_000): Promise<{ ok: boolean; out: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' },
      timeout,
    });
    return { ok: true, out: `${stdout}\n${stderr}`.trim() };
  } catch (error) {
    return { ok: false, out: error instanceof Error ? error.message : 'command failed' };
  }
}

export async function installDockerEngine(): Promise<{ ok: boolean; detail: string }> {
  const before = await getDockerAvailability();
  if (before.ok) {
    return { ok: true, detail: `Docker ${before.version ?? ''} is already installed and reachable.` };
  }

  // Always guarantee the static Docker CLI + Compose v2 plugin first (works even without root or apt-get)
  let cliBundleNote = '';
  if (!before.cliInstalled || !before.composeAvailable) {
    try {
      const cliResult = await ensureBundledDockerCli();
      cliBundleNote = cliResult.detail;
    } catch (error) {
      cliBundleNote = error instanceof Error ? error.message : 'Static CLI download failed';
    }
  }

  const afterCli = await getDockerAvailability();
  if (afterCli.ok) {
    return { ok: true, detail: `Docker ${afterCli.version ?? ''} is reachable. ${cliBundleNote}`.trim() };
  }

  const sandbox = detectServerlessSandbox();
  const remoteHost = getConfiguredDockerHost();
  if (sandbox.isServerlessSandbox && !remoteHost) {
    return {
      ok: afterCli.cliInstalled,
      detail: afterCli.cliInstalled
        ? `Docker CLI${afterCli.composeAvailable ? ' + Compose v2' : ''} installed at ${afterCli.cliPath}. Cloud Run's gVisor kernel does not permit nested dockerd daemons; connect a remote DOCKER_HOST or deploy on a Linux VPS. Built-in Node sensors remain active.`
        : `Static Docker CLI installation failed inside serverless container: ${cliBundleNote}`,
    };
  }

  if (afterCli.cliInstalled && !remoteHost) {
    const started = await startDockerDaemon();
    if (started.ok) {
      return { ok: true, detail: `${cliBundleNote} ${started.detail}`.trim() };
    }
  }

  // On real Debian/Ubuntu VPS hosts, install full docker.io daemon + compose plugin via apt-get
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const hasSudo = !isRoot && (await run('which', ['sudo'], 3000)).ok;
  const hasApt = (await run('which', ['apt-get'], 3000)).ok;
  if (!hasApt || (!isRoot && !hasSudo)) {
    return {
      ok: afterCli.cliInstalled,
      detail: afterCli.cliInstalled
        ? `Docker CLI is installed at ${afterCli.cliPath}, but full dockerd installation requires root/sudo apt-get on a Linux VPS (or connect a remote DOCKER_HOST).`
        : 'Docker CLI could not be downloaded and apt-get/root daemon installation is unavailable.',
    };
  }

  const prefix = isRoot ? [] : ['-n'];
  const sudo = isRoot ? null : 'sudo';
  const update = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'update'])
    : await run('apt-get', ['update']);
  if (!update.ok) {
    return {
      ok: afterCli.cliInstalled,
      detail: afterCli.cliInstalled
        ? `Docker CLI is ready (${afterCli.cliPath}), but apt-get daemon install failed: ${update.out}`
        : `Docker CLI setup failed and apt-get update failed: ${update.out}`,
    };
  }

  const install = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'install', '-y', 'docker.io', 'docker-compose-plugin'])
    : await run('apt-get', ['install', '-y', 'docker.io', 'docker-compose-plugin']);
  if (!install.ok) {
    return {
      ok: afterCli.cliInstalled,
      detail: afterCli.cliInstalled
        ? `Docker CLI is ready (${afterCli.cliPath}), but dockerd package installation failed: ${install.out}`
        : `Docker package installation failed: ${install.out}`,
    };
  }

  const started = await startDockerDaemon();
  return started.ok
    ? { ok: true, detail: `Docker Engine installed. ${started.detail}` }
    : { ok: false, detail: `Docker was installed but the daemon did not start. ${started.detail}` };
}
