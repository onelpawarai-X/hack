import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  ensureBundledDockerCli,
  findDockerdBinary,
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
    return {
      ok: true,
      detail: `Docker Engine ${before.version ?? ''} is already installed and running locally.`.trim(),
    };
  }

  // Install full static Docker bundle (docker + dockerd + containerd + crun + docker-compose) without apt/systemd
  let bundleNote = '';
  if (!before.cliInstalled || !before.composeAvailable || !findDockerdBinary()) {
    try {
      const bundleRes = await ensureBundledDockerCli();
      bundleNote = bundleRes.detail;
    } catch (error) {
      bundleNote = error instanceof Error ? error.message : 'Static bundle download failed';
    }
  }

  const remoteHost = getConfiguredDockerHost();
  if (!remoteHost && findDockerdBinary()) {
    const started = await startDockerDaemon();
    if (started.ok) {
      return { ok: true, detail: started.detail };
    }
    // If local bundled daemon failed cleanly (e.g. non-root environment), fall through to apt/sudo attempt below
    bundleNote = started.detail;
  }

  const afterCli = await getDockerAvailability();
  if (afterCli.ok) {
    return { ok: true, detail: `Docker ${afterCli.version ?? ''} is reachable. ${bundleNote}`.trim() };
  }

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const hasSudo = !isRoot && (await run('which', ['sudo'], 3000)).ok;
  const hasApt = (await run('which', ['apt-get'], 3000)).ok;
  if (!hasApt || (!isRoot && !hasSudo)) {
    return {
      ok: false,
      detail: bundleNote || 'Docker daemon could not be started locally.',
    };
  }

  const prefix = isRoot ? [] : ['-n'];
  const sudo = isRoot ? null : 'sudo';
  const update = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'update'])
    : await run('apt-get', ['update']);
  if (!update.ok) {
    return { ok: false, detail: `Docker apt-get update failed: ${update.out}` };
  }

  const install = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'install', '-y', 'docker.io', 'docker-compose-plugin'])
    : await run('apt-get', ['install', '-y', 'docker.io', 'docker-compose-plugin']);
  if (!install.ok) {
    return { ok: false, detail: `Docker package installation failed: ${install.out}` };
  }

  const started = await startDockerDaemon();
  return started.ok
    ? { ok: true, detail: `Docker Engine installed. ${started.detail}` }
    : { ok: false, detail: `Docker was installed but the daemon did not start. ${started.detail}` };
}
