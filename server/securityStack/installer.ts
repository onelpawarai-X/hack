import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getDockerAvailability, startDockerDaemon } from './manager.ts';

const execFileAsync = promisify(execFile);

async function run(command: string, args: string[], timeout = 300_000): Promise<{ ok: boolean; out: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, { timeout });
    return { ok: true, out: `${stdout}\n${stderr}`.trim() };
  } catch (error) {
    return { ok: false, out: error instanceof Error ? error.message : 'command failed' };
  }
}

export async function installDockerEngine(): Promise<{ ok: boolean; detail: string }> {
  const current = await getDockerAvailability();
  if (current.ok) {
    return { ok: true, detail: `Docker ${current.version ?? ''} is already installed and reachable.` };
  }

  if (current.cliInstalled) {
    const started = await startDockerDaemon();
    return started.ok
      ? { ok: true, detail: started.detail }
      : { ok: false, detail: started.detail };
  }

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const hasSudo = !isRoot && (await run('which', ['sudo'], 3000)).ok;
  if (!isRoot && !hasSudo) {
    return {
      ok: false,
      detail:
        'Docker CLI is not installed, and this process has no root or sudo access. Install Docker Engine as root, then press "Start Docker".',
    };
  }

  const prefix = isRoot ? [] : ['-n'];
  const sudo = isRoot ? null : 'sudo';
  const update = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'update'])
    : await run('apt-get', ['update']);
  if (!update.ok) {
    return {
      ok: false,
      detail: `Docker CLI is missing and apt-get update failed. Install Docker Engine manually as root, then restart SentinelGlobe. (${update.out})`,
    };
  }

  const install = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'install', '-y', 'docker.io', 'docker-compose-plugin'])
    : await run('apt-get', ['install', '-y', 'docker.io', 'docker-compose-plugin']);
  if (!install.ok) {
    return {
      ok: false,
      detail: `Docker package installation failed. Install Docker Engine manually, then restart the app. (${install.out})`,
    };
  }

  const started = await startDockerDaemon();
  return started.ok
    ? { ok: true, detail: `Docker installed. ${started.detail}` }
    : { ok: false, detail: `Docker was installed but the daemon did not start. ${started.detail}` };
}
