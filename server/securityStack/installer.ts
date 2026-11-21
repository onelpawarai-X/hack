import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { getDockerAvailability } from './manager.ts';

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

  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const prefix = isRoot ? [] : ['-n'];
  const sudo = isRoot ? null : 'sudo';

  const update = sudo
    ? await run(sudo, [...prefix, 'apt-get', 'update'])
    : await run('apt-get', ['update']);
  if (!update.ok) {
    return {
      ok: false,
      detail: `Cannot run apt-get update. Install Docker manually with: curl -fsSL https://get.docker.com | sh (${update.out})`,
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

  if (sudo) {
    await run(sudo, [...prefix, 'systemctl', 'enable', '--now', 'docker'], 60_000);
  } else {
    await run('systemctl', ['enable', '--now', 'docker'], 60_000);
  }

  const after = await getDockerAvailability();
  return after.ok
    ? { ok: true, detail: `Docker ${after.version ?? ''} installed and reachable.` }
    : {
        ok: false,
        detail: `Docker was installed but the daemon is not reachable. Start it with: sudo dockerd (${after.detail})`,
      };
}
