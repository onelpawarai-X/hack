import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface FirewallEnforcement {
  applied: boolean;
  detail: string;
  appliedAt?: string;
}

const ENFORCE = process.env.SENTINEL_ENFORCE_FIREWALL !== 'false';

function unsafeToBlock(ip: string): boolean {
  return ip.startsWith('127.') || ip === '0.0.0.0';
}

async function iptables(args: string[], timeout = 8_000): Promise<{ ok: boolean; err?: string }> {
  try {
    await execFileAsync('sudo', ['-n', 'iptables', ...args], { timeout });
    return { ok: true };
  } catch (error) {
    return { ok: false, err: error instanceof Error ? error.message : 'iptables failed' };
  }
}

async function ruleExists(chain: string, ip: string): Promise<boolean> {
  const result = await iptables(['-C', chain, '-s', ip, '-j', 'DROP']);
  return result.ok;
}

export async function applyIpBlock(ip: string): Promise<FirewallEnforcement> {
  if (!ENFORCE) {
    return { applied: false, detail: 'Host firewall enforcement is disabled by SENTINEL_ENFORCE_FIREWALL=false.' };
  }
  if (unsafeToBlock(ip)) {
    return { applied: false, detail: `Refusing to add a host firewall rule for protected address ${ip}.` };
  }

  for (const chain of ['INPUT', 'FORWARD']) {
    if (await ruleExists(chain, ip)) continue;
    const result = await iptables(['-I', chain, '-s', ip, '-j', 'DROP']);
    if (!result.ok) {
      return {
        applied: false,
        detail: `Could not apply ${chain} DROP for ${ip}: ${result.err ?? 'iptables failed'}. The in-app firewall still blocks this IP.`,
      };
    }
  }

  return {
    applied: true,
    detail: `Host firewall DROP rules applied for ${ip} in INPUT and FORWARD.`,
    appliedAt: new Date().toISOString(),
  };
}

export async function removeIpBlock(ip: string): Promise<FirewallEnforcement> {
  if (!ENFORCE || unsafeToBlock(ip)) {
    return { applied: false, detail: `No host firewall rule removed for ${ip}.` };
  }
  for (const chain of ['INPUT', 'FORWARD']) {
    while (await ruleExists(chain, ip)) {
      const result = await iptables(['-D', chain, '-s', ip, '-j', 'DROP']);
      if (!result.ok) {
        return {
          applied: false,
          detail: `Could not remove ${chain} DROP for ${ip}: ${result.err ?? 'iptables failed'}.`,
        };
      }
    }
  }
  return { applied: false, detail: `Host firewall DROP rules removed for ${ip}.` };
}
