import dns from 'node:dns/promises';
import net from 'node:net';
import { isPrivateOrReservedIp, isValidIpv4 } from './threatRules.ts';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
]);

export function isBlockedIpv6(ip: string): boolean {
  const clean = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (clean === '::1' || clean === '::') return true;
  if (clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }
  if (clean.startsWith('::ffff:')) {
    const v4 = clean.slice(7);
    if (isValidIpv4(v4)) return isPrivateOrReservedIp(v4);
  }
  return false;
}

export async function assertSafePublicUrl(rawUrl: string): Promise<{
  url: URL;
  hostname: string;
}> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL provided for security check.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS protocols are permitted.');
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Target host is restricted (local/internal addresses are blocked).');
  }

  if (net.isIPv4(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new Error('Private, loopback, or reserved IPv4 addresses are blocked.');
    }
    return { url: parsed, hostname };
  }

  if (net.isIPv6(hostname)) {
    if (isBlockedIpv6(hostname)) {
      throw new Error('Private, loopback, or link-local IPv6 addresses are blocked.');
    }
    return { url: parsed, hostname };
  }

  // Resolve DNS addresses before connecting to defend against DNS rebinding / internal resolution
  try {
    const [v4s, v6s] = await Promise.all([
      dns.resolve4(hostname).catch(() => [] as string[]),
      dns.resolve6(hostname).catch(() => [] as string[]),
    ]);
    for (const ip of v4s) {
      if (isPrivateOrReservedIp(ip)) {
        throw new Error(`Target resolves to non-public IPv4 address (${ip}).`);
      }
    }
    for (const ip of v6s) {
      if (isBlockedIpv6(ip)) {
        throw new Error(`Target resolves to non-public IPv6 address (${ip}).`);
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('non-public')) {
      throw err;
    }
  }

  return { url: parsed, hostname };
}
