import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getConfig, insertWafSync, setConfig } from './db.ts';

export interface WafProviderStatus {
  id: 'local';
  name: string;
  configured: boolean;
  detail: string;
  env: string[];
}

export interface WafActionResult {
  provider: WafProviderStatus['id'];
  ok: boolean;
  detail: string;
}

const ENFORCEMENT_DIR = path.resolve(process.cwd(), 'data', 'enforcement');

function logWaf(provider: string, action: string, ip: string | undefined, status: string, detail: string) {
  try {
    insertWafSync({
      id: randomUUID(),
      ts: new Date().toISOString(),
      provider,
      action,
      ip,
      status,
      detail: detail.slice(0, 600),
    });
  } catch {
    // Logging must never break a live defense action.
  }
}

function writeBundle(ips: string[]) {
  fs.mkdirSync(ENFORCEMENT_DIR, { recursive: true });
  const nginx = [
    '# SentinelGlobe local edge deny-list',
    ...ips.map((ip) => `deny ${ip};`),
    '',
  ].join('\n');
  const nft = [
    '#!/usr/sbin/nft -f',
    '# SentinelGlobe local netfilter rules',
    'table inet sentinel {',
    '  set blocked { type ipv4_addr; flags interval; }',
    `  set blocked { ${ips.length ? ips.join(', ') : ''} }`,
    '  chain input { type filter hook input priority 0; policy accept; ip saddr @blocked drop; }',
    '}',
    '',
  ].join('\n');
  const iptables = [
    '#!/usr/bin/env bash',
    '# SentinelGlobe local netfilter rules',
    ...ips.map((ip) => `iptables -I INPUT -s ${ip} -j DROP`),
    '',
  ].join('\n');
  fs.writeFileSync(path.join(ENFORCEMENT_DIR, 'nginx-deny.conf'), nginx, 'utf8');
  fs.writeFileSync(path.join(ENFORCEMENT_DIR, 'sentinel.nft'), nft, 'utf8');
  fs.writeFileSync(path.join(ENFORCEMENT_DIR, 'iptables.sh'), iptables, 'utf8');
}

export function isWafAutoPushEnabled(): boolean {
  return getConfig('waf.autoPush') !== 'false';
}

export function setWafAutoPush(enabled: boolean): void {
  setConfig('waf.autoPush', String(enabled));
}

export function getWafStatus(): WafProviderStatus[] {
  return [
    {
      id: 'local',
      name: 'Local Firewall / Edge Blocklist',
      configured: true,
      detail:
        'No cloud API. Blocks are enforced by the local defense engine and exported as nginx, nftables and iptables rules.',
      env: [],
    },
  ];
}

export async function pushIpToWaf(ip: string): Promise<WafActionResult[]> {
  logWaf('local', 'block', ip, 'ok', 'Enforced in the local defense blocklist');
  return [{ provider: 'local', ok: true, detail: 'Enforced in the local defense blocklist.' }];
}

export async function removeIpFromWaf(ip: string): Promise<WafActionResult[]> {
  logWaf('local', 'unblock', ip, 'ok', 'Removed from the local defense blocklist');
  return [{ provider: 'local', ok: true, detail: 'Removed from the local defense blocklist.' }];
}

export async function syncBlocklistToWaf(ips: string[]): Promise<WafActionResult[]> {
  writeBundle(ips);
  logWaf('local', 'sync', undefined, 'ok', `Wrote ${ips.length} IP(s) to data/enforcement/`);
  return [
    {
      provider: 'local',
      ok: true,
      detail: `Wrote ${ips.length} IP(s) to data/enforcement/nginx-deny.conf, sentinel.nft and iptables.sh`,
    },
  ];
}
