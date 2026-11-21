import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getConfig, insertWafSync, setConfig } from './db.ts';

export interface WafProviderStatus {
  id: 'local' | 'cloudflare';
  name: string;
  configured: boolean;
  detail: string;
  env: string[];
}

function cloudflareConfig(): { token: string; zoneId: string } | null {
  const token = process.env.CLOUDFLARE_API_TOKEN?.trim();
  const zoneId = process.env.CLOUDFLARE_ZONE_ID?.trim();
  return token && zoneId ? { token, zoneId } : null;
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

export interface ShieldFirewallBundle {
  nginxDenyList: string;
  iptablesScript: string;
  dnsSinkholeHosts: string;
  cloudflareWafExpr: string;
}

export function deployShieldFirewallBundle(
  shieldId: string,
  host: string,
  bundle: ShieldFirewallBundle,
): { ok: boolean; detail: string; directory: string; files: string[] } {
  const safeId = shieldId.replace(/[^a-zA-Z0-9._-]/g, '_');
  const directory = path.join(ENFORCEMENT_DIR, 'shields', safeId);
  fs.mkdirSync(directory, { recursive: true });
  const readme = [
    `# SentinelGlobe shield rules for ${host}`,
    '',
    'These files are generated from the live defense state. Deploy them on the',
    'protected site, not on the SentinelGlobe control plane.',
    '',
    '- nginx-deny.conf: include inside the site server block.',
    '- iptables.sh: run as root on the protected host.',
    '- cloudflare-waf.txt: paste into a Cloudflare WAF custom rule expression.',
    '- dns-sinkhole.hosts: optional hosts-file sinkhole entries.',
    '- deploy.sh: reviewed helper that installs the Nginx snippet and optionally applies iptables.',
    '',
    `Generated: ${new Date().toISOString()}`,
  ].join('\n');
  const deployScript = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    '# Run this on the protected web server as root, after reviewing every rule.',
    '# It installs the Nginx deny-list snippet but does not edit your site config.',
    'install -d /etc/nginx/snippets',
    'install -m 0644 nginx-deny.conf /etc/nginx/snippets/sentinelglobe-deny.conf',
    'echo "Installed /etc/nginx/snippets/sentinelglobe-deny.conf"',
    'echo "Add this line inside the site server block, then run: nginx -t && systemctl reload nginx"',
    'echo "  include /etc/nginx/snippets/sentinelglobe-deny.conf;"',
    '',
    'if [ "${1:-}" = "--apply-iptables" ]; then',
    '  echo "Applying iptables rules..."',
    '  bash iptables.sh',
    '  echo "iptables rules applied. Persist them with your distribution firewall tool."',
    'else',
    '  echo "iptables not applied. Re-run with --apply-iptables after review."',
    'fi',
    '',
  ].join('\n');
  const files: Array<[string, string]> = [
    ['nginx-deny.conf', bundle.nginxDenyList],
    ['iptables.sh', bundle.iptablesScript],
    ['cloudflare-waf.txt', bundle.cloudflareWafExpr],
    ['dns-sinkhole.hosts', bundle.dnsSinkholeHosts],
    ['deploy.sh', deployScript],
    ['README.md', readme],
  ];
  for (const [name, content] of files) {
    fs.writeFileSync(path.join(directory, name), `${content.trim()}\n`, 'utf8');
  }
  logWaf('local', 'deploy-shield', host, 'ok', `Wrote ${files.length} files to ${directory}`);
  return {
    ok: true,
    detail: `Wrote ${files.length} files for ${host}`,
    directory,
    files: files.map(([name]) => path.join(directory, name)),
  };
}

export function isWafAutoPushEnabled(): boolean {
  return getConfig('waf.autoPush') !== 'false';
}

export function setWafAutoPush(enabled: boolean): void {
  setConfig('waf.autoPush', String(enabled));
}

export function getWafStatus(): WafProviderStatus[] {
  const cloudflare = cloudflareConfig();
  return [
    {
      id: 'local',
      name: 'Local Firewall / Edge Blocklist',
      configured: true,
      detail:
        'No cloud API. Blocks are enforced by the local defense engine and exported as nginx, nftables and iptables rules.',
      env: [],
    },
    {
      id: 'cloudflare',
      name: 'Cloudflare Firewall',
      configured: Boolean(cloudflare),
      detail: cloudflare
        ? 'Cloudflare API is configured. Blocked IPs are pushed as zone firewall access rules.'
        : 'Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID to push blocks to Cloudflare.',
      env: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ZONE_ID'],
    },
  ];
}

async function cloudflareRequest(
  path: string,
  init: RequestInit,
  config: { token: string; zoneId: string },
): Promise<{ ok: boolean; detail: string }> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${config.token}`,
      'Content-Type': 'application/json',
      ...(init.headers ?? {}),
    },
    signal: AbortSignal.timeout(10_000),
  });
  const payload = (await res.json().catch(() => ({}))) as {
    success?: boolean;
    errors?: Array<{ message?: string }>;
  };
  if (res.ok && payload.success !== false) return { ok: true, detail: 'Cloudflare accepted the rule.' };
  const detail = payload.errors?.map((entry) => entry.message).filter(Boolean).join('; ');
  return { ok: false, detail: detail || `Cloudflare HTTP ${res.status}` };
}

export async function pushIpToWaf(ip: string): Promise<WafActionResult[]> {
  logWaf('local', 'block', ip, 'ok', 'Enforced in the local defense blocklist');
  const results: WafActionResult[] = [
    { provider: 'local', ok: true, detail: 'Enforced in the local defense blocklist.' },
  ];
  const cloudflare = cloudflareConfig();
  if (cloudflare) {
    try {
      const result = await cloudflareRequest(
        `/zones/${encodeURIComponent(cloudflare.zoneId)}/firewall/access_rules/rules`,
        {
          method: 'POST',
          body: JSON.stringify({
            mode: 'block',
            configuration: { target: 'ip', value: ip },
            notes: 'SentinelGlobe automatic defense',
          }),
        },
        cloudflare,
      );
      logWaf('cloudflare', 'block', ip, result.ok ? 'ok' : 'error', result.detail);
      results.push({ provider: 'cloudflare', ...result });
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Cloudflare request failed';
      logWaf('cloudflare', 'block', ip, 'error', detail);
      results.push({ provider: 'cloudflare', ok: false, detail });
    }
  }
  return results;
}

export async function removeIpFromWaf(ip: string): Promise<WafActionResult[]> {
  logWaf('local', 'unblock', ip, 'ok', 'Removed from the local defense blocklist');
  const results: WafActionResult[] = [
    { provider: 'local', ok: true, detail: 'Removed from the local defense blocklist.' },
  ];
  const cloudflare = cloudflareConfig();
  if (cloudflare) {
    try {
      const list = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(cloudflare.zoneId)}/firewall/access_rules/rules?configuration.target=ip&configuration.value=${encodeURIComponent(ip)}&per_page=50`,
        {
          headers: { Authorization: `Bearer ${cloudflare.token}` },
          signal: AbortSignal.timeout(10_000),
        },
      );
      const payload = (await list.json().catch(() => ({}))) as {
        result?: Array<{ id?: string }>;
      };
      const ids = (payload.result ?? []).map((entry) => entry.id).filter(Boolean) as string[];
      let ok = true;
      let detail = ids.length ? `Deleted ${ids.length} Cloudflare rule(s).` : 'No Cloudflare rule found.';
      for (const id of ids) {
        const result = await cloudflareRequest(
          `/zones/${encodeURIComponent(cloudflare.zoneId)}/firewall/access_rules/rules/${encodeURIComponent(id)}`,
          { method: 'DELETE' },
          cloudflare,
        );
        ok = ok && result.ok;
        if (!result.ok) detail = result.detail;
      }
      logWaf('cloudflare', 'unblock', ip, ok ? 'ok' : 'error', detail);
      results.push({ provider: 'cloudflare', ok, detail });
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Cloudflare request failed';
      logWaf('cloudflare', 'unblock', ip, 'error', detail);
      results.push({ provider: 'cloudflare', ok: false, detail });
    }
  }
  return results;
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
