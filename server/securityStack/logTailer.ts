import fs from 'node:fs';
import path from 'node:path';
import type { SecurityToolId } from '../../src/types/securityStack.ts';
import { getSecurityStackPaths } from './configs.ts';
import { ingestSecurityStackText } from './ingest.ts';

interface TailSource {
  source: SecurityToolId;
  file: string;
  onlyAlerts?: boolean;
}

const paths = getSecurityStackPaths();
const SOURCES: TailSource[] = [
  { source: 'suricata', file: path.join(paths.logs, 'suricata', 'eve.json'), onlyAlerts: true },
  { source: 'zeek', file: path.join(paths.logs, 'zeek', 'notice.log') },
  { source: 'zeek', file: path.join(paths.logs, 'zeek', 'weird.log') },
  { source: 'cowrie', file: path.join(paths.logs, 'cowrie', 'cowrie.json') },
  { source: 'opencanary', file: path.join(paths.logs, 'opencanary', 'opencanary.log') },
  { source: 'conpot', file: path.join(paths.logs, 'conpot', 'conpot.json') },
  { source: 'beelzebub', file: path.join(paths.logs, 'beelzebub', 'beelzebub.log') },
  { source: 'fail2ban', file: path.join(paths.logs, 'fail2ban.log') },
];

const offsets = new Map<string, number>();
let timer: NodeJS.Timeout | null = null;

function seedOffsets(): void {
  for (const item of SOURCES) {
    try {
      offsets.set(item.file, fs.statSync(item.file).size);
    } catch {
      offsets.set(item.file, 0);
    }
  }
}

async function readNewLines(item: TailSource): Promise<void> {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(item.file);
  } catch {
    return;
  }
  let offset = offsets.get(item.file) ?? 0;
  if (stat.size < offset) offset = 0;
  if (stat.size === offset) return;

  const length = Math.min(stat.size - offset, 512 * 1024);
  const buffer = Buffer.alloc(length);
  const fd = fs.openSync(item.file, 'r');
  try {
    fs.readSync(fd, buffer, 0, length, offset);
  } finally {
    fs.closeSync(fd);
  }
  offsets.set(item.file, offset + length);

  const lines = buffer.toString('utf8').split(/\r?\n/).filter((line) => line.trim());
  for (const line of lines.slice(-100)) {
    if (item.onlyAlerts && !line.includes('"event_type":"alert"')) continue;
    await ingestSecurityStackText(item.source, line).catch(() => undefined);
  }
}

async function tick(): Promise<void> {
  for (const item of SOURCES) {
    await readNewLines(item).catch(() => undefined);
  }
}

export function startSecurityStackLogTailer(): void {
  if (timer) return;
  seedOffsets();
  timer = setInterval(() => void tick(), 5_000);
}
