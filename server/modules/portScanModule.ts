import net from 'node:net';
import tls from 'node:tls';
import type {
  PortScanFinding,
  PortScanReport,
  RiskLevel,
} from '../../src/types/cyber.ts';
import { ethicalProbeDelay } from '../rateLimiter.ts';
import { isPrivateOrReservedIp } from '../threatRules.ts';
import { resolveDnsRecord, type ScanModulePlugin } from './types.ts';

const SCAN_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 6379,
  8080, 8443, 27017,
];

const HTTP_PORTS = new Set([80, 8000, 8080, 8888, 3000, 5000]);
const TLS_PORTS = new Set([443, 8443, 993, 995]);

const SERVICE_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'Microsoft SQL Server',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'HTTP Alternate',
  8443: 'HTTPS Alternate',
  27017: 'MongoDB',
};

const RISKY_PORTS: Record<number, RiskLevel> = {
  21: 'High',
  23: 'High',
  445: 'High',
  1433: 'High',
  3306: 'High',
  3389: 'High',
  5432: 'High',
  6379: 'Critical',
  27017: 'Critical',
  22: 'Medium',
  25: 'Low',
  8080: 'Medium',
  8443: 'Low',
  80: 'Low',
  443: 'Info',
};

const BANNER_LIMIT = 220;

function sanitizeBanner(raw: string): string | undefined {
  const cleaned = raw
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, BANNER_LIMIT);
  return cleaned.length > 0 ? cleaned : undefined;
}

function probeTcp(host: string, port: number, timeoutMs = 1400): Promise<{
  open: boolean;
  banner?: string;
  latencyMs: number;
}> {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let settled = false;
    let buffer = '';
    const socket = new net.Socket();

    const finish = (open: boolean, banner?: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        open,
        banner: banner ? sanitizeBanner(banner) : undefined,
        latencyMs: Date.now() - startedAt,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      if (HTTP_PORTS.has(port)) {
        socket.write(
          `HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: SentinelGlobe-AuthorizedAudit/1.0\r\n\r\n`,
        );
      }
      setTimeout(() => finish(true, buffer), HTTP_PORTS.has(port) ? 750 : 400);
    });
    socket.on('data', (chunk) => {
      if (buffer.length < BANNER_LIMIT) {
        buffer += chunk.toString('utf8').slice(0, BANNER_LIMIT);
      }
    });
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

function probeTls(host: string, port: number, timeoutMs = 1600): Promise<string | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value?: string) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = tls.connect(
      {
        host,
        port,
        servername: net.isIP(host) === 0 ? host : undefined,
        rejectUnauthorized: false,
      },
      () => {
        const protocol = socket.getProtocol() ?? 'TLS';
        const cipher = socket.getCipher()?.name ?? 'unknown cipher';
        const cert = socket.getPeerCertificate();
        const subject = cert?.subject?.CN ? ` · CN=${cert.subject.CN}` : '';
        socket.end();
        done(`${protocol} · ${cipher}${subject}`);
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      done(undefined);
    });
    socket.once('error', () => {
      socket.destroy();
      done(undefined);
    });
  });
}

async function runPool<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>) {
  let cursor = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      await worker(items[index]);
    }
  });
  await Promise.all(runners);
}

export async function scanCommonPorts(
  host: string,
  onOpen?: (finding: PortScanFinding) => void,
): Promise<PortScanReport> {
  const startedAt = new Date().toISOString();
  const findings: PortScanFinding[] = [];

  await runPool(SCAN_PORTS, 8, async (port) => {
    const result = await probeTcp(host, port);
    if (!result.open) return;

    let banner = result.banner;
    if (TLS_PORTS.has(port)) {
      const tlsBanner = await probeTls(host, port);
      banner = tlsBanner ?? banner;
    }

    const finding: PortScanFinding = {
      port,
      state: 'open',
      service: SERVICE_NAMES[port] ?? 'unknown',
      banner,
      latencyMs: result.latencyMs,
      riskLevel: RISKY_PORTS[port] ?? 'Info',
    };
    findings.push(finding);
    onOpen?.(finding);
    await ethicalProbeDelay(60);
  });

  findings.sort((a, b) => a.port - b.port);

  return {
    host,
    method: 'tcp-connect',
    scannedPorts: SCAN_PORTS,
    openPorts: findings,
    serviceFingerprint: findings
      .map((item) => (item.banner ? `${item.service} ${item.banner}` : item.service))
      .filter(Boolean),
    startedAt,
    completedAt: new Date().toISOString(),
  };
}

export const portScanModule: ScanModulePlugin = {
  id: 'portScan',
  label: 'Real TCP Port & Service Banner Scan',
  isActive: true,
  supportsTargetType: (t) => t === 'ip' || t === 'domain' || t === 'url',
  async run(ctx) {
    if (!ctx.ownershipVerified) return;

    let targetIps: string[] = [];
    if (ctx.targetType === 'ip') {
      targetIps = [ctx.host];
    } else {
      const aRecords =
        ctx.dns.a.length > 0 ? ctx.dns.a : await resolveDnsRecord(ctx.host, 'A');
      targetIps = aRecords.filter((ip) => !isPrivateOrReservedIp(ip)).slice(0, 2);
    }

    if (targetIps.length === 0) {
      ctx.log('No public IPv4 address resolved for TCP port scanning', 'warn', 'portScan');
      return;
    }

    const reports: PortScanReport[] = [];
    for (const ip of targetIps) {
      ctx.log(`TCP connect scan starting against ${ip} (${SCAN_PORTS.length} ports)`, 'info', 'portScan');
      const report = await scanCommonPorts(ip, (finding) => {
        ctx.log(
          `${ip}:${finding.port}/tcp open · ${finding.service} · ${finding.riskLevel}${finding.banner ? ` · ${finding.banner}` : ''}`,
          finding.riskLevel === 'Critical' || finding.riskLevel === 'High' ? 'warn' : 'success',
          'portScan',
        );
      });
      reports.push(report);
    }

    const firstReport = reports[0];
    const byPort = new Map<number, PortScanFinding>();
    for (const report of reports) {
      for (const finding of report.openPorts) {
        const existing = byPort.get(finding.port);
        if (!existing || (finding.latencyMs ?? Infinity) < (existing.latencyMs ?? Infinity)) {
          byPort.set(finding.port, finding);
        }
      }
    }
    ctx.portScan = firstReport
      ? {
          ...firstReport,
          openPorts: [...byPort.values()].sort((a, b) => a.port - b.port),
          serviceFingerprint: [...new Set(reports.flatMap((item) => item.serviceFingerprint))],
          completedAt: reports[reports.length - 1].completedAt,
        }
      : null;
    const openCount = ctx.portScan?.openPorts.length ?? 0;
    ctx.log(
      `Port scan complete · ${openCount} open service${openCount === 1 ? '' : 's'} discovered`,
      openCount > 0 ? 'success' : 'info',
      'portScan',
    );
  },
};
