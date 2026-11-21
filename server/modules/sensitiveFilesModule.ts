import type { RiskLevel, SensitivePathFinding } from '../../src/types/cyber.ts';
import { ethicalProbeDelay } from '../rateLimiter.ts';
import { assertSafePublicUrl } from '../ssrfGuard.ts';
import type { ScanModulePlugin } from './types.ts';

interface SensitiveProbeSpec {
  path: string;
  riskLevel: RiskLevel;
  expectedSignature: RegExp;
  label: string;
}

const SENSITIVE_PATH_SPECS: SensitiveProbeSpec[] = [
  {
    path: '/.env',
    riskLevel: 'Critical',
    expectedSignature: /^[A-Z0-9_]{2,}=/m,
    label: 'Environment variable secrets file (.env)',
  },
  {
    path: '/.git/config',
    riskLevel: 'Critical',
    expectedSignature: /\[core\]|\[remote\s+"/i,
    label: 'Git repository configuration (.git/config)',
  },
  {
    path: '/.git/HEAD',
    riskLevel: 'High',
    expectedSignature: /^(ref:\s+refs\/|[0-9a-f]{40})/i,
    label: 'Git repository HEAD pointer (.git/HEAD)',
  },
  {
    path: '/backup.zip',
    riskLevel: 'Critical',
    expectedSignature: /^PK\x03\x04/i,
    label: 'Publicly downloadable backup archive (backup.zip)',
  },
  {
    path: '/db.sql',
    riskLevel: 'Critical',
    expectedSignature: /CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL|--\s+PostgreSQL/i,
    label: 'Exposed SQL database dump (db.sql)',
  },
  {
    path: '/wp-config.php.bak',
    riskLevel: 'Critical',
    expectedSignature: /DB_NAME|DB_PASSWORD|<\?php/i,
    label: 'WordPress configuration backup (wp-config.php.bak)',
  },
  {
    path: '/phpinfo.php',
    riskLevel: 'Medium',
    expectedSignature: /php\s+version|configuration\s+php\s+core/i,
    label: 'PHP diagnostic exposure (phpinfo.php)',
  },
  {
    path: '/server-status',
    riskLevel: 'Medium',
    expectedSignature: /Apache\s+Server\s+Status|Server\s+Uptime/i,
    label: 'Apache server-status diagnostics',
  },
  {
    path: '/admin/',
    riskLevel: 'Low',
    expectedSignature: /<form|login|password|dashboard|admin/i,
    label: 'Publicly reachable administrative panel (/admin/)',
  },
];

export function classifySensitiveResponse(params: {
  spec: SensitiveProbeSpec;
  status: number;
  contentType: string;
  bodySample: string;
}): SensitivePathFinding {
  const { spec, status, contentType, bodySample } = params;
  const ct = contentType.toLowerCase();
  const isHtmlFallback = ct.includes('text/html') && /<!doctype|<html/i.test(bodySample);

  if (status === 200) {
    // Reject SPA catch-all HTML responses for non-HTML artifacts (.env, .git, .sql, .zip)
    if (isHtmlFallback && spec.path !== '/admin/' && spec.path !== '/phpinfo.php' && spec.path !== '/server-status') {
      return {
        path: spec.path,
        status,
        riskLevel: 'Info',
        exposed: false,
        detail: `Returned HTML fallback (likely SPA catch-all rewrite, not exposed ${spec.path}).`,
      };
    }

    const matchedSig =
      spec.expectedSignature.test(bodySample) ||
      (spec.path === '/backup.zip' && (ct.includes('application/zip') || ct.includes('octet-stream')));

    if (matchedSig) {
      return {
        path: spec.path,
        status,
        riskLevel: spec.riskLevel,
        exposed: true,
        detail: `CONFIRMED: ${spec.label} returned HTTP 200 with verified content signature.`,
      };
    }

    return {
      path: spec.path,
      status,
      riskLevel: 'Info',
      exposed: false,
      detail: `Returned HTTP 200 without sensitive artifact signature.`,
    };
  }

  if (status === 403 && spec.path === '/admin/') {
    return {
      path: spec.path,
      status,
      riskLevel: 'Info',
      exposed: false,
      detail: 'Admin endpoint returned HTTP 403 Forbidden (access control enforced).',
    };
  }

  return {
    path: spec.path,
    status,
    riskLevel: 'Info',
    exposed: false,
    detail: `Protected (HTTP ${status})`,
  };
}

export const sensitiveFilesModule: ScanModulePlugin = {
  id: 'sensitiveFiles',
  label: 'Sensitive File & Directory Discovery',
  isActive: true,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    if (!ctx.ownershipVerified) {
      return;
    }

    const baseOrigin = `https://${ctx.host}`;
    await assertSafePublicUrl(baseOrigin);

    const results: SensitivePathFinding[] = [];
    for (const spec of SENSITIVE_PATH_SPECS) {
      const targetUrl = `${baseOrigin}${spec.path}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      try {
        const res = await fetch(targetUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'User-Agent': 'SentinelGlobe-AuthorizedAudit/1.0' },
        });
        const contentType = res.headers.get('content-type') || '';
        const text = res.status === 200 ? (await res.text()).slice(0, 4096) : '';
        if (res.status !== 200) {
          await res.body?.cancel().catch(() => {});
        }
        results.push(
          classifySensitiveResponse({
            spec,
            status: res.status,
            contentType,
            bodySample: text,
          }),
        );
      } catch {
        results.push({
          path: spec.path,
          status: 0,
          riskLevel: 'Info',
          exposed: false,
          detail: 'Request timed out or blocked by edge firewall',
        });
      } finally {
        clearTimeout(timer);
      }
      // Strict ethical pacing between probe requests
      await ethicalProbeDelay(120);
    }

    ctx.sensitivePaths = results;
  },
};
