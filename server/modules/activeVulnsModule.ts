import crypto from 'node:crypto';
import type { ActiveVulnFinding } from '../../src/types/cyber.ts';
import { ethicalProbeDelay } from '../rateLimiter.ts';
import { assertSafePublicUrl } from '../ssrfGuard.ts';
import type { ScanModulePlugin } from './types.ts';

const CSRF_TOKEN_NAME_REGEX =
  /(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|antiforgery|nonce)/i;

const SQL_ERROR_PATTERNS: Array<{ pattern: RegExp; dbHint: string }> = [
  { pattern: /SQLSTATE\[[0-9A-Z]+\]/i, dbHint: 'PDO / SQLSTATE diagnostic error' },
  { pattern: /You have an error in your SQL syntax/i, dbHint: 'MySQL syntax stack leak' },
  { pattern: /Warning:\s*pg_(?:query|exec|connect)\(/i, dbHint: 'PostgreSQL PHP warning' },
  { pattern: /Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after/i, dbHint: 'MSSQL diagnostic error' },
  { pattern: /SQLite3::query\(|sqlite3\.OperationalError/i, dbHint: 'SQLite diagnostic leak' },
  { pattern: /ORA-\d{4,5}:/i, dbHint: 'Oracle DB error code' },
];

export function inspectFormsForCsrf(html: string, endpointUrl: string): ActiveVulnFinding[] {
  if (!html) return [];
  const findings: ActiveVulnFinding[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  let index = 0;

  while ((match = formRegex.exec(html)) !== null && findings.length < 3) {
    index += 1;
    const attrs = match[1] || '';
    const inner = match[2] || '';
    const methodMatch = attrs.match(/\bmethod\s*=\s*["']?([a-z]+)/i);
    const method = (methodMatch?.[1] || 'GET').toUpperCase();
    if (method !== 'POST' && method !== 'PUT' && method !== 'DELETE') {
      continue;
    }

    const actionMatch = attrs.match(/\baction\s*=\s*["']?([^"'\s>]+)/i);
    const action = actionMatch?.[1] || endpointUrl;

    // Skip passive search forms cleanly if explicitly labeled search
    if (/search/i.test(action) && !/login|password|account|transfer|admin|delete|update/i.test(inner)) {
      continue;
    }

    const hiddenInputs = inner.match(/<input\b[^>]*type\s*=\s*["']?hidden["']?[^>]*>/gi) ?? [];
    const hasCsrfHidden = hiddenInputs.some((inp) => CSRF_TOKEN_NAME_REGEX.test(inp));
    if (!hasCsrfHidden) {
      findings.push({
        id: `csrf-missing-${index}`,
        category: 'Missing CSRF Protection',
        riskLevel: 'Medium',
        endpoint: action,
        evidence: `State-changing <form method="${method}"> contains no identifiable hidden anti-CSRF token field.`,
        owaspCategory: 'A01:2021 - Broken Access Control',
        remediation:
          'Generate and validate a cryptographically strong per-session or double-submit CSRF token on all POST/PUT/DELETE forms and enforce SameSite=Strict/Lax cookies.',
      });
    }
  }

  return findings;
}

export function inspectCanaryReflection(params: {
  canary: string;
  body: string;
  endpointUrl: string;
  parameter: string;
  hasCsp: boolean;
}): ActiveVulnFinding | null {
  if (!params.body || !params.body.includes(params.canary)) {
    return null;
  }

  return {
    id: `reflected-canary-${params.parameter}`,
    category: 'Reflected XSS',
    riskLevel: params.hasCsp ? 'Medium' : 'High',
    endpoint: params.endpointUrl,
    parameter: params.parameter,
    evidence: `Benign verification canary "${params.canary}" from query parameter ?${params.parameter}= reflected verbatim in HTML response${params.hasCsp ? ' (CSP present)' : ' without a Content-Security-Policy header'}.`,
    owaspCategory: 'A03:2021 - Injection',
    remediation:
      'Contextually HTML-encode all query parameters before rendering templates and enforce a strict Content-Security-Policy (script-src \'self\').',
  };
}

export function inspectSqlErrorLeak(params: {
  body: string;
  endpointUrl: string;
  parameter: string;
}): ActiveVulnFinding | null {
  if (!params.body) return null;
  for (const sig of SQL_ERROR_PATTERNS) {
    if (sig.pattern.test(params.body)) {
      return {
        id: `sqli-error-leak-${params.parameter}`,
        category: 'SQL Injection Indicator',
        riskLevel: 'High',
        endpoint: params.endpointUrl,
        parameter: params.parameter,
        evidence: `Application returned raw database diagnostic signature (${sig.dbHint}) during benign type-mismatch verification probe.`,
        owaspCategory: 'A03:2021 - Injection',
        remediation:
          'Use parameterized prepared statements for all database queries and disable verbose database error stack traces in production.',
      };
    }
  }
  return null;
}

export const activeVulnsModule: ScanModulePlugin = {
  id: 'activeVulns',
  label: 'Safe Active Vulnerability Audit (XSS / SQLi Indicator / CSRF)',
  isActive: true,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    if (!ctx.ownershipVerified) {
      return;
    }

    const baseUrlObj = new URL(ctx.probeUrl || `https://${ctx.host}/`);
    await assertSafePublicUrl(baseUrlObj.toString());

    const findings: ActiveVulnFinding[] = [];
    const hasCsp = Boolean(ctx.rawHttpHeaders['content-security-policy']);

    // 1. HTML Form CSRF Token Absence Check
    if (ctx.htmlSample) {
      findings.push(...inspectFormsForCsrf(ctx.htmlSample, baseUrlObj.toString()));
    }

    // 2. Non-destructive alphanumeric reflection canary check (never sends executable HTML/JS syntax)
    const canary = `sgverify${crypto.randomBytes(4).toString('hex')}`;
    const reflectionUrl = new URL(baseUrlObj.toString());
    reflectionUrl.searchParams.set('q', canary);

    const refController = new AbortController();
    const refTimer = setTimeout(() => refController.abort(), 4000);
    try {
      const res = await fetch(reflectionUrl.toString(), {
        method: 'GET',
        redirect: 'follow',
        signal: refController.signal,
        headers: { 'User-Agent': 'SentinelGlobe-AuthorizedAudit/1.0' },
      });
      const ct = (res.headers.get('content-type') || '').toLowerCase();
      if (ct.includes('text/html')) {
        const text = (await res.text()).slice(0, 64 * 1024);
        const hit = inspectCanaryReflection({
          canary,
          body: text,
          endpointUrl: reflectionUrl.pathname,
          parameter: 'q',
          hasCsp,
        });
        if (hit) findings.push(hit);
      } else {
        await res.body?.cancel().catch(() => {});
      }
    } catch {
      // ignore transient HTTP timeout
    } finally {
      clearTimeout(refTimer);
    }

    await ethicalProbeDelay(150);

    // 3. Safe Database Diagnostic Error Leak Check (benign type-mismatch query param without SQL commands)
    const diagUrl = new URL(baseUrlObj.toString());
    diagUrl.searchParams.set('id', 'sg_type_mismatch_check');
    const sqlController = new AbortController();
    const sqlTimer = setTimeout(() => sqlController.abort(), 4000);
    try {
      const res = await fetch(diagUrl.toString(), {
        method: 'GET',
        redirect: 'follow',
        signal: sqlController.signal,
        headers: { 'User-Agent': 'SentinelGlobe-AuthorizedAudit/1.0' },
      });
      const text = (await res.text()).slice(0, 32 * 1024);
      const hit = inspectSqlErrorLeak({
        body: text,
        endpointUrl: diagUrl.pathname,
        parameter: 'id',
      });
      if (hit) findings.push(hit);
    } catch {
      // ignore transient timeout
    } finally {
      clearTimeout(sqlTimer);
    }

    ctx.activeVulns = findings;
  },
};
