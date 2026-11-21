import type { ScanModulePlugin } from './types.ts';

async function checkWellKnownPath(
  origin: string,
  path: string,
  pattern: RegExp,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    const res = await fetch(`${origin}${path}`, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'SentinelGlobe-SecurityAudit/1.0' },
    });
    const text = res.ok ? (await res.text()).slice(0, 32_768) : '';
    return res.ok && pattern.test(text);
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

interface SchemeAudit {
  ok: boolean;
  scheme: 'https' | 'http';
  status?: number;
  finalUrl?: string;
  server?: string;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
  cookieIssues: string[];
  securityTxtFound: boolean;
  robotsTxtFound: boolean;
  htmlSample: string;
  setCookies: string[];
  error?: string;
}

async function auditScheme(host: string, scheme: 'https' | 'http'): Promise<SchemeAudit> {
  const origin = `${scheme}://${host}`;
  const probeUrl = `${origin}/`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);

  try {
    const [res, securityTxtFound, robotsTxtFound] = await Promise.all([
      fetch(probeUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'SentinelGlobe-SecurityAudit/1.0' },
      }),
      checkWellKnownPath(origin, '/.well-known/security.txt', /contact:/i),
      checkWellKnownPath(origin, '/robots.txt', /user-agent|disallow|allow|sitemap/i),
    ]);

    const allHeaders: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      allHeaders[key.toLowerCase()] = value;
    });

    const setCookies =
      typeof res.headers.getSetCookie === 'function'
        ? res.headers.getSetCookie()
        : res.headers.get('set-cookie')
          ? [res.headers.get('set-cookie')!]
          : [];

    let htmlSample = '';
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('text/html') || contentType === '') {
      try {
        htmlSample = (await res.text()).slice(0, 128 * 1024);
      } catch {
        htmlSample = '';
      }
    } else {
      await res.body?.cancel().catch(() => {});
    }

    const headers: Record<string, string> = {};
    const wanted = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
      'server',
      'x-powered-by',
    ];
    for (const h of wanted) {
      if (allHeaders[h]) headers[h] = allHeaders[h];
    }

    const coreSecurity = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
    ];
    const missingSecurityHeaders = coreSecurity.filter((h) => !headers[h]);

    const cookieIssues: string[] = [];
    for (const rawCookie of setCookies.slice(0, 5)) {
      const lower = rawCookie.toLowerCase();
      const name = rawCookie.split('=')[0]?.trim() || 'cookie';
      if (!lower.includes('httponly')) cookieIssues.push(`${name}: missing HttpOnly`);
      if (!lower.includes('secure')) cookieIssues.push(`${name}: missing Secure`);
      if (!lower.includes('samesite')) cookieIssues.push(`${name}: missing SameSite`);
    }

    return {
      ok: true,
      scheme,
      status: res.status,
      finalUrl: res.url,
      server: headers.server || undefined,
      headers,
      missingSecurityHeaders,
      cookieIssues,
      securityTxtFound,
      robotsTxtFound,
      htmlSample,
      setCookies,
    };
  } catch (err) {
    return {
      ok: false,
      scheme,
      headers: {},
      missingSecurityHeaders: [],
      cookieIssues: [],
      securityTxtFound: false,
      robotsTxtFound: false,
      htmlSample: '',
      setCookies: [],
      error: err instanceof Error ? err.message : 'HTTP header audit unreachable',
    };
  } finally {
    clearTimeout(timer);
  }
}

export const headersModule: ScanModulePlugin = {
  id: 'headers',
  label: 'HTTP Security Headers & Cookies',
  isActive: false,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    ctx.log(`Fetching HTTP response headers from ${ctx.host}`, 'info', 'headers');

    let audit = await auditScheme(ctx.host, 'https');
    if (!audit.ok) {
      ctx.log(
        `HTTPS request failed (${audit.error ?? 'unknown error'}); falling back to plain HTTP`,
        'warn',
        'headers',
      );
      audit = await auditScheme(ctx.host, 'http');
    }

    if (!audit.ok) {
      ctx.log(`HTTP fallback also failed: ${audit.error ?? 'unreachable'}`, 'error', 'headers');
      ctx.httpAudit = {
        headers: {},
        missingSecurityHeaders: [],
        cookieIssues: [],
        securityTxtFound: false,
        robotsTxtFound: false,
        error: audit.error,
      };
      return;
    }

    ctx.rawHttpHeaders = audit.headers;
    ctx.rawSetCookies = audit.setCookies;
    ctx.htmlSample = audit.htmlSample;
    ctx.httpAudit = {
      status: audit.status,
      finalUrl: audit.finalUrl,
      server: audit.server,
      headers: audit.headers,
      missingSecurityHeaders: audit.missingSecurityHeaders,
      cookieIssues: audit.cookieIssues,
      securityTxtFound: audit.securityTxtFound,
      robotsTxtFound: audit.robotsTxtFound,
    };

    ctx.log(
      `HTTP ${audit.status ?? 0} via ${audit.scheme.toUpperCase()} · server=${audit.server ?? 'hidden'}`,
      'success',
      'headers',
    );
    if (audit.missingSecurityHeaders.length > 0) {
      ctx.log(
        `Missing security headers: ${audit.missingSecurityHeaders.join(', ')}`,
        'warn',
        'headers',
      );
    } else {
      ctx.log('All core security headers are present', 'success', 'headers');
    }
  },
};
