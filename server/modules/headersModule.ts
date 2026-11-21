import type { ScanModulePlugin } from './types.ts';

async function checkWellKnownPath(
  host: string,
  path: string,
  pattern: RegExp,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    const res = await fetch(`https://${host}${path}`, {
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

export const headersModule: ScanModulePlugin = {
  id: 'headers',
  label: 'HTTP Security Headers & Cookies',
  isActive: false,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    try {
      const [res, securityTxtFound, robotsTxtFound] = await Promise.all([
        fetch(ctx.probeUrl, {
          method: 'GET',
          redirect: 'follow',
          signal: controller.signal,
          headers: {
            'User-Agent': 'SentinelGlobe-SecurityAudit/1.0',
          },
        }),
        checkWellKnownPath(ctx.host, '/.well-known/security.txt', /contact:/i),
        checkWellKnownPath(ctx.host, '/robots.txt', /user-agent|disallow|allow|sitemap/i),
      ]);

      // Capture all lowercased headers for downstream WAF inspection without re-fetching
      const allHeaders: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        allHeaders[key.toLowerCase()] = value;
      });
      ctx.rawHttpHeaders = allHeaders;

      const setCookies =
        typeof res.headers.getSetCookie === 'function'
          ? res.headers.getSetCookie()
          : res.headers.get('set-cookie')
            ? [res.headers.get('set-cookie')!]
            : [];
      ctx.rawSetCookies = setCookies;

      // Capture up to 128 KB HTML sample cleanly for downstream inspection
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('text/html') || contentType === '') {
        try {
          const text = await res.text();
          ctx.htmlSample = text.slice(0, 128 * 1024);
        } catch {
          ctx.htmlSample = '';
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

      ctx.httpAudit = {
        status: res.status,
        finalUrl: res.url,
        server: headers.server || undefined,
        headers,
        missingSecurityHeaders,
        cookieIssues,
        securityTxtFound,
        robotsTxtFound,
      };
    } catch (err) {
      ctx.httpAudit = {
        headers: {},
        missingSecurityHeaders: [],
        cookieIssues: [],
        securityTxtFound: false,
        robotsTxtFound: false,
        error: err instanceof Error ? err.message : 'HTTP header audit unreachable',
      };
    } finally {
      clearTimeout(timer);
    }
  },
};
