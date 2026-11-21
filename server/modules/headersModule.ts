import type { ScanModulePlugin } from './types.ts';

// followRedirects: true — every probe follows the full redirect chain so the
// audit evaluates the final origin (for example google.com -> www.google.com).
async function httpFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, redirect: 'follow' });
}

export type CookieCategory = 'session' | 'tracking' | 'preference' | 'unknown';
export type CookieRisk = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface CookieAudit {
  name: string;
  category: CookieCategory;
  missing: string[];
  severity: CookieRisk;
  hasExpiry: boolean;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
}

const TRACKING_COOKIE_NAMES = new Set([
  'nid', '1p_jar', 'consent', 'aec', 'sidcc', 'hsid', 'ssid', 'apisid', 'sapisid',
  'ide', 'dsid', 'anid', 'ysc', 'visitor_info1_live', 'pref', '__gads', '__gpi',
  '__eoi', 'fcnec', 'fplc', 'fr', '_fbp', '_fbc', '_ga', '_gid', '_gat', '_gcl_au',
  '_gcl_aw', '_gcl_dc', '_hj', '_hjfirstseen', '_hjid', '_clck', '_clsk', '_uet',
  '_pin_unauth', '_tt_enable_cookie', '_ttp', '_scid', '_sc_at', 'mp_', 'ajs_anonymous_id',
]);

const SESSION_COOKIE_NAMES = new Set([
  'phpsessid', 'phpssid', 'jsessionid', 'asp.net_sessionid', 'aspsessionid',
  'session', 'sessionid', 'sid', 'auth', 'auth_token', 'access_token',
  'refresh_token', 'id_token', 'jwt', 'token', 'csrftoken', 'xsrf-token',
  'laravel_session', 'ci_session', 'connect.sid', '_session_id', 'wordpress_logged_in',
]);

function parseCookieAttributes(rawCookie: string): {
  name: string;
  lower: string;
  hasExpiry: boolean;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  path?: string;
  domain?: string;
} {
  const parts = rawCookie.split(';').map((part) => part.trim());
  const first = parts.shift() ?? '';
  const name = first.split('=')[0]?.trim() || 'cookie';
  const lower = rawCookie.toLowerCase();
  const attr = (key: string) => parts.find((part) => part.toLowerCase().startsWith(`${key}=`));
  const sameSiteRaw = attr('samesite');
  return {
    name,
    lower,
    hasExpiry: /\bmax-age=|\bexpires=/i.test(rawCookie),
    secure: /\bsecure\b/i.test(lower),
    httpOnly: /\bhttponly\b/i.test(lower),
    sameSite: sameSiteRaw ? sameSiteRaw.split('=').slice(1).join('=').trim() : undefined,
    path: attr('path')?.split('=').slice(1).join('=').trim(),
    domain: attr('domain')?.split('=').slice(1).join('=').trim(),
  };
}

function isTrackingCookie(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    TRACKING_COOKIE_NAMES.has(lower) ||
    /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_hj|_clck|_clsk|_uet|_pin|_tt|_sc|__utm|__gads|__gpi|__eoi)/i.test(name) ||
    /^__(secure-)?3p/i.test(name)
  );
}

function isSessionCookie(name: string, hasExpiry: boolean): boolean {
  const lower = name.toLowerCase();
  if (SESSION_COOKIE_NAMES.has(lower)) return true;
  // __Host- is a strict browser contract normally used for session cookies.
  if (/^__host-/i.test(name)) return true;
  if (/(sess|session|auth|token|jwt|login|csrf|xsrf|sid)/i.test(name)) return true;
  // __Secure- only mandates the Secure attribute; it does not imply a session.
  if (/^__secure-/i.test(name)) return false;
  // A non-tracking cookie without Max-Age/Expires is normally a session cookie.
  return !hasExpiry;
}

export function auditSetCookie(rawCookie: string): CookieAudit {
  const parsed = parseCookieAttributes(rawCookie);
  const name = parsed.name;
  const tracking = isTrackingCookie(name);
  const session = !tracking && isSessionCookie(name, parsed.hasExpiry);
  const preference = !tracking && !session && /^(lang|locale|theme|currency|timezone|country|region|ui-|pref)/i.test(name);
  const category: CookieCategory = tracking ? 'tracking' : session ? 'session' : preference ? 'preference' : 'unknown';
  const missing: string[] = [];
  if (!parsed.secure) missing.push('Secure');
  if (!parsed.httpOnly) missing.push('HttpOnly');
  if (!parsed.sameSite) missing.push('SameSite');
  if (parsed.sameSite?.toLowerCase() === 'none' && !parsed.secure) {
    // SameSite=None is only valid together with Secure.
    if (!missing.includes('Secure')) missing.push('Secure');
  }

  let severity: CookieRisk = 'Info';
  if (missing.length > 0) {
    if (category === 'tracking') {
      severity = 'Info';
    } else if (category === 'session') {
      const sessionFlagMissing = !parsed.secure || !parsed.httpOnly;
      severity = sessionFlagMissing ? 'Critical' : 'High';
    } else if (category === 'preference') {
      severity = !parsed.secure || !parsed.httpOnly ? 'Medium' : 'Low';
    } else {
      severity = !parsed.secure || !parsed.httpOnly ? 'Medium' : 'Low';
    }
  }

  // __Host- / __Secure- prefixes are strict browser contracts.
  if (/^__host-/i.test(name) && (!parsed.secure || parsed.path !== '/' || Boolean(parsed.domain))) {
    severity = 'Critical';
    if (!parsed.secure && !missing.includes('Secure')) missing.push('Secure');
    if (parsed.path !== '/') missing.push('Path=/');
    if (parsed.domain) missing.push('no Domain');
  }
  if (/^__secure-/i.test(name) && !parsed.secure) {
    severity = 'Critical';
    if (!missing.includes('Secure')) missing.push('Secure');
  }

  return {
    name,
    category,
    missing,
    severity,
    hasExpiry: parsed.hasExpiry,
    secure: parsed.secure,
    httpOnly: parsed.httpOnly,
    sameSite: parsed.sameSite,
  };
}

async function checkWellKnownPath(
  origin: string,
  path: string,
  pattern: RegExp,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  try {
    const res = await httpFetch(`${origin}${path}`, {
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

export interface SchemeAudit {
  ok: boolean;
  scheme: 'https' | 'http';
  status?: number;
  finalUrl?: string;
  finalOrigin?: string;
  redirected: boolean;
  server?: string;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
  cookieIssues: string[];
  cookieAudit: CookieAudit[];
  securityTxtFound: boolean;
  robotsTxtFound: boolean;
  cors: {
    allowOrigin?: string;
    allowCredentials: boolean;
    allowMethods?: string;
    reflective: boolean;
    risky: boolean;
  };
  httpMethods: string[];
  htmlSample: string;
  setCookies: string[];
  error?: string;
}

export async function probeCorsAndMethods(origin: string): Promise<Pick<SchemeAudit, 'cors' | 'httpMethods'>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);
  const probeOrigin = 'https://sentinelglobe.example';
  try {
    const res = await httpFetch(`${origin}/`, {
      method: 'OPTIONS',
      signal: controller.signal,
      headers: {
        Origin: probeOrigin,
        'Access-Control-Request-Method': 'GET',
        'User-Agent': 'SentinelGlobe-SecurityAudit/1.0',
      },
    });
    const allowOrigin = res.headers.get('access-control-allow-origin') ?? undefined;
    const allowCredentials =
      (res.headers.get('access-control-allow-credentials') ?? '').toLowerCase() === 'true';
    const allowMethods = res.headers.get('access-control-allow-methods') ?? undefined;
    const reflective = Boolean(allowOrigin && allowOrigin === probeOrigin);
    const risky = Boolean(
      allowOrigin && allowCredentials && (allowOrigin === '*' || reflective),
    );
    const allowHeader = res.headers.get('allow') ?? allowMethods ?? '';
    const httpMethods = allowHeader
      .split(',')
      .map((method) => method.trim().toUpperCase())
      .filter(Boolean);
    await res.body?.cancel().catch(() => {});
    return {
      cors: { allowOrigin, allowCredentials, allowMethods, reflective, risky },
      httpMethods,
    };
  } catch {
    return { cors: { allowCredentials: false, reflective: false, risky: false }, httpMethods: [] };
  } finally {
    clearTimeout(timer);
  }
}

export async function auditScheme(host: string, scheme: 'https' | 'http'): Promise<SchemeAudit> {
  const origin = `${scheme}://${host}`;
  const probeUrl = `${origin}/`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);

  try {
    const res = await httpFetch(probeUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'SentinelGlobe-SecurityAudit/1.0' },
    });
    const finalUrl = res.url || probeUrl;
    let finalOrigin = origin;
    try {
      finalOrigin = new URL(finalUrl).origin;
    } catch {
      finalOrigin = origin;
    }
    const redirected = finalUrl !== probeUrl;
    const [securityTxtFound, robotsTxtFound, corsProbe] = await Promise.all([
      checkWellKnownPath(finalOrigin, '/.well-known/security.txt', /contact:/i),
      checkWellKnownPath(finalOrigin, '/robots.txt', /user-agent|disallow|allow|sitemap/i),
      probeCorsAndMethods(finalOrigin),
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

    const cookieAudit = setCookies.slice(0, 20).map(auditSetCookie);
    const cookieIssues = cookieAudit
      .filter((cookie) => cookie.missing.length > 0)
      .map(
        (cookie) =>
          `${cookie.name} [${cookie.category}/${cookie.severity}]: missing ${cookie.missing.join(', ')}`,
      );

    return {
      ok: true,
      scheme,
      status: res.status,
      finalUrl,
      finalOrigin,
      redirected,
      server: headers.server || undefined,
      headers,
      missingSecurityHeaders,
      cookieIssues,
      cookieAudit,
      securityTxtFound,
      robotsTxtFound,
      cors: corsProbe.cors,
      httpMethods: corsProbe.httpMethods,
      htmlSample,
      setCookies,
    };
  } catch (err) {
    return {
      ok: false,
      scheme,
      redirected: false,
      headers: {},
      missingSecurityHeaders: [],
      cookieIssues: [],
      cookieAudit: [],
      securityTxtFound: false,
      robotsTxtFound: false,
      cors: { allowCredentials: false, reflective: false, risky: false },
      httpMethods: [],
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
        cookieAudit: [],
        securityTxtFound: false,
        robotsTxtFound: false,
        error: audit.error,
      };
      return;
    }

    ctx.rawHttpHeaders = audit.headers;
    ctx.rawSetCookies = audit.setCookies;
    ctx.htmlSample = audit.htmlSample;
    if (audit.redirected) {
      ctx.log(`Followed redirect to final origin ${audit.finalOrigin}`, 'info', 'headers');
    }
    ctx.httpAudit = {
      status: audit.status,
      finalUrl: audit.finalUrl,
      server: audit.server,
      headers: audit.headers,
      missingSecurityHeaders: audit.missingSecurityHeaders,
      cookieIssues: audit.cookieIssues,
      cookieAudit: audit.cookieAudit,
      securityTxtFound: audit.securityTxtFound,
      robotsTxtFound: audit.robotsTxtFound,
      cors: audit.cors,
      httpMethods: audit.httpMethods,
    };

    ctx.log(
      `HTTP ${audit.status ?? 0} via ${audit.scheme.toUpperCase()} · server=${audit.server ?? 'hidden'}`,
      'success',
      'headers',
    );
    if (audit.cors.risky) {
      ctx.log(
        `Risky CORS policy: origin=${audit.cors.allowOrigin} credentials=${audit.cors.allowCredentials}`,
        'warn',
        'headers',
      );
    }
    if (audit.httpMethods.some((method) => method === 'TRACE' || method === 'TRACK')) {
      ctx.log(`Dangerous HTTP methods advertised: ${audit.httpMethods.join(', ')}`, 'warn', 'headers');
    }
    if (audit.missingSecurityHeaders.length > 0) {
      ctx.log(
        `Missing security headers: ${audit.missingSecurityHeaders.join(', ')}`,
        'warn',
        'headers',
      );
    } else {
      ctx.log('All core security headers are present', 'success', 'headers');
    }
    const criticalCookies = audit.cookieAudit.filter((cookie) => cookie.severity === 'Critical');
    if (criticalCookies.length > 0) {
      ctx.log(
        `Critical session cookie flags missing: ${criticalCookies.map((cookie) => cookie.name).join(', ')}`,
        'error',
        'headers',
      );
    }
  },
};
