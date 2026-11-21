import type {
  CveDetailRecord,
  PortScanReport,
  TechFingerprint,
  WafDetectionResult,
} from '../src/types/cyber.ts';

interface DetectionInput {
  serverHeader?: string;
  poweredBy?: string;
  headers: Record<string, string>;
  html?: string;
  portScan?: PortScanReport | null;
  waf?: WafDetectionResult | null;
}

const SERVER_SIGNATURES: Array<{
  match: RegExp;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { match: /cloudflare/i, name: 'Cloudflare', category: 'cdn' },
  { match: /nginx/i, name: 'Nginx', category: 'server' },
  { match: /openresty/i, name: 'OpenResty', category: 'server' },
  { match: /apache/i, name: 'Apache HTTP Server', category: 'server' },
  { match: /microsoft-iis/i, name: 'Microsoft IIS', category: 'server' },
  { match: /litespeed/i, name: 'LiteSpeed', category: 'server' },
  { match: /caddy/i, name: 'Caddy', category: 'server' },
  { match: /envoy/i, name: 'Envoy Proxy', category: 'server' },
  { match: /gunicorn/i, name: 'Gunicorn', category: 'server' },
  { match: /heroku/i, name: 'Heroku', category: 'platform' },
  { match: /vercel/i, name: 'Vercel', category: 'platform' },
  { match: /netlify/i, name: 'Netlify', category: 'platform' },
  { match: /github\.com/i, name: 'GitHub Pages', category: 'platform' },
  { match: /amazons3/i, name: 'Amazon S3', category: 'platform' },
  { match: /awselb/i, name: 'AWS Elastic Load Balancer', category: 'platform' },
  { match: /cloudfront/i, name: 'Amazon CloudFront', category: 'cdn' },
];

const POWERED_BY_SIGNATURES: Array<{
  match: RegExp;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { match: /express/i, name: 'Express', category: 'framework' },
  { match: /next\.js/i, name: 'Next.js', category: 'framework' },
  { match: /nuxt/i, name: 'Nuxt', category: 'framework' },
  { match: /php/i, name: 'PHP', category: 'language' },
  { match: /asp\.net/i, name: 'ASP.NET', category: 'framework' },
  { match: /servlet|jsp/i, name: 'Java Servlet', category: 'language' },
  { match: /django/i, name: 'Django', category: 'framework' },
  { match: /rails/i, name: 'Ruby on Rails', category: 'framework' },
];

const HTML_SIGNATURES: Array<{
  match: RegExp;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { match: /wp-content|wp-includes/i, name: 'WordPress', category: 'framework' },
  { match: /__NEXT_DATA__|_next\/static/i, name: 'Next.js', category: 'framework' },
  { match: /nuxt|__NUXT__/i, name: 'Nuxt', category: 'framework' },
  { match: /drupal-settings-json|sites\/default\/files/i, name: 'Drupal', category: 'framework' },
  { match: /joomla/i, name: 'Joomla', category: 'framework' },
  { match: /cdn\.shopify\.com/i, name: 'Shopify', category: 'platform' },
  { match: /laravel/i, name: 'Laravel', category: 'framework' },
  { match: /react/i, name: 'React', category: 'framework' },
];

const BANNER_SIGNATURES: Array<{
  match: RegExp;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { match: /openssh/i, name: 'OpenSSH', category: 'server' },
  { match: /nginx/i, name: 'Nginx', category: 'server' },
  { match: /apache/i, name: 'Apache HTTP Server', category: 'server' },
  { match: /mysql/i, name: 'MySQL', category: 'database' },
  { match: /mariadb/i, name: 'MariaDB', category: 'database' },
  { match: /postgresql/i, name: 'PostgreSQL', category: 'database' },
  { match: /redis/i, name: 'Redis', category: 'database' },
  { match: /microsoft-iis/i, name: 'Microsoft IIS', category: 'server' },
  { match: /vsftpd|proftpd|pure-ftpd/i, name: 'FTP Daemon', category: 'server' },
  { match: /exim|postfix|sendmail/i, name: 'Mail Transfer Agent', category: 'server' },
];

const COOKIE_SIGNATURES: Array<{
  match: RegExp;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { match: /phpsessid/i, name: 'PHP', category: 'language' },
  { match: /jsessionid/i, name: 'Java', category: 'language' },
  { match: /asp\.net_sessionid/i, name: 'ASP.NET', category: 'framework' },
  { match: /laravel_session/i, name: 'Laravel', category: 'framework' },
  { match: /_rails|_session_id/i, name: 'Ruby on Rails', category: 'framework' },
];

const HEADER_HINTS: Array<{
  header: string;
  name: string;
  category: TechFingerprint['category'];
}> = [
  { header: 'x-vercel-id', name: 'Vercel', category: 'platform' },
  { header: 'x-nextjs-cache', name: 'Next.js', category: 'framework' },
  { header: 'x-amz-cf-id', name: 'Amazon CloudFront', category: 'cdn' },
  { header: 'x-heroku-request-id', name: 'Heroku', category: 'platform' },
  { header: 'x-nf-request-id', name: 'Netlify', category: 'platform' },
  { header: 'x-github-request-id', name: 'GitHub Pages', category: 'platform' },
  { header: 'x-azure-ref', name: 'Azure Front Door', category: 'cdn' },
  { header: 'cf-ray', name: 'Cloudflare', category: 'cdn' },
];

function pushUnique(
  list: TechFingerprint[],
  name: string,
  category: TechFingerprint['category'],
  confidence: TechFingerprint['confidence'],
  evidence: string,
) {
  const existing = list.find((item) => item.name === name);
  if (existing) {
    if (existing.confidence !== 'High' && confidence === 'High') {
      existing.confidence = 'High';
      existing.evidence = evidence;
    }
    return;
  }
  list.push({ name, category, confidence, evidence });
}

export function detectTechStack(input: DetectionInput): TechFingerprint[] {
  const stack: TechFingerprint[] = [];
  const headers = input.headers || {};
  const setCookies = headers['set-cookie'] ?? '';

  const serverValue = input.serverHeader || headers.server || '';
  for (const sig of SERVER_SIGNATURES) {
    if (sig.match.test(serverValue)) {
      pushUnique(stack, sig.name, sig.category, 'High', `Server header: ${serverValue}`);
    }
  }

  const poweredValue = input.poweredBy || headers['x-powered-by'] || '';
  for (const sig of POWERED_BY_SIGNATURES) {
    if (sig.match.test(poweredValue)) {
      pushUnique(stack, sig.name, sig.category, 'High', `X-Powered-By: ${poweredValue}`);
    }
  }

  for (const hint of HEADER_HINTS) {
    if (headers[hint.header]) {
      pushUnique(stack, hint.name, hint.category, 'High', `Header ${hint.header} present`);
    }
  }

  for (const sig of COOKIE_SIGNATURES) {
    if (sig.match.test(setCookies)) {
      pushUnique(stack, sig.name, sig.category, 'Medium', 'Cookie name signature');
    }
  }

  if (input.html) {
    for (const sig of HTML_SIGNATURES) {
      if (sig.match.test(input.html)) {
        pushUnique(stack, sig.name, sig.category, 'Medium', 'HTML marker detected');
      }
    }
  }

  for (const banner of input.portScan?.serviceFingerprint ?? []) {
    for (const sig of BANNER_SIGNATURES) {
      if (sig.match.test(banner)) {
        pushUnique(stack, sig.name, sig.category, 'High', `Service banner: ${banner}`);
      }
    }
  }

  if (input.waf?.detected && input.waf.provider) {
    pushUnique(
      stack,
      input.waf.provider,
      'cdn',
      input.waf.confidence === 'High' ? 'High' : 'Medium',
      'WAF signature',
    );
  }

  return stack;
}

const SERVER_FAMILIES: Array<{ token: RegExp; family: string }> = [
  { token: /apache|httpd|http_server/i, family: 'apache' },
  { token: /nginx|openresty/i, family: 'nginx' },
  { token: /microsoft[-_ ]?iis|\biis\b/i, family: 'iis' },
  { token: /litespeed/i, family: 'litespeed' },
  { token: /caddy/i, family: 'caddy' },
  { token: /tomcat/i, family: 'tomcat' },
  { token: /jetty/i, family: 'jetty' },
];

function familyOf(value: string): string | null {
  for (const entry of SERVER_FAMILIES) {
    if (entry.token.test(value)) return entry.family;
  }
  return null;
}

/**
 * Drop CVEs that explicitly target a different web server family than the one
 * actually observed. This prevents cross-product false positives such as an
 * Apache CVE being reported against a Heroku/Nginx host.
 */
export function filterContextualCves(
  cveDetails: CveDetailRecord[],
  stack: TechFingerprint[],
): { kept: CveDetailRecord[]; excluded: Array<{ cveId: string; reason: string }> } {
  const detectedFamilies = new Set<string>();
  for (const item of stack) {
    if (item.category !== 'server' && item.category !== 'platform') continue;
    const family = familyOf(item.name);
    if (family) detectedFamilies.add(family);
  }

  if (detectedFamilies.size === 0) {
    return { kept: cveDetails, excluded: [] };
  }

  const kept: CveDetailRecord[] = [];
  const excluded: Array<{ cveId: string; reason: string }> = [];

  for (const cve of cveDetails) {
    const families = new Set<string>();
    for (const product of cve.affectedProducts) {
      const family = familyOf(product);
      if (family) families.add(family);
    }

    if (families.size === 0) {
      kept.push(cve);
      continue;
    }

    const matchesDetected = [...families].some((family) => detectedFamilies.has(family));
    if (matchesDetected) {
      kept.push(cve);
      continue;
    }

    excluded.push({
      cveId: cve.cveId,
      reason: `Affected product family (${[...families].join(', ')}) does not match observed server stack (${[...detectedFamilies].join(', ')}).`,
    });
  }

  return { kept, excluded };
}
