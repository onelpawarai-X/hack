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
  cpes?: string[];
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
  version?: string,
  cpe?: string,
) {
  const existing = list.find((item) => item.name === name);
  if (existing) {
    if (!existing.version && version) existing.version = version;
    if (!existing.cpe && cpe) existing.cpe = cpe;
    if (existing.confidence !== 'High' && confidence === 'High') {
      existing.confidence = 'High';
      existing.evidence = evidence;
    }
    return;
  }
  list.push({ name, category, confidence, evidence, version, cpe });
}

function extractVersion(value: string): string | undefined {
  const match = value.match(/(?:^|[/_\s-])v?(\d+\.\d+(?:\.\d+){0,2})/i);
  return match?.[1];
}

interface CpeParts {
  vendor: string;
  product: string;
  version?: string;
  raw: string;
}

const CPE_NAMES: Record<string, { name: string; category: TechFingerprint['category'] }> = {
  'apache:http_server': { name: 'Apache HTTP Server', category: 'server' },
  'nginx:nginx': { name: 'Nginx', category: 'server' },
  'microsoft:iis': { name: 'Microsoft IIS', category: 'server' },
  'openbsd:openssh': { name: 'OpenSSH', category: 'server' },
  'php:php': { name: 'PHP', category: 'language' },
  'wordpress:wordpress': { name: 'WordPress', category: 'framework' },
  'drupal:drupal': { name: 'Drupal', category: 'framework' },
  'joomla:joomla': { name: 'Joomla', category: 'framework' },
  'apache:tomcat': { name: 'Apache Tomcat', category: 'server' },
  'eclipse:jetty': { name: 'Jetty', category: 'server' },
  'oracle:mysql': { name: 'MySQL', category: 'database' },
  'mysql:mysql': { name: 'MySQL', category: 'database' },
  'postgresql:postgresql': { name: 'PostgreSQL', category: 'database' },
  'redis:redis': { name: 'Redis', category: 'database' },
  'mariadb:mariadb': { name: 'MariaDB', category: 'database' },
  'exim:exim': { name: 'Exim', category: 'server' },
  'postfix:postfix': { name: 'Postfix', category: 'server' },
  'caddy:caddy': { name: 'Caddy', category: 'server' },
  'litespeed:litespeed': { name: 'LiteSpeed', category: 'server' },
  'nodejs:node.js': { name: 'Node.js', category: 'language' },
  'expressjs:express': { name: 'Express', category: 'framework' },
  'rubyonrails:rails': { name: 'Ruby on Rails', category: 'framework' },
  'djangoproject:django': { name: 'Django', category: 'framework' },
  'cloudflare:cloudflare': { name: 'Cloudflare', category: 'cdn' },
  'amazon:cloudfront': { name: 'Amazon CloudFront', category: 'cdn' },
  'fastly:fastly': { name: 'Fastly', category: 'cdn' },
};

function parseCpe(value: string): CpeParts | null {
  const raw = value.trim();
  if (raw.startsWith('cpe:2.3:')) {
    const parts = raw.split(':');
    if (parts.length < 5) return null;
    return {
      vendor: parts[3].toLowerCase(),
      product: parts[4].toLowerCase(),
      version: parts[5] && parts[5] !== '*' ? parts[5] : undefined,
      raw,
    };
  }
  if (raw.startsWith('cpe:/')) {
    const parts = raw.slice(5).split(':');
    if (parts.length < 3) return null;
    return {
      vendor: parts[1].toLowerCase(),
      product: parts[2].toLowerCase(),
      version: parts[3] && parts[3] !== '*' ? parts[3] : undefined,
      raw,
    };
  }
  return null;
}

function cpeDisplay(parts: CpeParts): { name: string; category: TechFingerprint['category'] } {
  return (
    CPE_NAMES[`${parts.vendor}:${parts.product}`] ?? {
      name: parts.product.replace(/[_-]+/g, ' '),
      category: 'server',
    }
  );
}

function stackFromCpes(cpes: string[]): TechFingerprint[] {
  const stack: TechFingerprint[] = [];
  for (const raw of cpes) {
    const parts = parseCpe(raw);
    if (!parts) continue;
    const display = cpeDisplay(parts);
    pushUnique(
      stack,
      display.name,
      display.category,
      'Medium',
      `CPE ${raw}`,
      parts.version,
      `${parts.vendor}:${parts.product}`,
    );
  }
  return stack;
}

export function detectTechStack(input: DetectionInput): TechFingerprint[] {
  const stack: TechFingerprint[] = [];
  const headers = input.headers || {};
  const setCookies = headers['set-cookie'] ?? '';

  const serverValue = input.serverHeader || headers.server || '';
  for (const sig of SERVER_SIGNATURES) {
    if (sig.match.test(serverValue)) {
      pushUnique(stack, sig.name, sig.category, 'High', `Server header: ${serverValue}`, extractVersion(serverValue));
    }
  }

  const poweredValue = input.poweredBy || headers['x-powered-by'] || '';
  for (const sig of POWERED_BY_SIGNATURES) {
    if (sig.match.test(poweredValue)) {
      pushUnique(stack, sig.name, sig.category, 'High', `X-Powered-By: ${poweredValue}`, extractVersion(poweredValue));
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
        pushUnique(stack, sig.name, sig.category, 'High', `Service banner: ${banner}`, extractVersion(banner));
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

  for (const fromCpe of stackFromCpes(input.cpes ?? [])) {
    pushUnique(
      stack,
      fromCpe.name,
      fromCpe.category,
      fromCpe.confidence,
      fromCpe.evidence,
      fromCpe.version,
      fromCpe.cpe,
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
 * Drop CVEs that explicitly target a different product or web server family
 * than the one actually observed. CPE metadata is preferred; textual product
 * names are used as a fallback.
 */
export function filterContextualCves(
  cveDetails: CveDetailRecord[],
  stack: TechFingerprint[],
): { kept: CveDetailRecord[]; excluded: Array<{ cveId: string; reason: string }> } {
  const detectedFamilies = new Set<string>();
  const detectedCpes = new Set<string>();
  const detectedNames = new Set<string>();

  for (const item of stack) {
    const family = familyOf(item.name);
    if (family) detectedFamilies.add(family);
    if (item.cpe) detectedCpes.add(item.cpe);
    detectedNames.add(item.name.toLowerCase());
  }

  if (detectedFamilies.size === 0 && detectedCpes.size === 0 && detectedNames.size === 0) {
    return { kept: cveDetails, excluded: [] };
  }

  const kept: CveDetailRecord[] = [];
  const excluded: Array<{ cveId: string; reason: string }> = [];

  for (const cve of cveDetails) {
    const cveFamilies = new Set<string>();
    const cveCpes = new Set<string>();
    const cveProductLabels: string[] = [];
    const cveNameMatches: string[] = [];
    const cveVersions: string[] = [];

    for (const product of cve.affectedProducts) {
      const parts = parseCpe(product);
      if (parts) {
        cveCpes.add(`${parts.vendor}:${parts.product}`);
        cveProductLabels.push(`${parts.vendor}:${parts.product}`);
        if (parts.version) cveVersions.push(parts.version);
        const display = cpeDisplay(parts);
        const family = familyOf(display.name) ?? familyOf(parts.product);
        if (family) cveFamilies.add(family);
        continue;
      }
      const family = familyOf(product);
      if (family) cveFamilies.add(family);
      const normalized = product.toLowerCase();
      for (const name of detectedNames) {
        if (normalized.includes(name) || name.includes(normalized)) {
          cveProductLabels.push(product);
          cveNameMatches.push(product);
        }
      }
    }

    const cpeMatch = [...cveCpes].find((key) => detectedCpes.has(key));
    if (cpeMatch) {
      const detected = stack.find((item) => item.cpe === cpeMatch);
      kept.push({
        ...cve,
        stackMatch: {
          confidence: 'High',
          reason: `CPE ${cpeMatch} matches detected ${detected?.name ?? 'component'}${detected?.version ? ` ${detected.version}` : ''}.`,
        },
      });
      continue;
    }

    if (cveNameMatches.length > 0) {
      kept.push({
        ...cve,
        stackMatch: {
          confidence: 'Medium',
          reason: `Affected product text matches detected stack: ${cveNameMatches.slice(0, 3).join(', ')}.`,
        },
      });
      continue;
    }

    const familyMatch = [...cveFamilies].find((family) => detectedFamilies.has(family));
    if (familyMatch) {
      const versions = cveVersions.length ? ` CVE versions: ${Array.from(new Set(cveVersions)).slice(0, 4).join(', ')}.` : '';
      kept.push({
        ...cve,
        stackMatch: {
          confidence: 'Medium',
          reason: `Affected product family (${familyMatch}) matches the observed stack.${versions}`,
        },
      });
      continue;
    }

    if (cveCpes.size === 0 && cveFamilies.size === 0) {
      kept.push({
        ...cve,
        stackMatch: {
          confidence: 'Low',
          reason: 'CVE feed did not include a machine-readable product or family; kept for analyst review.',
        },
      });
      continue;
    }

    excluded.push({
      cveId: cve.cveId,
      reason: `Affected products (${cveProductLabels.slice(0, 3).join(', ') || [...cveCpes, ...cveFamilies].join(', ')}) do not match observed stack (${[...detectedCpes, ...detectedFamilies].join(', ')}).`,
    });
  }

  return { kept, excluded };
}
