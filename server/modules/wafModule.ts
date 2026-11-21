import type { WafDetectionResult } from '../../src/types/cyber.ts';
import type { ScanModulePlugin } from './types.ts';

interface WafSignature {
  provider: string;
  check: (headers: Record<string, string>, cookies: string[]) => string[];
}

const WAF_SIGNATURES: WafSignature[] = [
  {
    provider: 'Cloudflare',
    check: (h, cookies) => {
      const hits: string[] = [];
      if (h['cf-ray']) hits.push(`cf-ray: ${h['cf-ray']}`);
      if (h['cf-cache-status']) hits.push(`cf-cache-status: ${h['cf-cache-status']}`);
      if (h['server']?.toLowerCase().includes('cloudflare')) hits.push('server: cloudflare');
      if (cookies.some((c) => /__cf_bm=|cf_clearance=/i.test(c))) {
        hits.push('Cloudflare challenge/bot cookie');
      }
      return hits;
    },
  },
  {
    provider: 'AWS WAF / CloudFront',
    check: (h, cookies) => {
      const hits: string[] = [];
      if (h['x-amz-cf-id']) hits.push(`x-amz-cf-id present`);
      if (h['x-amz-cf-pop']) hits.push(`x-amz-cf-pop: ${h['x-amz-cf-pop']}`);
      if (h['x-amzn-requestid'] && h['x-amzn-errortype']) hits.push('AWS Gateway/WAF error header');
      if (h['via']?.toLowerCase().includes('cloudfront')) hits.push('via: CloudFront');
      if (h['server']?.toLowerCase().includes('awselb') || h['server']?.toLowerCase().includes('cloudfront')) {
        hits.push(`server: ${h['server']}`);
      }
      if (cookies.some((c) => /awsalb=|aws-waf-token=/i.test(c))) {
        hits.push('AWS WAF / ALB token cookie');
      }
      return hits;
    },
  },
  {
    provider: 'Akamai Kona Site Defender',
    check: (h, cookies) => {
      const hits: string[] = [];
      if (h['x-akamai-transformed']) hits.push('x-akamai-transformed');
      if (h['akamai-grn'] || h['akamai-origin-hop']) hits.push('akamai edge header');
      if (h['server']?.toLowerCase().includes('akamaighost')) hits.push('server: AkamaiGHost');
      if (cookies.some((c) => /ak_bmsc=|bm_sz=/i.test(c))) {
        hits.push('Akamai Bot Manager cookie');
      }
      return hits;
    },
  },
  {
    provider: 'Imperva / Incapsula',
    check: (h, cookies) => {
      const hits: string[] = [];
      if (h['x-iinfo']) hits.push('x-iinfo header');
      if (h['x-cdn']?.toLowerCase().includes('imperva') || h['x-cdn']?.toLowerCase().includes('incapsula')) {
        hits.push(`x-cdn: ${h['x-cdn']}`);
      }
      if (cookies.some((c) => /incap_ses_|visid_incap_/i.test(c))) {
        hits.push('Imperva Incapsula session cookie');
      }
      return hits;
    },
  },
  {
    provider: 'Sucuri CloudProxy',
    check: (h) => {
      const hits: string[] = [];
      if (h['x-sucuri-id']) hits.push(`x-sucuri-id: ${h['x-sucuri-id']}`);
      if (h['x-sucuri-cache']) hits.push(`x-sucuri-cache: ${h['x-sucuri-cache']}`);
      if (h['server']?.toLowerCase().includes('sucuri')) hits.push('server: Sucuri');
      return hits;
    },
  },
  {
    provider: 'Fastly Edge / Signal Sciences',
    check: (h) => {
      const hits: string[] = [];
      if (h['x-fastly-request-id'] || h['fastly-restarts']) hits.push('Fastly edge request header');
      if (h['x-served-by']?.toLowerCase().includes('cache-')) hits.push(`x-served-by: ${h['x-served-by']}`);
      if (h['via']?.toLowerCase().includes('varnish') && h['x-timer']) hits.push('Fastly Varnish timer');
      return hits;
    },
  },
  {
    provider: 'Azure Front Door / Application Gateway WAF',
    check: (h) => {
      const hits: string[] = [];
      if (h['x-azure-ref']) hits.push(`x-azure-ref: ${h['x-azure-ref']}`);
      if (h['x-fd-int-roxy-purgeid']) hits.push('Azure Front Door header');
      return hits;
    },
  },
  {
    provider: 'F5 BIG-IP ASM / ModSecurity',
    check: (h, cookies) => {
      const hits: string[] = [];
      if (h['server']?.toLowerCase().includes('bigip') || h['x-wa-info']) hits.push('F5 BIG-IP header');
      if (h['server']?.toLowerCase().includes('mod_security')) hits.push('server: ModSecurity');
      if (cookies.some((c) => /^TS[0-9a-f]{6,}=/i.test(c) || /BIGipServer/i.test(c))) {
        hits.push('F5 BIG-IP persistence/ASM cookie');
      }
      return hits;
    },
  },
];

export function detectWafFromHeaders(
  headers: Record<string, string>,
  setCookies: string[] = [],
  nsRecords: string[] = [],
): WafDetectionResult {
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v;
  }

  for (const sig of WAF_SIGNATURES) {
    const signals = sig.check(lowerHeaders, setCookies);
    if (signals.length > 0) {
      return {
        detected: true,
        provider: sig.provider,
        confidence: signals.length >= 2 ? 'High' : 'Medium',
        signals,
      };
    }
  }

  // Fallback NS check for Cloudflare DNS proxy edge
  const cfNs = nsRecords.filter((ns) => ns.toLowerCase().endsWith('.ns.cloudflare.com'));
  if (cfNs.length > 0) {
    return {
      detected: true,
      provider: 'Cloudflare (DNS Edge)',
      confidence: 'Medium',
      signals: [`Authoritative NS: ${cfNs[0]}`],
    };
  }

  return {
    detected: false,
    confidence: 'None',
    signals: [],
  };
}

export const wafModule: ScanModulePlugin = {
  id: 'waf',
  label: 'WAF & Edge Shield Detection',
  isActive: false,
  supportsTargetType: (t) => t === 'domain' || t === 'url',
  async run(ctx) {
    // Reuse headers fetched by headersModule if already populated, otherwise do a lightweight HEAD request
    if (Object.keys(ctx.rawHttpHeaders).length === 0) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const res = await fetch(ctx.probeUrl, {
          method: 'HEAD',
          redirect: 'follow',
          signal: controller.signal,
          headers: { 'User-Agent': 'SentinelGlobe-SecurityAudit/1.0' },
        });
        const hdrs: Record<string, string> = {};
        res.headers.forEach((v, k) => {
          hdrs[k.toLowerCase()] = v;
        });
        ctx.rawHttpHeaders = hdrs;
        ctx.rawSetCookies =
          typeof res.headers.getSetCookie === 'function'
            ? res.headers.getSetCookie()
            : res.headers.get('set-cookie')
              ? [res.headers.get('set-cookie')!]
              : [];
      } catch {
        // leave empty
      } finally {
        clearTimeout(timer);
      }
    }

    ctx.waf = detectWafFromHeaders(
      ctx.rawHttpHeaders,
      ctx.rawSetCookies,
      ctx.dns.ns,
    );

    if (ctx.waf.detected) {
      ctx.log(
        `Edge WAF/CDN detected · ${ctx.waf.provider} (${ctx.waf.confidence} confidence)`,
        'success',
        'waf',
      );
    } else {
      ctx.log('No edge WAF or CDN signature detected', 'warn', 'waf');
    }
  },
};
