import crypto from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import type { DomainVerificationStatus } from '../src/types/cyber.ts';
import { extractRootDomain } from './osintParsers.ts';
import { assertSafePublicUrl } from './ssrfGuard.ts';
import { getConfig, setConfig } from './db.ts';

const VERIFICATION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours authorization lease

// In-memory runtime fallback if VERIFICATION_SECRET is not configured in environment
const RUNTIME_FALLBACK_SECRET = crypto.randomBytes(32).toString('hex');

function getSigningSecret(): string {
  return process.env.VERIFICATION_SECRET?.trim() || RUNTIME_FALLBACK_SECRET;
}

export interface VerifiedDomainGrant {
  domain: string;
  method: 'dns-txt' | 'http-file' | 'agent-beacon';
  verifiedAt: string;
  expiresAt: number;
  token: string;
}

export function normalizeVerificationDomain(rawTarget: string): string {
  const clean = rawTarget.trim().toLowerCase();
  if (!clean) return '';
  try {
    const u = new URL(/^https?:\/\//i.test(clean) ? clean : `https://${clean}`);
    return extractRootDomain(u.hostname);
  } catch {
    return extractRootDomain(clean.split('/')[0]);
  }
}

export function buildDomainVerificationToken(domain: string, secret = getSigningSecret()): string {
  const normalized = normalizeVerificationDomain(domain);
  const digest = crypto
    .createHmac('sha256', secret)
    .update(`sentinelglobe-auth-v1:${normalized}`)
    .digest('hex')
    .slice(0, 24);
  return `sentinelglobe-verify=${digest}`;
}

export function matchesTxtVerificationToken(txtRecords: string[], expectedToken: string): boolean {
  const normExpected = expectedToken.trim().toLowerCase();
  return txtRecords.some((rec) => rec.trim().toLowerCase().includes(normExpected));
}

export function matchesHttpVerificationBody(body: string, expectedToken: string): boolean {
  if (!body) return false;
  return body.trim().includes(expectedToken.trim());
}

class DomainVerificationStore {
  private readonly grants = new Map<string, VerifiedDomainGrant>();
  private loaded = false;

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = getConfig('domainVerification.grants');
      if (!raw) return;
      const parsed = JSON.parse(raw) as Record<string, VerifiedDomainGrant>;
      for (const [domain, grant] of Object.entries(parsed)) {
        if (grant && grant.expiresAt > Date.now()) this.grants.set(domain, grant);
      }
    } catch {
      // A corrupt cache must not block verification.
    }
  }

  private persist(): void {
    try {
      setConfig('domainVerification.grants', JSON.stringify(Object.fromEntries(this.grants)));
    } catch {
      // Verification remains valid for this process even if persistence fails.
    }
  }

  public getStatus(rawTarget: string): DomainVerificationStatus {
    this.load();
    const domain = normalizeVerificationDomain(rawTarget);
    const token = buildDomainVerificationToken(domain);
    const grant = this.grants.get(domain);
    const now = Date.now();
    const isActiveGrant = Boolean(grant && grant.expiresAt > now);

    if (grant && !isActiveGrant) {
      this.grants.delete(domain);
      this.persist();
    }

    const expiresIso = isActiveGrant
      ? new Date(grant!.expiresAt).toISOString()
      : new Date(now + VERIFICATION_TTL_MS).toISOString();

    return {
      domain,
      verified: isActiveGrant,
      method: isActiveGrant ? grant!.method : undefined,
      verifiedAt: isActiveGrant ? grant!.verifiedAt : undefined,
      token,
      txtRecordHost: `_sentinelglobe-verify.${domain}`,
      txtRecordValue: token,
      httpFilePath: '/.well-known/sentinelglobe-verify.txt',
      httpFileContent: token,
      expiresAt: expiresIso,
    };
  }

  public isDomainVerified(rawTarget: string, now = Date.now()): boolean {
    this.load();
    const domain = normalizeVerificationDomain(rawTarget);
    if (!domain) return false;
    const grant = this.grants.get(domain);
    if (!grant) return false;
    if (grant.expiresAt <= now) {
      this.grants.delete(domain);
      this.persist();
      return false;
    }
    return true;
  }

  public markVerified(domain: string, method: 'dns-txt' | 'http-file' | 'agent-beacon', now = Date.now()): VerifiedDomainGrant {
    this.load();
    const normalized = normalizeVerificationDomain(domain);
    const token = buildDomainVerificationToken(normalized);
    const grant: VerifiedDomainGrant = {
      domain: normalized,
      method,
      verifiedAt: new Date(now).toISOString(),
      expiresAt: now + VERIFICATION_TTL_MS,
      token,
    };
    this.grants.set(normalized, grant);
    this.persist();
    return grant;
  }

  public async verifyDomainOwnership(
    rawTarget: string,
    method: 'dns-txt' | 'http-file' | 'agent-beacon',
  ): Promise<DomainVerificationStatus> {
    const domain = normalizeVerificationDomain(rawTarget);
    if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
      const empty = this.getStatus(rawTarget);
      return { ...empty, verified: false, error: 'Valid public domain is required for ownership verification.' };
    }

    const expectedToken = buildDomainVerificationToken(domain);

    if (method === 'dns-txt') {
      const hostsToCheck = [`_sentinelglobe-verify.${domain}`, domain];
      for (const queryHost of hostsToCheck) {
        const txtRecords = await queryTxt(queryHost);
        if (matchesTxtVerificationToken(txtRecords, expectedToken)) {
          this.markVerified(domain, 'dns-txt');
          return this.getStatus(domain);
        }
      }
      const status = this.getStatus(domain);
      return {
        ...status,
        verified: false,
        error: `DNS TXT record "${expectedToken}" not found at _sentinelglobe-verify.${domain} or ${domain}.`,
      };
    }

    // HTTP well-known verification file check with strict SSRF defense
    const pathsToCheck = [
      `https://${domain}/.well-known/sentinelglobe-verify.txt`,
      `https://${domain}/sentinelglobe-verify.html`,
    ];

    for (const candidateUrl of pathsToCheck) {
      try {
        await assertSafePublicUrl(candidateUrl);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
          const res = await fetch(candidateUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: controller.signal,
            headers: { 'User-Agent': 'SentinelGlobe-OwnershipVerifier/1.0' },
          });
          if (res.ok) {
            const text = (await res.text()).slice(0, 4096);
            if (matchesHttpVerificationBody(text, expectedToken)) {
              this.markVerified(domain, 'http-file');
              return this.getStatus(domain);
            }
          }
        } finally {
          clearTimeout(timer);
        }
      } catch {
        // try next well-known path
      }
    }

    const status = this.getStatus(domain);
    return {
      ...status,
      verified: false,
      error: `Verification file containing "${expectedToken}" was not found at https://${domain}/.well-known/sentinelglobe-verify.txt or /sentinelglobe-verify.html.`,
    };
  }
}

async function queryTxt(name: string): Promise<string[]> {
  try {
    return (await resolveTxt(name)).map((parts) => parts.join(''));
  } catch {
    return [];
  }
}

export const domainVerificationStore = new DomainVerificationStore();
