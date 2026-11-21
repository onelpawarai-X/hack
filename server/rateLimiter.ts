import type { NextFunction, Request, Response } from 'express';

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
}

export class SlidingWindowRateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly hits = new Map<string, number[]>();

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  check(key: string, now = Date.now()): RateLimitDecision {
    const cutoff = now - this.windowMs;
    const existing = (this.hits.get(key) ?? []).filter((ts) => ts > cutoff);

    if (existing.length >= this.maxRequests) {
      const oldest = existing[0] ?? now;
      const resetAt = oldest + this.windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - now) / 1000));
      this.hits.set(key, existing);
      return {
        allowed: false,
        remaining: 0,
        resetAt,
        retryAfterSeconds,
      };
    }

    existing.push(now);
    this.hits.set(key, existing);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - existing.length),
      resetAt: (existing[0] ?? now) + this.windowMs,
      retryAfterSeconds: 0,
    };
  }

  reset(): void {
    this.hits.clear();
  }
}

export function extractClientKey(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || 'unknown';
}

export function createRateLimitMiddleware(
  limiter: SlidingWindowRateLimiter,
  scopeLabel: string,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const decision = limiter.check(`${scopeLabel}:${extractClientKey(req)}`);
    res.setHeader('X-RateLimit-Remaining', String(decision.remaining));
    res.setHeader('X-RateLimit-Reset', new Date(decision.resetAt).toISOString());

    if (!decision.allowed) {
      res.setHeader('Retry-After', String(decision.retryAfterSeconds));
      return res.status(429).json({
        error: `Ethical rate limit exceeded for ${scopeLabel}. Please wait ${decision.retryAfterSeconds}s before retrying.`,
        retryAfterSeconds: decision.retryAfterSeconds,
      });
    }
    return next();
  };
}

export async function ethicalProbeDelay(ms = 120): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
