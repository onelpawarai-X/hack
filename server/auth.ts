import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { db } from './db.ts';

const SESSION_COOKIE = 'sentinel_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

export interface AuthUser {
  id: string;
  username: string;
  role: string;
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPasswordHash(password: string, stored: string): boolean {
  const [scheme, salt, digest] = stored.split('$');
  if (scheme !== 'scrypt' || !salt || !digest) return false;
  const derived = scryptSync(password, salt, 64);
  const expected = Buffer.from(digest, 'hex');
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  const cookies: Record<string, string> = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

export function hasAdminUser(): boolean {
  const row = db.prepare('SELECT COUNT(*) AS count FROM users').get() as { count: number };
  return Number(row?.count ?? 0) > 0;
}

export function createAdminUser(username: string, password: string): AuthUser {
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters.');
  }
  const cleanUsername = username.trim().slice(0, 64) || 'admin';
  const id = `user-${randomBytes(8).toString('hex')}`;
  db.prepare(
    'INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(id, cleanUsername, hashPassword(password), 'admin', new Date().toISOString());
  return { id, username: cleanUsername, role: 'admin' };
}

export function ensureEnvAdmin(): void {
  const password = process.env.SENTINEL_ADMIN_PASSWORD;
  if (!password || hasAdminUser()) return;
  try {
    createAdminUser(process.env.SENTINEL_ADMIN_USERNAME || 'admin', password);
  } catch {
    // Password too short or already created concurrently.
  }
}

export function verifyCredentials(username: string, password: string): AuthUser | null {
  const row = db
    .prepare('SELECT id, username, role, password_hash FROM users WHERE username = ?')
    .get(username.trim()) as
    | { id: string; username: string; role: string; password_hash: string }
    | undefined;
  if (!row) return null;
  if (!verifyPasswordHash(password, row.password_hash)) return null;
  return { id: row.id, username: row.username, role: row.role };
}

export function createSession(user: AuthUser, req: Request): { token: string; expiresAt: string } {
  const token = randomBytes(32).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();
  db.prepare(
    'INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(
    hashToken(token),
    user.id,
    now.toISOString(),
    expiresAt,
    req.ip ?? null,
    typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'].slice(0, 200) : null,
  );
  return { token, expiresAt };
}

export function destroySession(token: string | undefined): void {
  if (!token) return;
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
}

export function cleanupSessions(): void {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
}

export function sessionFromCookie(cookieHeader: string | undefined): AuthUser | null {
  const token = parseCookies(cookieHeader)[SESSION_COOKIE];
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.id, u.username, u.role, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?`,
    )
    .get(hashToken(token)) as
    | { id: string; username: string; role: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    destroySession(token);
    return null;
  }
  return { id: row.id, username: row.username, role: row.role };
}

export function sessionFromRequest(req: Request): AuthUser | null {
  return sessionFromCookie(req.headers.cookie);
}

export function sessionTokenFromRequest(req: Request): string | undefined {
  return parseCookies(req.headers.cookie)[SESSION_COOKIE];
}

export function setSessionCookie(req: Request, res: Response, token: string, expiresAt: string): void {
  const secure =
    req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  const maxAge = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${
      secure ? '; Secure' : ''
    }`,
  );
}

export function clearSessionCookie(res: Response): void {
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
  );
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const user = sessionFromRequest(req);
  if (!user) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }
  res.locals.user = user;
  next();
}

export function authStatus(req: Request): {
  authenticated: boolean;
  user: AuthUser | null;
  hasAdmin: boolean;
  setupRequired: boolean;
  ssoEnabled: boolean;
} {
  const user = sessionFromRequest(req);
  const hasAdmin = hasAdminUser();
  return {
    authenticated: Boolean(user),
    user,
    hasAdmin,
    setupRequired: !hasAdmin,
    ssoEnabled: Boolean(getOidcConfig()),
  };
}

export function getOidcConfig(): OidcConfig | null {
  const issuer = process.env.OIDC_ISSUER?.trim();
  const clientId = process.env.OIDC_CLIENT_ID?.trim();
  const clientSecret = process.env.OIDC_CLIENT_SECRET?.trim();
  const redirectUri = process.env.OIDC_REDIRECT_URI?.trim();
  if (!issuer || !clientId || !clientSecret || !redirectUri) return null;
  return {
    issuer: issuer.replace(/\/$/, ''),
    clientId,
    clientSecret,
    redirectUri,
    scopes: process.env.OIDC_SCOPES?.trim() || 'openid email profile',
  };
}

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
}

async function discoverOidc(config: OidcConfig): Promise<OidcDiscovery> {
  const res = await fetch(`${config.issuer}/.well-known/openid-configuration`, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`OIDC discovery failed (HTTP ${res.status})`);
  const json = (await res.json()) as Partial<OidcDiscovery>;
  if (!json.authorization_endpoint || !json.token_endpoint) {
    throw new Error('OIDC discovery response is missing endpoints');
  }
  return json as OidcDiscovery;
}

const oidcStates = new Map<string, { createdAt: number; nonce: string }>();

export async function buildOidcAuthorizationUrl(): Promise<string> {
  const config = getOidcConfig();
  if (!config) throw new Error('OIDC SSO is not configured.');
  const discovery = await discoverOidc(config);
  const state = randomBytes(24).toString('hex');
  const nonce = randomBytes(16).toString('hex');
  oidcStates.set(state, { createdAt: Date.now(), nonce });
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('scope', config.scopes);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  return url.toString();
}

export async function completeOidcLogin(
  code: string,
  state: string,
): Promise<AuthUser> {
  const config = getOidcConfig();
  if (!config) throw new Error('OIDC SSO is not configured.');
  const stateEntry = oidcStates.get(state);
  oidcStates.delete(state);
  if (!stateEntry || Date.now() - stateEntry.createdAt > 10 * 60_000) {
    throw new Error('OIDC state is invalid or expired.');
  }

  const discovery = await discoverOidc(config);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
  });
  const tokenRes = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });
  if (!tokenRes.ok) throw new Error(`OIDC token exchange failed (HTTP ${tokenRes.status})`);
  const tokenJson = (await tokenRes.json()) as { access_token?: string; id_token?: string };
  if (!tokenJson.access_token) throw new Error('OIDC token response has no access token.');

  let email = '';
  let name = '';
  if (discovery.userinfo_endpoint) {
    const infoRes = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokenJson.access_token}`, Accept: 'application/json' },
    });
    if (infoRes.ok) {
      const info = (await infoRes.json()) as { email?: string; name?: string; preferred_username?: string };
      email = info.email ?? '';
      name = info.name ?? info.preferred_username ?? '';
    }
  }

  const username = (email || name || `sso-${randomBytes(4).toString('hex')}`).slice(0, 64);
  const existing = db
    .prepare('SELECT id, username, role FROM users WHERE username = ?')
    .get(username) as { id: string; username: string; role: string } | undefined;
  if (existing) return existing;

  const id = `user-${randomBytes(8).toString('hex')}`;
  db.prepare(
    'INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(id, username, 'sso$disabled', 'admin', new Date().toISOString());
  return { id, username, role: 'admin' };
}
