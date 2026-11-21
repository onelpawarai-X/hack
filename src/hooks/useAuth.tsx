import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

export interface AuthUser {
  id: string;
  username: string;
  role: string;
}

export interface AuthStatus {
  authenticated: boolean;
  user: AuthUser | null;
  hasAdmin: boolean;
  setupRequired: boolean;
  ssoEnabled: boolean;
}

interface AuthContextValue {
  status: AuthStatus | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  login: (username: string, password: string) => Promise<boolean>;
  setup: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function readError(res: Response): Promise<string> {
  const payload = (await res.json().catch(() => ({}))) as { error?: string };
  return payload.error || `Request failed (HTTP ${res.status})`;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/status', { cache: 'no-store' });
      if (!res.ok) throw new Error(await readError(res));
      setStatus((await res.json()) as AuthStatus);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication status failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    setError(null);
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      setError(await readError(res));
      return false;
    }
    await refresh();
    return true;
  }, [refresh]);

  const setup = useCallback(async (username: string, password: string) => {
    setError(null);
    const res = await fetch('/api/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      setError(await readError(res));
      return false;
    }
    await refresh();
    return true;
  }, [refresh]);

  const logout = useCallback(async () => {
    await fetch('/api/auth/logout', { method: 'POST' }).catch(() => null);
    setStatus((prev) => (prev ? { ...prev, authenticated: false, user: null } : prev));
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      loading,
      error,
      refresh,
      login,
      setup,
      logout,
      clearError: () => setError(null),
    }),
    [status, loading, error, refresh, login, setup, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside AuthProvider');
  return context;
}
