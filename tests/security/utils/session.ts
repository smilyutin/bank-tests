import { APIRequestContext, BrowserContext, Page } from '@playwright/test';

export type StorageSnapshot = {
  local: string[];
  session: string[];
};

export type AuthCookieSummary = {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: string | null;
  expires?: number;
};

// Keep storage snapshots in a simple, serializable shape.
export function getStorageSnapshotFromKeys(local: string[], session: string[]): StorageSnapshot {
  return { local, session };
}

// Truncate cookie values so reports do not expose full secrets.
export function summarizeCookies(cookies: Array<{ name: string; value: string; httpOnly: boolean; secure: boolean; sameSite?: string | null; expires?: number }>): AuthCookieSummary[] {
  return cookies.map(c => ({
    name: c.name,
    value: c.value ? (c.value.length > 32 ? `${c.value.slice(0, 32)}...` : c.value) : '',
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: c.sameSite,
    expires: c.expires,
  }));
}

// Find the first cookie that looks like an auth/session token.
export function findAuthCookie(cookies: Array<{ name: string; httpOnly: boolean; secure: boolean; sameSite?: string | null }>) {
  return cookies.find(c =>
    c.name.toLowerCase().includes('auth') ||
    c.name.toLowerCase().includes('token') ||
    c.name.toLowerCase().includes('session')
  ) || null;
}

// Capture the current localStorage and sessionStorage keys from the page.
export async function captureStorageKeys(page: Page): Promise<StorageSnapshot> {
  return page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));
}

// Return any storage keys that look sensitive.
export function getSensitiveStorageKeys(storage: StorageSnapshot): string[] {
  return storage.local.concat(storage.session).filter(key =>
    key.toLowerCase().includes('token') ||
    key.toLowerCase().includes('auth') ||
    key.toLowerCase().includes('password') ||
    key.toLowerCase().includes('secret')
  );
}

// Read all cookies from the active browser context.
export async function getContextCookies(context: BrowserContext) {
  return context.cookies();
}

// Probe protected endpoints to see whether a bearer token is accepted.
export async function isTokenAcceptedOnAnyEndpoint(
  api: APIRequestContext,
  token: string,
  protectedEndpoints: string[]
): Promise<boolean> {
  for (const endpoint of protectedEndpoints) {
    try {
      const res = await api.get(endpoint, {
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => null);

      if (res && res.status() === 200) return true;
    } catch {
      // continue
    }
  }
  return false;
}
