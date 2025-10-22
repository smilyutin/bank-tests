import { APIRequestContext, request as playwrightRequest, TestInfo } from '@playwright/test';
import { loadUsers, createRandomUser, saveUser } from '../../utils/credentials';

export const LOGIN_CANDIDATES = [
  '/api/login',
  '/login',
  '/auth/login',
  '/sessions',
  '/api/sessions',
  '/api/auth/token',
  '/api/token',
  '/oauth/token',
  '/api/auth/login',
];
export function getLoginCandidates(): string[] {
  const env = process.env.SECURITY_LOGIN_PATH;
  if (env && env.trim()) {
    return env.split(',').map(s => s.trim()).filter(Boolean);
  }
  return LOGIN_CANDIDATES;
}

export type CookieFlags = {
  httpOnly: boolean;
  secure: boolean;
  sameSite?: string | null;
};

export function parseSetCookieFlags(setCookieHeader: string): CookieFlags {
  const parts = setCookieHeader.split(';').map(p => p.trim());
  const flags: CookieFlags = { httpOnly: false, secure: false, sameSite: null };
  for (const p of parts) {
    const low = p.toLowerCase();
    if (low === 'httponly') flags.httpOnly = true;
    if (low === 'secure') flags.secure = true;
    if (low.startsWith('samesite=')) flags.sameSite = p.split('=')[1];
  }
  return flags;
}

export function parseSetCookieValue(setCookieHeader: string, name: string): string | null {
  // setCookieHeader may contain multiple cookies separated by comma in some contexts
  const parts = Array.isArray(setCookieHeader) ? setCookieHeader : String(setCookieHeader).split(/,(?=\s*[^\s]+=)/);
  for (const p of parts) {
    const m = p.match(new RegExp('(?:^|; )' + name + '=(?<val>[^;]+)'));
    if (m && m.groups && m.groups.val) return decodeURIComponent(m.groups.val);
  }
  return null;
}

export function softCheck(info: TestInfo, condition: boolean, message: string) {
  if (condition) return;
  const soft = process.env.SECURITY_SOFT === '1' || process.env.SECURITY_SOFT === 'true';
  if (soft) {
    // Attach an annotation and warn instead of failing the test
    try {
      info.annotations.push({ type: 'security', description: message });
    } catch (e) {
      // ignore
    }
    // eslint-disable-next-line no-console
    console.warn('[SECURITY-WARN]', message);
  } else {
    throw new Error(message);
  }
}

export async function findLoginEndpoint(request: APIRequestContext) {
  for (const path of LOGIN_CANDIDATES) {
    try {
      const res = await request.post(path, { data: {} });
      // If server responds 4xx/5xx we still consider endpoint present; return path for further probing
      if (res) return path;
    } catch (e) {
      // continue
    }
  }
  return null;
}

export async function tryLogin(request: APIRequestContext, email: string, password: string) {
  const candidates = getLoginCandidates();
  const tokenField = process.env.SECURITY_TOKEN_FIELD || 'token';
  const tokenCookie = process.env.SECURITY_TOKEN_COOKIE || 'token';
  // Try a few styles (form, json) and attempt to detect tokens in body/headers/cookies
  for (const path of candidates) {
    try {
      // JSON
      let res = await request.post(path, { data: { email, username: email, password }, headers: { 'content-type': 'application/json' } }).catch(()=>null);
      if (res && res.status() < 600) {
        // try extract token from JSON
        try {
          const json = await res.json().catch(()=>null);
          if (json && (json[tokenField] || json.access_token || json.jwt || json.id_token)) {
            return { res, path, token: json[tokenField] || json.access_token || json.jwt || json.id_token };
          }
        } catch (e) {}
        // check headers
        const auth = res.headers()['authorization'] || res.headers()['x-auth-token'] || res.headers()['www-authenticate'];
        if (auth) {
          const maybe = String(auth).split(' ').pop();
          if (maybe) return { res, path, token: maybe };
        }
        // check set-cookie for token names
        const sc = res.headers()['set-cookie'];
        if (sc) {
          const cookieToken = parseSetCookieValue(String(sc), tokenCookie) || parseSetCookieValue(String(sc), 'jwt') || parseSetCookieValue(String(sc), 'access_token');
          if (cookieToken) return { res, path, token: cookieToken };
        }
        // return res as evidence endpoint exists
        return { res, path };
      }

      // form
      res = await request.post(path, { form: { email, username: email, password } }).catch(()=>null);
      if (res && res.status() < 600) {
        try {
          const json = await res.json().catch(()=>null);
          if (json && (json[tokenField] || json.access_token || json.jwt || json.id_token)) {
            return { res, path, token: json[tokenField] || json.access_token || json.jwt || json.id_token };
          }
        } catch (e) {}
        const auth = res.headers()['authorization'] || res.headers()['x-auth-token'] || res.headers()['www-authenticate'];
        if (auth) {
          const maybe = String(auth).split(' ').pop();
          if (maybe) return { res, path, token: maybe };
        }
        const sc = res.headers()['set-cookie'];
        if (sc) {
          const cookieToken = parseSetCookieValue(String(sc), tokenCookie) || parseSetCookieValue(String(sc), 'jwt') || parseSetCookieValue(String(sc), 'access_token');
          if (cookieToken) return { res, path, token: cookieToken };
        }
        return { res, path };
      }
    } catch (e) {
      // ignore and continue
    }
  }
  return null;
}

export async function ensureTestUser(request: APIRequestContext) {
  const users = loadUsers();
  if (users && users.length) return users[0];
  const u = createRandomUser('sec');
  saveUser(u);
  return u;
}
