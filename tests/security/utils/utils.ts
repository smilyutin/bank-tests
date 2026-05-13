import { APIRequestContext, request as playwrightRequest, TestInfo } from '@playwright/test';
import { loadUsers, createRandomUser, saveUser } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

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

// Return the configured login candidates, or the default list when no override is set.
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

// Parse common cookie attributes from a Set-Cookie header.
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

// Extract a cookie value by name from one or more Set-Cookie headers.
export function parseSetCookieValue(setCookieHeader: string, name: string): string | null {
  // setCookieHeader may contain multiple cookies separated by comma in some contexts
  const parts = Array.isArray(setCookieHeader) ? setCookieHeader : String(setCookieHeader).split(/,(?=\s*[^\s]+=)/);
  for (const p of parts) {
    const m = p.match(new RegExp('(?:^|; )' + name + '=(?<val>[^;]+)'));
    if (m && m.groups && m.groups.val) return decodeURIComponent(m.groups.val);
  }
  return null;
}

// Map a soft-check message to an OWASP category.
function inferSoftCheckCategory(message: string): string {
  const m = message.toLowerCase();

  if (m.includes('cors') || m.includes('header') || m.includes('hsts') || m.includes('csp') || m.includes('referrer') || m.includes('nosniff') || m.includes('frame')) {
    return OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name;
  }

  if (m.includes('xss') || m.includes('inline') || m.includes('script') || m.includes('inject') || m.includes('injection')) {
    return OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name;
  }

  if (m.includes('csrf') || m.includes('token') || m.includes('session') || m.includes('auth') || m.includes('login') || m.includes('password')) {
    return OWASP_VULNERABILITIES.API2_AUTH.name;
  }

  return OWASP_VULNERABILITIES.API9_ASSET_MGMT.name;
}

// Generate remediation suggestions based on the soft-check message content.
function inferSoftCheckRecommendations(message: string): string[] {
  const m = message.toLowerCase();

  if (m.includes('cors')) {
    return [
      'Use a strict allowlist for trusted origins and do not reflect arbitrary Origin values.',
      'Return no CORS allow-origin header for untrusted origins and include Vary: Origin when CORS is used.',
      'Avoid wildcard origin when credentials are enabled.'
    ];
  }

  if (m.includes('referrer-policy') || m.includes('header') || m.includes('csp') || m.includes('hsts') || m.includes('nosniff') || m.includes('frame')) {
    return [
      'Set required security headers globally at proxy or middleware level.',
      'Use secure header values aligned with OWASP recommendations.',
      'Add automated security-header regression checks in CI.'
    ];
  }

  if (m.includes('xss') || m.includes('inline') || m.includes('script') || m.includes('injection')) {
    return [
      'Sanitize and encode untrusted input before rendering to HTML or JavaScript contexts.',
      'Eliminate inline scripts/handlers and enforce CSP without unsafe-inline.',
      'Add negative tests for reflected and stored payloads in CI.'
    ];
  }

  if (m.includes('csrf') || m.includes('token')) {
    return [
      'Require anti-CSRF tokens for state-changing operations and validate them server-side.',
      'Rotate CSRF/session tokens on login and privilege changes.',
      'Use SameSite cookies and origin/referer validation for additional protection.'
    ];
  }

  if (m.includes('auth') || m.includes('login') || m.includes('password') || m.includes('session')) {
    return [
      'Enforce strong authentication/session controls and explicit access checks.',
      'Harden credential handling and add rate limiting for auth endpoints.',
      'Add monitoring and alerting for suspicious authentication events.'
    ];
  }

  return [
    'Review this security control against OWASP API Security Top 10 guidance.',
    'Document expected secure behavior and enforce it with regression tests.',
    'Apply least-privilege and secure-by-default configuration principles.'
  ];
}

// Report a warning when a soft check fails, using inferred category and recommendations.
export function softCheck(info: TestInfo, condition: boolean, message: string) {
  if (condition) return;

  const reporter = new SecurityReporter(info);
  reporter.reportWarning(
    message,
    inferSoftCheckRecommendations(message),
    inferSoftCheckCategory(message)
  );
}

// Probe login endpoints so later tests can use a reachable path if one exists.
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

// Try both JSON and form login styles and return token evidence when available.
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

// Load or create a reusable security test user.
export async function ensureTestUser(request: APIRequestContext) {
  const users = loadUsers();
  if (users && users.length) return users[0];
  const u = createRandomUser('sec');
  saveUser(u);
  return u;
}
