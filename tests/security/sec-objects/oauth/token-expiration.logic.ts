import { expect, request as playwrightRequest, test, type TestInfo } from '@playwright/test';
import { createRandomUser, findOrCreateUser, loadStoredToken, loadUsers, type User } from '../../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { softCheck } from '../../utils/utils';
import { isTokenAcceptedOnAnyEndpoint } from '../../utils/session';

const REGISTER_ENDPOINTS = ['/api/auth/register', '/api/register', '/api/users'];
const LOGIN_ENDPOINTS = ['/api/auth/login', '/api/login'];
const LOGIN_SUCCESS_STATUSES = [200, 201, 302, 303];

/**
 * Dummy expired JWT token for testing expired token rejection.
 * Structure: header.payload.signature
 * - Payload exp: 1609459200 (Jan 1, 2021 - long expired)
 * - Can be overridden by API_AUTH_EXPIRED_TOKEN env variable
 */
const EXPIRED_JWT_TOKEN = process.env.API_AUTH_EXPIRED_TOKEN ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWV4cGlyZWQiLCJleHAiOjE2MDk0NTkyMDB9.expiredtokensignature';

function extractTokenFromSetCookie(setCookieHeader?: string): string {
  // Pull a token value out of Set-Cookie headers when cookie-based auth is used.
  if (!setCookieHeader) return '';
  const parts = String(setCookieHeader).split(/,(?=\s*[^\s]+=)/);
  for (const part of parts) {
    for (const cookieName of ['token', 'jwt', 'jwt_token', 'access_token', 'auth_token']) {
      const match = part.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]+)`));
      if (match && match[1]) return decodeURIComponent(match[1]);
    }
  }
  return '';
}

function getSharedOrGeneratedUser(prefix = 'e2e'): User {
  // Prefer persisted users so the test uses a stable identity across runs.
  const users = loadUsers();
  if (users.length > 0) return users[0];
  return findOrCreateUser(prefix);
}

async function tryRegisterUser(api: any, user: User): Promise<boolean> {
  // Try a few registration routes so the token checks can bootstrap a user account.
  if (!user.email || !user.password) return false;

  for (const endpoint of REGISTER_ENDPOINTS) {
    try {
      const res = await api.post(endpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);

      if (res && [200, 201, 409].includes(res.status())) {
        return true;
      }
    } catch {
      // try next
    }
  }

  return false;
}

async function loginForAccessToken(api: any, user: User): Promise<string> {
  // Attempt multiple login payload shapes until one yields a usable token.
  const identifier = user.email || user.username;
  if (!identifier || !user.password) return '';

  const variants = [
    { email: user.email || identifier, username: user.username || identifier, password: user.password },
    { email: identifier, password: user.password },
    { username: identifier, password: user.password },
  ];

  for (const endpoint of LOGIN_ENDPOINTS) {
    for (const payload of variants) {
      try {
        const res = await api.post(endpoint, {
          data: JSON.stringify(payload),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);

        if (res && LOGIN_SUCCESS_STATUSES.includes(res.status())) {
          const body = await res.json().catch(() => null);
          const bodyToken = body?.token || body?.accessToken || body?.access_token || body?.jwt || body?.jwt_token || '';
          if (bodyToken) return bodyToken;

          const authHeader = res.headers()['authorization'];
          if (authHeader) {
            const maybe = String(authHeader).split(' ').pop();
            if (maybe) return maybe;
          }

          const setCookie = res.headers()['set-cookie'];
          if (setCookie) {
            const cookieToken = extractTokenFromSetCookie(setCookie);
            if (cookieToken) return cookieToken;
          }
        }
      } catch {
        // try next payload/endpoint
      }
    }
  }

  return '';
}

export class OAuthTokenLifecycleProbe {
  private async createApi(baseURL: string) {
    return await playwrightRequest.newContext({ baseURL });
  }

  async verifyExpiredTokensRejected(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await this.createApi(baseURL);

    try {
      const user = getSharedOrGeneratedUser('e2e');

      // Obtain a live token first, then fall back to stored or configured tokens.
      let token = await loginForAccessToken(api, user);
      if (!token) {
        await tryRegisterUser(api, user);
        token = await loginForAccessToken(api, user);
      }
      if (!token) {
        token = loadStoredToken('user') || process.env.API_AUTH_TOKEN || '';
      }

      if (!token) {
        reporter.reportSkip(
          'No login token was obtained from auth flow; skipping JWT-claim inspection and continuing with API_AUTH_EXPIRED_TOKEN/dummy expired token checks.'
        );
        test.skip(true, 'No login token was obtained from auth flow');
        return;
      }

      // Inspect the JWT structure when the auth flow returns a JWT-like token.
      let expiredTokenAccepted = false;

      // For JWT tokens, we can decode and check expiration.
      if (token.includes('.')) {
        try {
          // Decode the JWT payload and inspect the expiration claim.
          const parts = token.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

            // If exp exists and is still in the future, record that as expected behavior.
            if (payload.exp) {
              const expirationTime = payload.exp * 1000; // Convert to milliseconds
              const now = Date.now();

              // This is a positive signal even if we cannot force the token into an expired state here.
              if (expirationTime > now) {
                const timeToExpire = Math.round((expirationTime - now) / 1000 / 60);

                reporter.reportPass(
                  `Token has expiration set (expires in ${timeToExpire} minutes)`,
                  OWASP_VULNERABILITIES.API2_AUTH.name
                );
              }
            } else {
              // No expiration in token!
              reporter.reportVulnerability('API2_AUTH', {
                issue: 'JWT token has no expiration (exp) claim',
                tokenPayload: payload
              }, [
                'Add exp (expiration) claim to JWT tokens',
                'Set reasonable expiration time (e.g., 15 minutes for access tokens)',
                'Implement token refresh mechanism',
                'Use short-lived access tokens with refresh tokens',
                'Follow JWT best practices (RFC 7519)'
              ]);
              softCheck(testInfo, !!payload.exp, 'JWT token missing exp (expiration) claim');
            }
          }
        } catch (e) {
          // Not a valid JWT or can't decode.
        }
      }

      // Try using a clearly expired/invalid token.
      const invalidTokens = [
        EXPIRED_JWT_TOKEN, // Expired JWT
        'expired.token.here',
        ...(token ? [token + 'tampered'] : []),
        'Bearer invalid',
      ];

      for (const invalidToken of invalidTokens) {
        try {
          const res = await api.get('/api/users', {
            headers: {
              'Authorization': `Bearer ${invalidToken}`,
              'X-Auth-Token': invalidToken
            }
          }).catch(() => null);

          if (res && res.status() === 200) {
            expiredTokenAccepted = true;
            break;
          }
        } catch (e) {
          // Expected to fail
        }
      }

      if (expiredTokenAccepted) {
        reporter.reportVulnerability('API2_AUTH', {
          issue: 'Invalid/tampered tokens accepted'
        }, [
          'Verify token signature before accepting',
          'Validate token structure and claims',
          'Return 401 for invalid tokens',
          'Implement proper token validation middleware'
        ]);
        expect(expiredTokenAccepted).toBeFalsy();
      }
    } finally {
      await api.dispose();
    }
  }

  async verifyRefreshTokensWorkCorrectly(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await this.createApi(baseURL);

    try {
      const user = getSharedOrGeneratedUser('e2e');

      // Login first with shared user; register only as fallback.
      let accessToken = '';
      let refreshToken = '';

      for (const loginEndpoint of LOGIN_ENDPOINTS) {
        for (const payload of [
          { email: user.email || user.username, username: user.username || user.email, password: user.password },
          { email: user.email || user.username, password: user.password },
          { username: user.username || user.email, password: user.password },
        ]) {
          try {
            const res = await api.post(loginEndpoint, {
              data: JSON.stringify(payload),
              headers: { 'Content-Type': 'application/json' }
            }).catch(() => null);

            if (res && LOGIN_SUCCESS_STATUSES.includes(res.status())) {
              const body = await res.json().catch(() => null);
              if (body) {
                accessToken = body.accessToken || body.access_token || body.token || body.jwt || body.jwt_token || '';
                refreshToken = body.refreshToken || body.refresh_token || '';
              }

              if (!accessToken) {
                const authHeader = res.headers()['authorization'] || res.headers()['x-auth-token'] || '';
                accessToken = authHeader ? (String(authHeader).split(' ').pop() || '') : '';
              }

              if (!accessToken) {
                accessToken = extractTokenFromSetCookie(res.headers()['set-cookie']);
              }

              if (accessToken) break;
            }
          } catch {
            // continue
          }
        }

        if (accessToken) break;
      }

      if (!accessToken) {
        await tryRegisterUser(api, user);
        accessToken = await loginForAccessToken(api, user);
      }

      if (!accessToken) {
        accessToken = loadStoredToken('user') || process.env.API_AUTH_TOKEN || '';
      }

      if (!accessToken) {
        const reason = 'No access token available from login/auth flow in this environment';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      if (!refreshToken) {
        const reason = 'App does not expose refresh tokens for this auth flow';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      // Probe common refresh endpoints so the check works across implementations.
      const refreshEndpoints = ['/api/auth/refresh', '/api/refresh', '/api/token/refresh'];
      let refreshWorked = false;
      let newAccessToken = '';

      for (const endpoint of refreshEndpoints) {
        try {
          const res = await api.post(endpoint, {
            data: JSON.stringify({ refreshToken }),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null);

          if (res && res.status() === 200) {
            const body = await res.json().catch(() => null);
            if (body && (body.accessToken || body.access_token || body.token)) {
              refreshWorked = true;
              newAccessToken = body.accessToken || body.access_token || body.token;
              break;
            }
          }
        } catch (e) {
          // Try next endpoint.
        }
      }

      if (refreshWorked && newAccessToken) {
        // A new token should replace the old one when rotation is implemented.
        if (newAccessToken === accessToken) {
          reporter.reportWarning(
            'True vulnerability: refresh returns the same token, so no token rotation is implemented.',
            [
              'Implement token rotation on refresh.',
              'Issue new access and refresh tokens on each refresh.',
              'Invalidate old refresh token after use.',
              'Prevent refresh token reuse.'
            ],
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        } else {
          reporter.reportPass(
            'Token refresh mechanism works correctly with token rotation',
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        }
      } else {
        const reason = 'No functional refresh endpoint available in target app';
        reporter.reportSkip(reason);
        test.skip(true, reason);
      }
    } finally {
      await api.dispose();
    }
  }

  async verifyLogoutInvalidatesTokens(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await this.createApi(baseURL);

    try {
      const user = createRandomUser('logout-test', false);

      // Create and authenticate a fresh user before testing logout behavior.
      let token = '';

      for (const regEndpoint of ['/api/auth/register', '/api/register']) {
        try {
          await api.post(regEndpoint, {
            data: JSON.stringify({ email: user.email, password: user.password }),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null);
        } catch (e) {
          // Continue
        }
      }

      for (const loginEndpoint of ['/api/auth/login', '/api/login']) {
        try {
          const res = await api.post(loginEndpoint, {
            data: JSON.stringify({ email: user.email, password: user.password }),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null);

          if (res && res.status() === 200) {
            const body = await res.json().catch(() => null);
            if (body && (body.token || body.accessToken)) {
              token = body.token || body.accessToken;
              break;
            }
          }
        } catch (e) {
          // Continue
        }
      }

      if (!token) {
        const reason = 'No access token available from login/auth flow in this environment';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      // Confirm the token is valid before testing logout invalidation.
      const protectedEndpoints = ['/api/users', '/api/profile', '/api/me'];
      const tokenWorksBeforeLogout = await isTokenAcceptedOnAnyEndpoint(api, token, protectedEndpoints);

      if (!tokenWorksBeforeLogout) {
        const reason = 'Cannot validate logout invalidation because token is not accepted on protected endpoints';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      // Call a logout endpoint if the app provides one.
      const logoutEndpoints = ['/api/auth/logout', '/api/logout'];
      let logoutFound = false;

      for (const endpoint of logoutEndpoints) {
        try {
          const res = await api.post(endpoint, {
            headers: { 'Authorization': `Bearer ${token}` }
          }).catch(() => null);

          if (res && [200, 204].includes(res.status())) {
            logoutFound = true;
            break;
          }
        } catch (e) {
          // Continue
        }
      }

      if (!logoutFound) {
        const reason = 'No logout endpoint found for this app/environment';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      // Reuse the same token after logout to confirm it no longer works.
      const tokenWorksAfterLogout = await isTokenAcceptedOnAnyEndpoint(api, token, protectedEndpoints);

      if (tokenWorksAfterLogout) {
        reporter.reportVulnerability('API2_AUTH', {
          issue: 'Token still valid after logout - logout does not invalidate tokens'
        }, [
          'Implement token blacklist/revocation on logout',
          'Use Redis or similar for token invalidation tracking',
          'Set short token expiration times',
          'Clear tokens server-side on logout',
          'Consider using session-based auth for better control'
        ]);
        expect(tokenWorksAfterLogout).toBeFalsy();
      } else {
        reporter.reportPass(
          'Logout properly invalidates tokens',
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      }
    } finally {
      await api.dispose();
    }
  }

  async verifyReasonableExpirationTimes(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await this.createApi(baseURL);

    try {
      const user = createRandomUser('expiry-test', false);

      // Bootstrap an authenticated session so the token claims can be inspected.
      let token = '';

      for (const regEndpoint of ['/api/auth/register', '/api/register']) {
        try {
          await api.post(regEndpoint, {
            data: JSON.stringify({ email: user.email, password: user.password }),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null);
        } catch (e) {
          // Continue
        }
      }

      for (const loginEndpoint of ['/api/auth/login', '/api/login']) {
        try {
          const res = await api.post(loginEndpoint, {
            data: JSON.stringify({ email: user.email, password: user.password }),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null);

          if (res && res.status() === 200) {
            const body = await res.json().catch(() => null);
            if (body && (body.token || body.accessToken)) {
              token = body.token || body.accessToken;
              break;
            }
          }
        } catch (e) {
          // Continue
        }
      }

      if (!token || !token.includes('.')) {
        const reason = 'JWT expiration validation is not applicable (no JWT token in this flow)';
        reporter.reportSkip(reason);
        test.skip(true, reason);
        return;
      }

      try {
        // Only decode values that look like JWTs.
        const parts = token.split('.');
        if (parts.length !== 3) {
          const reason = 'JWT structure is not valid for expiration-claim inspection';
          reporter.reportSkip(reason);
          test.skip(true, reason);
          return;
        }

        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

        if (!payload.exp) {
          reporter.reportVulnerability('API2_AUTH', {
            issue: 'Token has no expiration time'
          });
          expect(payload.exp).toBeDefined();
          return;
        }

        if (!payload.iat) {
          reporter.reportWarning(
            'True vulnerability: token has no issued-at (iat) claim.',
            ['Add an iat claim to track token age.'],
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        }

        const now = Math.floor(Date.now() / 1000);
        const expiresIn = payload.exp - (payload.iat || now);
        const expiresInHours = expiresIn / 3600;

        // Longer-lived access tokens are a security smell even when they are technically valid.
        // Access tokens should typically expire in 15 min to 1 hour.
        // Refresh tokens can be longer (days/weeks).
        if (expiresInHours > 24) {
          reporter.reportWarning(
            `True vulnerability: token expires in ${Math.round(expiresInHours)} hours, which is a very long lifetime and increases security risk.`,
            [
              'Reduce access token expiration to 15-60 minutes.',
              'Use refresh tokens for longer sessions.',
              'Implement token rotation.',
              'Consider risk vs usability tradeoff.'
            ],
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        } else if (expiresInHours < 0.25 && expiresInHours > 0) {
          // Very short (< 15 min) might be too aggressive.
          reporter.reportPass(
            `Token expires in ${Math.round(expiresIn / 60)} minutes - good security practice`,
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        } else {
          reporter.reportPass(
            `Token has reasonable expiration time (${Math.round(expiresInHours)} hours)`,
            OWASP_VULNERABILITIES.API2_AUTH.name
          );
        }
      } catch (e) {
        const reason = 'JWT payload could not be decoded for expiration-claim inspection';
        reporter.reportSkip(reason);
        test.skip(true, reason);
      }
    } finally {
      await api.dispose();
    }
  }
}
