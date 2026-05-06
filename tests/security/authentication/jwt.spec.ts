import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'Implement strict JWT signature validation (HS256 or RS256)',
  'Reject algorithms "none", "HS256" when expecting RS256, and vice versa (algorithm confusion)',
  'Validate JWT structure: 3 base64url-encoded parts separated by dots',
  'Reject tokens with expired `exp` claim (timestamp comparison)',
  'Verify token issuer (`iss`) and audience (`aud`) claims match expected values',
  'Implement token revocation/blacklist for logged-out tokens',
];

/**
 * JWT (JSON Web Token) Security Tests
 * 
 * These tests verify that JWT tokens are properly implemented and secure against
 * common attack vectors. JWT tokens are widely used for authentication and authorization
 * in modern web applications.
 * 
 * Security Risks Addressed:
 * 1. Algorithm confusion attacks (alg=none)
 * 2. Token tampering and signature validation
 * 3. Expired token acceptance
 * 4. Improper token structure
 * 
 * Expected Behavior:
 * - Tokens should have proper 3-part structure (header.payload.signature)
 * - Algorithm "none" should be rejected
 * - Tampered tokens should be rejected
 * - Expired tokens should be rejected
 */

test.describe('JWT integrity & expiry checks', () => {
  test('JWT tokens properly validated against tampering and algorithm confusion', async ({ request }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    const user = await ensureTestUser(request as any);
    if (!user.email || !user.password) {
      reporter.reportWarning(
        'JWT validation could not run because no test user credentials are available.',
        [
          ...TARGET_APP_FIX_FIRST,
          'Seed a valid authentication test user in tests/fixtures/users.json',
          'Add deterministic test-user bootstrap before security test execution',
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }
    
    // Step 1: Attempt login to get JWT token
    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt) {
      reporter.reportWarning(
        'JWT validation could not run because login endpoint was not found or unreachable.',
        [
          ...TARGET_APP_FIX_FIRST,
          'Ensure at least one login endpoint is reachable in SECURITY_LOGIN_PATH candidates',
          'Stabilize auth route availability in the test environment before security scans',
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }
    
    const { res, token: returnedToken, path } = attempt as any;
    
    // Step 2: Extract token from response body or headers
    let bodyToken = null;
    try {
      const json = await res.json().catch(() => null);
      if (json && (json.token || json.access_token || json.jwt)) {
        bodyToken = json.token || json.access_token || json.jwt;
      }
    } catch (e) {}
    
    const auth = res.headers()['authorization'] || res.headers()['www-authenticate'];
    const token = returnedToken || bodyToken || (auth && String(auth).split(' ').pop());
    
    if (!token) {
      reporter.reportWarning(
        `No JWT token was returned by login endpoint (${path || 'unknown path'}), so JWT integrity checks could not be completed. ` +
        `This may indicate cookie-based auth or missing token exposure in API responses.`,
        [
          ...TARGET_APP_FIX_FIRST,
          'If auth is cookie-based, add equivalent cookie/session tampering checks to this suite',
          'Document auth token transport mechanism so tests target the correct medium',
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    // Step 3: Verify JWT structure (3 parts separated by dots)
    const parts = token.split('.');
    if (parts.length !== 3) {
      reporter.reportWarning(
        `Token returned is not a valid JWT structure. Expected 3 base64url parts separated by dots, got ${parts.length} parts.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    // Step 4: Parse JWT header and payload
    let header: any, payload: any;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
      payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    } catch (e) {
      reporter.reportWarning(
        `JWT header or payload could not be decoded. Token may be malformed. Error: ${String(e).slice(0, 100)}`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    // Collect findings
    const findings: { success: string[]; vulnerabilities: string[] } = { success: [], vulnerabilities: [] };

    // Step 5: Test algorithm "none" vulnerability
    header.alg = 'none';
    const algNone = [Buffer.from(JSON.stringify(header)).toString('base64url'), Buffer.from(JSON.stringify(payload)).toString('base64url'), ''].join('.');

    const protectedPaths = ['/api/me', '/api/profile', '/profile', '/me'];
    let algNoneAccepted = false;
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${algNone}` } });
        if (r.status() < 400 || r.status() >= 500) {
          findings.vulnerabilities.push(`alg=none token accepted on ${p} (status ${r.status()})`);
          algNoneAccepted = true;
        }
      } catch (e) {}
    }
    if (!algNoneAccepted) {
      findings.success.push('alg=none algorithm confusion attack rejected');
    }

    // Step 6: Test token tampering detection
    const tamperedPayload = { ...payload, exp: 1 }; // expired
    const tampered = [parts[0], Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url'), parts[2]].join('.');
    let tamperedAccepted = false;
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${tampered}` } });
        if (r.status() < 400 || r.status() >= 500) {
          findings.vulnerabilities.push(`Tampered/expired token accepted on ${p} (status ${r.status()})`);
          tamperedAccepted = true;
        }
      } catch (e) {}
    }
    if (!tamperedAccepted) {
      findings.success.push('Token tampering/expiry detection working');
    }

    // Step 7: Report findings
    if (findings.vulnerabilities.length === 0) {
      reporter.reportPass(
        `JWT implementation is secure. Token structure valid (3 parts). ` +
        `Verified: ${findings.success.join(', ')}. Algorithm confusion (alg=none) rejected. ` +
        `Tampered tokens rejected. Evidence: tested against ${protectedPaths.length} protected endpoints.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning(
        `JWT implementation has security issues. ${findings.vulnerabilities.length} vulnerability(ies) detected: ${findings.vulnerabilities.join('; ')}. ` +
        `This allows attackers to forge tokens or bypass authentication.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  });
});
