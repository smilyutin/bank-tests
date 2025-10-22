import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

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

/**
 * Test: JWT integrity and expiry checks
 * 
 * Purpose: Verifies that JWT tokens are properly structured and validated,
 * protecting against common JWT vulnerabilities like algorithm confusion and token tampering.
 * 
 * Security Impact: JWT vulnerabilities can lead to:
 * - Authentication bypass through algorithm confusion
 * - Token forgery through signature tampering
 * - Session hijacking through expired token reuse
 * - Privilege escalation through token manipulation
 * 
 * Test Strategy:
 * 1. Extract JWT token from login response
 * 2. Verify token structure (3 parts separated by dots)
 * 3. Test algorithm "none" vulnerability
 * 4. Test token tampering detection
 * 5. Verify expired token rejection
 */
// Heuristic JWT checks: non-destructive. Will skip if no JWT is returned by login.
test.describe('JWT integrity & expiry checks', () => {
  test('Login returns JWT (skip if app uses cookies)', async ({ request }, testInfo) => {
    const user = await ensureTestUser(request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    
    // Step 1: Attempt login to get JWT token
    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt) {
      test.skip(true, 'Login endpoint not found');
      return;
    }
    
    const { res, token: returnedToken, path } = attempt as any;
    if (returnedToken) {
      softCheck(testInfo, true, `Login returned token via ${path}`);
    }
    
    // Step 2: Extract token from response body
    // Check common JWT token field names
    let bodyToken = null;
    try {
      const json = await res.json().catch(()=>null);
      if (json && (json.token || json.access_token || json.jwt)) bodyToken = json.token || json.access_token || json.jwt;
    } catch (e) {}
    
    // Step 3: Check for token in Authorization headers
    const auth = res.headers()['authorization'] || res.headers()['www-authenticate'];
    softCheck(testInfo, !!bodyToken || !!auth, 'No JWT-like token returned by login (skipping JWT tests)');
    if (!bodyToken && !auth) test.skip(true, 'No JWT returned');

    // Step 4: Parse and validate token
    const token = returnedToken || bodyToken || (auth && String(auth).split(' ').pop());
    if (!token) {
      test.skip(true, 'Token not parseable');
      return;
    }

    // Step 5: Verify JWT structure (3 parts separated by dots)
    const parts = token.split('.');
    softCheck(testInfo, parts.length === 3, 'Token is not a JWT (dot-separated 3 parts)');
    if (parts.length !== 3) return;

    // Step 6: Parse JWT header and payload
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));

    // Step 7: Test algorithm "none" vulnerability
    // This is a critical vulnerability where alg=none tokens are accepted
    header.alg = 'none';
    const algNone = [Buffer.from(JSON.stringify(header)).toString('base64url'), Buffer.from(JSON.stringify(payload)).toString('base64url'), ''].join('.');

    // Step 8: Test alg=none token against protected endpoints
    const protectedPaths = ['/api/me', '/api/profile', '/profile', '/me'];
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${algNone}` } });
        // Expect rejection (401/403) or at least not 2xx
        softCheck(testInfo, r.status() >= 400 && r.status() < 500, `alg=none token was accepted on ${p} (status ${r.status()})`);
      } catch (e) {
        // ignore
      }
    }

    // Step 9: Test token tampering detection
    // Modify payload and reuse signature (invalid signature) should be rejected
    const tamperedPayload = { ...payload, exp: 1 }; // expired
    const tampered = [parts[0], Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url'), parts[2]].join('.');
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${tampered}` } });
        softCheck(testInfo, r.status() >= 400 && r.status() < 500, `Tampered/expired token was accepted on ${p} (status ${r.status()})`);
      } catch (e) {}
    }
  });
});
