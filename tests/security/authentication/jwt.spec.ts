import { test } from '@playwright/test';
import { JwtIntegrityProbe } from '../sec-objects/authentication/jwt.logic';

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
    await new JwtIntegrityProbe().verify(testInfo, request);
  });
});
