import { test } from '@playwright/test';
import { CsrfValidationProbe } from '../sec-objects/crossSiteReqForgery/csrf-validation.logic';

/**
 * CSRF Token Validation Tests
 *
 * These tests verify that the application properly validates CSRF tokens to prevent
 * Cross-Site Request Forgery attacks. CSRF attacks occur when malicious websites
 * trick users into performing unwanted actions on authenticated applications.
 *
 * Security Risks Addressed:
 * 1. Missing CSRF token protection
 * 2. Invalid token acceptance
 * 3. Improper cookie configuration
 * 4. Token leakage in URLs
 *
 * Expected Behavior:
 * - State-changing requests must include valid CSRF tokens
 * - Invalid tokens should be rejected with 403/401 status
 * - Session cookies should have proper SameSite attributes
 * - Tokens should not be exposed in URLs
 */

test('CSRF: requests without token are rejected', async ({ request }, testInfo) => {
  await new CsrfValidationProbe().verifyRequestsWithoutTokenAreRejected(request, testInfo);
});

test('CSRF: invalid token is rejected', async ({ request }, testInfo) => {
  await new CsrfValidationProbe().verifyInvalidTokensAreRejected(request, testInfo);
});

test('CSRF: SameSite cookie attribute set', async ({ request }, testInfo) => {
  await new CsrfValidationProbe().verifySameSiteCookieAttribute(request, testInfo);
});

test('CSRF: double submit cookie pattern or synchronizer token', async ({ page }, testInfo) => {
  await new CsrfValidationProbe().verifyProtectionImplementation(page, testInfo);
});

test('CSRF: token not leaked in URL', async ({ page }, testInfo) => {
  await new CsrfValidationProbe().verifyTokenNotLeakedInUrl(page, testInfo);
});
