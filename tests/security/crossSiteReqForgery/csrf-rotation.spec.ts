import { test } from '@playwright/test';
import { CsrfRotationProbe } from '../sec-objects/crossSiteReqForgery/csrf-rotation.logic';

/**
 * CSRF Token Rotation Tests
 *
 * These tests verify that CSRF tokens are properly rotated/invalidated after significant security events
 * to prevent Cross-Site Request Forgery attacks and session fixation vulnerabilities.
 *
 * CSRF tokens should be rotated when:
 * 1. User logs in (prevents session fixation)
 * 2. User logs out (invalidates old tokens)
 * 3. Sensitive operations like password changes occur
 */

test('CSRF: browser token rotates after login', async ({ page }, testInfo) => {
  await new CsrfRotationProbe().verifyTokenRotatesAfterLogin(page, testInfo);
});

test('CSRF: browser token invalidated after logout', async ({ page }, testInfo) => {
  await new CsrfRotationProbe().verifyTokenInvalidatedAfterLogout(page, testInfo);
});

test('CSRF: browser token rotates after a sensitive action', async ({ page }, testInfo) => {
  await new CsrfRotationProbe().verifyTokenRotatesAfterSensitiveAction(page, testInfo);
});
