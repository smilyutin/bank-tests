import { test } from '@playwright/test';
import { BrokenAuthenticationProbe } from '../sec-objects/authentication/broken-authentication.logic';

test.describe('Broken authentication checks', () => {
  test('Broken authentication: weak passwords are rejected', async ({ request }, testInfo) => {
    await new BrokenAuthenticationProbe().checkWeakPasswords(request, testInfo);
  });

  test('Broken authentication: no default credentials accepted', async ({ request }, testInfo) => {
    await new BrokenAuthenticationProbe().checkDefaultCredentials(request, testInfo);
  });

  test('Broken authentication: password reset requires verification', async ({ request }, testInfo) => {
    await new BrokenAuthenticationProbe().checkPasswordResetVerification(request, testInfo);
  });

  test('Broken authentication: enumeration protection on login', async ({ request }, testInfo) => {
    await new BrokenAuthenticationProbe().checkEnumerationProtection(request, testInfo);
  });

  test('Authentication bypass: direct dashboard access without credentials', async ({ page }, testInfo) => {
    await new BrokenAuthenticationProbe().checkDirectDashboardAccess(page, testInfo);
  });

  test('Authentication bypass: JWT token manipulation', async ({ page }, testInfo) => {
    await new BrokenAuthenticationProbe().checkJwtManipulation(page, testInfo);
  });

  test('XSS prevention: user data sanitization in dashboard', async ({ page }, testInfo) => {
    await new BrokenAuthenticationProbe().checkDashboardXss(page, testInfo);
  });
});
