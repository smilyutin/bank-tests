import { test } from '@playwright/test';
import { SessionTimeoutProbe } from '../sec-objects/authentication/session-timeout.logic';

test.describe('Session Timeout Security - High Priority', () => {
  test.describe.configure({ timeout: 120_000 });

  test('Idle sessions are properly terminated after inactivity', async ({ page }, testInfo) => {
    await new SessionTimeoutProbe().verifyIdleSessionTerminates(page, testInfo);
  });

  test('Expired sessions return 401 from API endpoints', async ({ page }, testInfo) => {
    await new SessionTimeoutProbe().verifyExpiredSessionsReturn401(page, testInfo);
  });

  test('Concurrent sessions are properly managed', async ({ browser }, testInfo) => {
    await new SessionTimeoutProbe().verifyConcurrentSessions(browser, testInfo);
  });

  test('Session timeout: UI logout should invalidate browser session token', async ({ page }, testInfo) => {
    await new SessionTimeoutProbe().verifyLogoutInvalidatesBrowserSession(page, testInfo);
  });
});
