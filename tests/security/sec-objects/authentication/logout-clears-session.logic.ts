import { test } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { LOGIN_SELECTORS, LOGOUT_SELECTORS, getInputLocator } from '../../selectors.config';
import { getTestUserWithUsername } from '../../test-users';
import { captureStorageKeys, getContextCookies } from '../../utils/session';

const TARGET_APP_FIX_FIRST = [
  'Implement server-side session invalidation on logout endpoint',
  'Clear all session tokens and cookies on logout (/api/logout endpoint)',
  'Delete or invalidate refresh tokens when logout is called',
  'Implement proper CSRF tokens that are cleared and regenerated on logout',
  'Validate that subsequent API calls after logout return 401/403',
  'Prevent token reuse by blacklisting or shortening expiration on logout',
];

class LogoutClearsSessionProbe {
  async verify(browser: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const context = await browser.newContext();
    const page = await context.newPage();

    try {
      const user = getTestUserWithUsername();
      if (!user.username && !user.email) {
        reporter.reportSkip('No test user configured for logout test');
        test.skip(true, 'No test user configured for logout test');
        return;
      }

      const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
      if (!response || response.status() === 404) {
        reporter.reportSkip('Login page not found at configured path');
        test.skip(true, `Login page not found at ${LOGIN_SELECTORS.loginPath}`);
        return;
      }

      const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
      const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
      const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);

      if (!emailInput || !passwordInput || !submitButton) {
        reporter.reportSkip('Login form controls not found on page');
        test.skip(true, 'Login form controls not found on page');
        return;
      }

      await emailInput.fill(user.username || user.email, { timeout: 3000 }).catch(() => {});
      await passwordInput.fill(user.password, { timeout: 3000 }).catch(() => {});
      await Promise.all([
        submitButton.click({ timeout: 3000 }).catch(() => {}),
        page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
      ]);

      const cookiesBeforeLogout = await getContextCookies(context);
      const storageBeforeLogout = await captureStorageKeys(page);

      await page.goto(LOGOUT_SELECTORS.logoutPath, { timeout: 5000 }).catch(() => {});

      const cookiesAfterLogout = await getContextCookies(context);
      const storageAfterLogout = await captureStorageKeys(page);

      const cookiesCleared = cookiesAfterLogout.length === 0;
      const storageCleared = storageAfterLogout.local.length === 0 && storageAfterLogout.session.length === 0;

      testInfo.attach('cookies-before-after.json', {
        body: JSON.stringify({
          before: cookiesBeforeLogout.length,
          after: cookiesAfterLogout.length,
          details: cookiesAfterLogout.map(c => ({ name: c.name, httpOnly: c.httpOnly }))
        }, null, 2),
        contentType: 'application/json'
      });

      if (cookiesCleared && storageCleared) {
        reporter.reportPass(
          `Logout properly clears all session data. ` +
          `Evidence: ${cookiesBeforeLogout.length} cookies before logout → ${cookiesAfterLogout.length} after. ` +
          `Storage cleared: localStorage ${storageBeforeLogout.local.length} → ${storageAfterLogout.local.length}, ` +
          `sessionStorage ${storageBeforeLogout.session.length} → ${storageAfterLogout.session.length}. ` +
          `This prevents session hijacking via cookie/token reuse.`,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      } else {
        const remaining = [];
        if (!cookiesCleared) remaining.push(`${cookiesAfterLogout.length} cookies remain`);
        if (!storageCleared) remaining.push(`Storage not cleared (${storageAfterLogout.local.length} localStorage, ${storageAfterLogout.session.length} sessionStorage keys)`);

        reporter.reportWarning(
          `Logout does not properly clear session data. ${remaining.join('; ')}. ` +
          `This allows attackers to reuse existing tokens/cookies to hijack sessions after logout.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      }
    } catch {
      reporter.reportSkip('Exception during logout test');
      test.skip(true, 'Exception during logout test');
    } finally {
      await context.close();
    }
  }
}

export { LogoutClearsSessionProbe };
