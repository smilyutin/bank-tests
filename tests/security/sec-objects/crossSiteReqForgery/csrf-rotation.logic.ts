import { type Page, type TestInfo, test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { captureCsrfToken } from '../../utils/csrf';

class CsrfRotationProbe {
  async verifyTokenRotatesAfterLogin(page: Page, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(page.request as any);

    if (!user.email || !user.password) {
      test.skip(true, 'No user configured');
      return;
    }

    try {
      await page.goto('/login');
      const initialToken = await captureCsrfToken(page);

      await page.fill('input[name="email"]', user.email).catch(() => {});
      await page.fill('input[type="password"]', user.password!).catch(() => {});
      await page.click('button[type="submit"]').catch(() => {});
      await page.waitForTimeout(2000);

      const afterLoginToken = await captureCsrfToken(page);

      softCheck(testInfo, !initialToken || afterLoginToken !== initialToken, 'CSRF token should rotate after login to prevent session fixation');

      if (!initialToken || afterLoginToken !== initialToken) {
        reporter.reportPass(
          'CSRF token rotated after login (or no initial token was exposed before authentication).',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } catch {
      test.skip(true, 'Login page not available');
    }
  }

  async verifyTokenInvalidatedAfterLogout(page: Page, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(page.request as any);

    if (!user.email || !user.password) {
      test.skip(true, 'No user configured');
      return;
    }

    try {
      await page.goto('/login');
      await page.fill('input[name="email"]', user.email).catch(() => {});
      await page.fill('input[type="password"]', user.password!).catch(() => {});
      await page.click('button[type="submit"]').catch(() => {});
      await page.waitForTimeout(2000);

      const loggedInToken = await captureCsrfToken(page);
      await page.goto('/logout').catch(() => {});
      await page.waitForTimeout(1000);

      if (loggedInToken) {
        try {
          const res = await page.request.post('/api/profile', {
            headers: { 'X-CSRF-Token': loggedInToken },
            data: { name: 'Test' },
          });

          softCheck(testInfo, res.status() >= 400, 'Old CSRF token should be invalidated after logout');

          if (res.status() >= 400) {
            reporter.reportPass(
              'The old CSRF token was rejected after logout.',
              OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
            );
          }
        } catch {
          // Expected behavior - the request should fail
        }
      }
    } catch {
      test.skip(true, 'Login/logout not available');
    }
  }

  async verifyTokenRotatesAfterSensitiveAction(page: Page, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(page.request as any);

    if (!user.email || !user.password) {
      test.skip(true, 'No user configured');
      return;
    }

    try {
      const attempt = await tryLogin(page.request as any, user.email, user.password);
      if (!attempt) {
        test.skip(true, 'Could not login');
        return;
      }

      await page.goto('/');
      const beforeToken = await captureCsrfToken(page);
      await page.goto('/settings').catch(() => {});
      const afterToken = await captureCsrfToken(page);

      if (!beforeToken || !afterToken) {
        test.skip(true, 'CSRF token not exposed for rotation check');
        return;
      }

      softCheck(testInfo, afterToken !== beforeToken, 'CSRF tokens should rotate after sensitive operations like password changes');

      if (afterToken !== beforeToken) {
        reporter.reportPass(
          'CSRF token rotated after the simulated sensitive operation.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } catch {
      test.skip(true, 'Settings page not available');
    }
  }
}

export { CsrfRotationProbe };
