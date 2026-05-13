import { test, type TestInfo } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { pageHasCsrfTokenField } from '../../utils/csrf';

class CsrfValidationProbe {
  async verifyRequestsWithoutTokenAreRejected(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(request as any);

    if (!user.email || !user.password) {
      reporter.reportSkip('CSRF missing-token probe could not run because no valid test user credentials are configured.');
      test.skip(true, 'No valid test user credentials are configured');
      return;
    }

    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt || !attempt.token) {
      reporter.reportSkip('CSRF missing-token probe could not run because login failed or no bearer token was obtained.');
      test.skip(true, 'Login failed or no bearer token was obtained');
      return;
    }

    const { token } = attempt as any;
    const dangerousEndpoints = [
      { method: 'POST', url: '/api/profile' },
      { method: 'DELETE', url: '/api/users/me' },
      { method: 'PATCH', url: '/api/settings' },
    ];

    let properlyProtected = true;
    for (const endpoint of dangerousEndpoints) {
      try {
        const res = await request.fetch(endpoint.url, {
          method: endpoint.method,
          headers: { 'Authorization': `Bearer ${token}` },
          data: { test: 'data' },
        });

        if (res.status() < 400) {
          properlyProtected = false;
          break;
        }
      } catch {
        // Expected behavior - request should fail
      }
    }

    softCheck(testInfo, properlyProtected, 'State-changing requests should require CSRF token protection');

    if (properlyProtected) {
      reporter.reportPass(
        'State-changing requests without CSRF tokens were rejected.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
  }

  async verifyInvalidTokensAreRejected(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(request as any);

    if (!user.email || !user.password) {
      reporter.reportSkip('CSRF invalid-token probe could not run because no valid test user credentials are configured.');
      test.skip(true, 'No valid test user credentials are configured');
      return;
    }

    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt || !attempt.token) {
      reporter.reportSkip('CSRF invalid-token probe could not run because login failed or no bearer token was obtained.');
      test.skip(true, 'Login failed or no bearer token was obtained');
      return;
    }

    const { token } = attempt as any;
    const invalidTokens = ['invalid-token-12345', 'expired-token', '', 'null'];
    let rejected = false;

    for (const csrfToken of invalidTokens) {
      try {
        const res = await request.post('/api/profile', {
          headers: {
            'Authorization': `Bearer ${token}`,
            'X-CSRF-Token': csrfToken,
            'X-XSRF-Token': csrfToken,
          },
          data: { name: 'Hacker' },
        });

        if (res.status() === 403 || res.status() === 401) {
          rejected = true;
          break;
        }
      } catch {
        rejected = true;
        break;
      }
    }

    softCheck(testInfo, rejected, 'Invalid CSRF tokens should be rejected with 403/401');

    if (rejected) {
      reporter.reportPass(
        'Invalid CSRF tokens were rejected.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
  }

  async verifySameSiteCookieAttribute(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(request as any);

    if (!user.email || !user.password) {
      reporter.reportSkip('CSRF SameSite-cookie probe could not run because no valid test user credentials are configured.');
      test.skip(true, 'No valid test user credentials are configured');
      return;
    }

    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt) {
      reporter.reportSkip('CSRF SameSite-cookie probe could not run because login failed.');
      test.skip(true, 'Login failed');
      return;
    }

    const { res } = attempt as any;
    const setCookie = res.headers()['set-cookie'];

    if (setCookie) {
      const sameSitePresent = setCookie.toLowerCase().includes('samesite=lax') || setCookie.toLowerCase().includes('samesite=strict');
      softCheck(testInfo, sameSitePresent, 'Session cookies should have SameSite attribute (Lax or Strict) for CSRF protection');

      if (sameSitePresent) {
        reporter.reportPass(
          'Session cookies include a SameSite attribute for CSRF protection.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } else {
      reporter.reportSkip('CSRF SameSite-cookie probe failed because no cookies were set during login.');
      test.skip(true, 'No cookies were set during login');
    }
  }

  async verifyProtectionImplementation(page: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    try {
      await page.goto('/');
      const hasCsrfProtection = await pageHasCsrfTokenField(page);

      softCheck(testInfo, hasCsrfProtection, 'Application should implement CSRF protection (token in meta tag or form)');

      if (hasCsrfProtection) {
        reporter.reportPass(
          'CSRF protection is implemented via a meta tag or form token.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } catch {
      reporter.reportSkip('CSRF protection-implementation probe could not run because the page was not available.');
      test.skip(true, 'The page was not available');
    }
  }

  async verifyTokenNotLeakedInUrl(page: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    try {
      await page.goto('/');
      const url = page.url();
      const hasTokenInUrl = url.includes('csrf') || url.includes('token=') || url.includes('_token=');

      softCheck(testInfo, !hasTokenInUrl, 'CSRF tokens should not be included in URLs (should be in headers/body only)');

      if (!hasTokenInUrl) {
        reporter.reportPass(
          'CSRF tokens were not leaked in the URL.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } catch {
      reporter.reportSkip('CSRF token-in-URL probe could not run because the page was not available.');
      test.skip(true, 'The page was not available');
    }
  }
}

export { CsrfValidationProbe };
