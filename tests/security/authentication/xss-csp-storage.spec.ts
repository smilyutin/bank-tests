import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils/utils';
import { SecurityReporter } from '../security-reporter';

test('XSS/Storage: sensitive tokens not in localStorage', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(page.request as any);
  
  if (!user.email || !user.password) {
    reporter.reportWarning('No test user configured', [
      'Ensure test credentials are set up in tests/fixtures/users.json',
      'Run setup scripts to initialize test user',
      'Verify FIXTURE_USERS_INTEGRATION.md for user setup process',
      'Check if app registration endpoint is available'
    ], 'A2:2021-Identification and Authentication Failures');
    return;
  }

  // Login via API
  const attempt = await tryLogin(page.request as any, user.email, user.password);
  if (!attempt) {
    reporter.reportWarning('Could not complete login via API', [
      'Verify /login or /api/auth endpoints exist',
      'Check that API login returns auth tokens or sets secure cookies',
      'Ensure test credentials are valid for the target app',
      'Review app authentication flow and expected response format'
    ], 'A2:2021-Identification and Authentication Failures');
    return;
  }

  try {
    await page.goto('/');
    
    // Check localStorage for tokens
    const localStorage = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) {
          items[key] = window.localStorage.getItem(key) || '';
        }
      }
      return items;
    });

    const sensitiveKeys = ['token', 'jwt', 'auth', 'session', 'access_token', 'id_token'];
    const foundSensitive = Object.keys(localStorage).some(key => 
      sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
    );

    softCheck(
      testInfo,
      !foundSensitive,
      'Sensitive auth tokens should not be stored in localStorage (prefer httpOnly cookies)'
    );
  } catch (e) {
    reporter.reportWarning('Exception while checking localStorage', [
      'Ensure page is accessible and JavaScript is enabled',
      'Check browser console for errors during page load',
      'Verify DOM is ready before querying storage',
      'Use try-catch to handle navigation failures gracefully'
    ], 'A3:2021-Injection');
  }
});

test('CSP: Content Security Policy header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  try {
    const response = await page.goto('/');
    
    if (!response) {
      reporter.reportWarning('No response received from base URL', [
        'Verify BASE_URL environment variable is set correctly',
        'Ensure application is running and accessible',
        'Check network connectivity and firewall rules',
        'Review server logs for startup errors'
      ], 'A1:2021-Broken Access Control');
      return;
    }
    
    const headers = response.headers();
    const csp = headers['content-security-policy'];
    
    softCheck(
      testInfo,
      !!csp,
      'Content-Security-Policy header should be present to prevent XSS'
    );

    if (csp) {
      // Check for unsafe-inline in script-src
      const hasUnsafeInline = csp.includes("'unsafe-inline'");
      
      softCheck(
        testInfo,
        !hasUnsafeInline || csp.includes('nonce-') || csp.includes('sha256-'),
        "CSP should avoid 'unsafe-inline' or use nonces/hashes"
      );
    }
  } catch (e) {
    reporter.reportWarning('Exception while checking CSP header', [
      'Verify application base URL is accessible',
      'Check that CSP headers are being sent by server',
      'Review server configuration for missing CSP middleware',
      'Ensure SSL/TLS is properly configured if using HTTPS'
    ], 'A6:2021-Vulnerable and Outdated Components');
  }
});

test('XSS: sessionStorage does not contain sensitive data', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  try {
    await page.goto('/');
    
    const sessionStorage = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.sessionStorage.length; i++) {
        const key = window.sessionStorage.key(i);
        if (key) {
          items[key] = window.sessionStorage.getItem(key) || '';
        }
      }
      return items;
    });

    const sensitiveKeys = ['password', 'secret', 'private'];
    const foundSensitive = Object.keys(sessionStorage).some(key => 
      sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
    );

    softCheck(
      testInfo,
      !foundSensitive,
      'Passwords or secrets should never be stored in sessionStorage'
    );
  } catch (e) {
    reporter.reportWarning('Exception while checking sessionStorage', [
      'Verify application is running and accessible at BASE_URL',
      'Check browser console for page load or script errors',
      'Ensure session is properly initialized before querying storage',
      'Add error logging to understand why storage check failed'
    ], 'A1:2021-Broken Access Control');
  }
});
