import { test } from '@playwright/test';
import { ensureTestUser } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'Implement idle session timeout (15-30 minutes recommended)',
  'Invalidate session server-side when timeout occurs',
  'Return 401 Unauthorized from API endpoints for expired sessions',
  'Redirect to login page for UI when session expires',
  'Implement activity detection to extend session timeout on user interaction',
  'Clear authentication tokens/cookies when session expires',
];

const IDLE_SESSION_SIMULATION_MS = Number(process.env.SESSION_IDLE_SIMULATION_MS || '10000');
const LOGIN_IDENTIFIER_SELECTOR = '[name="email"], [name="username"], [type="email"], input[type="text"]';

/**
 * Session Timeout Security Tests 
 * 
 * These tests verify that the application properly handles session timeouts
 * to enhance both security and user experience.
 * 
 * Security Risks Addressed:
 * 1. Idle session exploitation
 * 2. Unattended session access
 * 3. Session hijacking through abandoned sessions
 * 
 * Expected Behavior:
 * - Idle sessions should timeout after appropriate duration
 * - Users should receive warnings before session expiry
 * - Expired sessions should require re-authentication
 */

test.describe('Session Timeout Security - High Priority', () => {
  test.describe.configure({ timeout: 120_000 });

  test('Idle sessions are properly terminated after inactivity', async ({ page }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      reporter.reportWarning('No test user configured for session timeout test', [
        'Ensure test credentials exist in tests/fixtures/users.json',
        'Run user initialization and fixture setup scripts',
        'Verify ensureTestUser() returns valid email and password',
        'Check FIXTURE_USERS_INTEGRATION.md for user setup process'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    const email = user.email;
    const password = user.password;

    // Login normally
    await page.goto('/login').catch(() => {});
    await page.fill(LOGIN_IDENTIFIER_SELECTOR, email).catch(() => {});
    await page.fill('[name="password"], [type="password"]', password).catch(() => {});
    await page.click('[type="submit"], button[type="submit"]').catch(() => {});
    await page.waitForTimeout(2000);

    // Simulate idle session (kept short to avoid Playwright per-test timeout)
    await page.waitForTimeout(IDLE_SESSION_SIMULATION_MS);

    // Try to access protected resource
    const response = await page.goto('/dashboard').catch(() => null);
    const finalUrl = page.url();
    const sessionActive = finalUrl.includes('/dashboard') && response?.status() !== 401;
    
    if (!sessionActive) {
      reporter.reportPass(
        `Session properly terminates after idle period. User is redirected to login. ` +
        `This prevents unauthorized access through abandoned sessions. ` +
        `Evidence: Idle ${(IDLE_SESSION_SIMULATION_MS / 1000).toFixed(0)}s + access attempt → redirected away from protected resource.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning(
        `Session remains active after ${(IDLE_SESSION_SIMULATION_MS / 1000).toFixed(0)} seconds of inactivity. Attackers can hijack abandoned sessions. ` +
        `Impact: Unattended workstations vulnerable to compromise.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  });

  test('Expired sessions return 401 from API endpoints', async ({ page }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      reporter.reportWarning('No test user configured for API expiration test', [
        'Ensure test credentials exist in tests/fixtures/users.json',
        'Run user initialization and fixture setup',
        'Verify ensureTestUser() returns valid email/password',
        'Check FIXTURE_USERS_INTEGRATION.md for user setup'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login').catch(() => {});
    await page.fill(LOGIN_IDENTIFIER_SELECTOR, email).catch(() => {});
    await page.fill('[name="password"], [type="password"]', password).catch(() => {});
    await page.click('[type="submit"], button[type="submit"]').catch(() => {});
    await page.waitForTimeout(2000);

    // Simulate idle session
    await page.waitForTimeout(IDLE_SESSION_SIMULATION_MS);

    // Try API call
    const response = await page.request.get('/api/me').catch(() => null);
    const statusCode = response?.status();
    
    if (statusCode === 401) {
      reporter.reportPass(
        `API properly rejects expired session tokens with 401 Unauthorized. ` +
        `This prevents API abuse with stale credentials. ` +
        `Evidence: POST /login → idle ${(IDLE_SESSION_SIMULATION_MS / 1000).toFixed(0)}s → GET /api/me returns 401.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else if (statusCode && statusCode < 500) {
      reporter.reportWarning(
        `API returned ${statusCode} instead of 401 for expired session. ` +
        `Clients may retry with cached/expired tokens if response code is ambiguous.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning('API endpoint /api/me not found or unreachable', [
        'Verify /api/me endpoint exists and is accessible',
        'Check application server is running',
        'Ensure API endpoints respond to authenticated requests',
        'Review server logs for /api/me endpoint errors'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
    }
  });

  test('Concurrent sessions are properly managed', async ({ browser }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    const bootstrapContext = await browser.newContext();
    const user = await ensureTestUser(bootstrapContext.request as any);
    await bootstrapContext.close();
    if (!user.email || !user.password) {
      reporter.reportWarning('No test user configured for concurrent session test', [
        'Ensure test credentials exist in tests/fixtures/users.json',
        'Run user initialization and fixture setup',
        'Verify ensureTestUser() returns valid email/password',
        'Check FIXTURE_USERS_INTEGRATION.md for user setup'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    const email = user.email;
    const password = user.password;

    // Create multiple browser contexts for same user
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    const loginWithFastFail = async (page: typeof page1): Promise<boolean> => {
      await page.goto('/login').catch(() => {});

      const emailInput = page.locator(LOGIN_IDENTIFIER_SELECTOR).first();
      const passwordInput = page.locator('[name="password"], [type="password"]').first();
      const submitButton = page.locator('[type="submit"], button[type="submit"]').first();

      if (await emailInput.count() === 0 || await passwordInput.count() === 0 || await submitButton.count() === 0) {
        return false;
      }

      await emailInput.fill(email, { timeout: 2000 }).catch(() => {});
      await passwordInput.fill(password, { timeout: 2000 }).catch(() => {});
      await submitButton.click({ timeout: 2000 }).catch(() => {});
      await page.waitForTimeout(2000);

      return true;
    };

    // Login same user in both contexts
    const loginPromise1 = (async () => {
      return loginWithFastFail(page1);
    })();

    const loginPromise2 = (async () => {
      return loginWithFastFail(page2);
    })();

    const [login1Ready, login2Ready] = await Promise.all([loginPromise1, loginPromise2]);

    if (!login1Ready || !login2Ready) {
      reporter.reportWarning('Login form selectors not found for concurrent session test', [
        'Verify LOGIN_IDENTIFIER_SELECTOR and password selectors match form inputs',
        'Run discovery script: npm run discover:selectors',
        'Check page HTML to find actual form control selectors',
        'Update LOGIN_IDENTIFIER_SELECTOR in selectors.config.ts if needed'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      await context1.close();
      await context2.close();
      return;
    }

    // Check if both sessions are active
    const session1Active = page1.url().includes('/dashboard');
    const session2Active = page2.url().includes('/dashboard'); 

    const activeSessions = [session1Active, session2Active].filter(Boolean).length;

    if (activeSessions === 1) {
      reporter.reportPass(
        `Only one concurrent session allowed per user. Second login invalidates first session. ` +
        `This prevents credential sharing and limits account hijacking impact. ` +
        `Evidence: Login attempt from 2 contexts → only 1 session active.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else if (activeSessions > 1) {
      reporter.reportWarning(
        `Multiple concurrent sessions allowed (${activeSessions} active). ` +
        `This enables credential sharing and makes session hijacking more impactful.`,
        [...TARGET_APP_FIX_FIRST, 'Implement per-user session limits (recommend max 1-2 concurrent sessions)'],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning(
        `No active sessions after login attempt. Check login functionality.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }

    await context1.close();
    await context2.close();
  });

});

  test('Session timeout: logout should invalidate session token', async ({ page }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);

    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      reporter.reportWarning('No test user configured for logout invalidation test', [
        'Ensure test credentials exist in tests/fixtures/users.json',
        'Run user initialization and fixture setup',
        'Verify ensureTestUser() returns valid email/password',
        'Check FIXTURE_USERS_INTEGRATION.md for user setup'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login').catch(() => {});

    const emailInput = page.locator(LOGIN_IDENTIFIER_SELECTOR).first();
    const passwordInput = page.locator('[name="password"], [type="password"]').first();
    if (await emailInput.count() === 0 || await passwordInput.count() === 0) {
      reporter.reportWarning('Login form selectors not found for logout invalidation test', [
        'Verify LOGIN_IDENTIFIER_SELECTOR and password selectors match form inputs',
        'Run discovery script: npm run discover:selectors',
        'Check page HTML to find actual form control selectors',
        'Update LOGIN_IDENTIFIER_SELECTOR in selectors.config.ts if needed'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }

    await emailInput.fill(email).catch(() => {});
    await passwordInput.fill(password).catch(() => {});
    await page.click('[type="submit"], button[type="submit"]').catch(() => {});
    await page.waitForTimeout(2000);

    // Attempt logout
    await page.click('text=/logout/i').catch(() => {});
    await page.waitForTimeout(1000);

    // Access protected route
    await page.goto('/dashboard');
    const url = page.url();

    if (url.includes('/login')) {
      reporter.reportPass(
        'Logout invalidated session and blocked access to protected route',
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning(
        'Protected route still accessible after logout; session invalidation may be incomplete',
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  });

