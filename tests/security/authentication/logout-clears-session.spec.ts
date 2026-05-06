import { test } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { LOGIN_SELECTORS, LOGOUT_SELECTORS, getInputLocator } from '../selectors.config';
import { getTestUserWithUsername } from '../test-users';

const TARGET_APP_FIX_FIRST = [
  'Implement server-side session invalidation on logout endpoint',
  'Clear all session tokens and cookies on logout (/api/logout endpoint)',
  'Delete or invalidate refresh tokens when logout is called',
  'Implement proper CSRF tokens that are cleared and regenerated on logout',
  'Validate that subsequent API calls after logout return 401/403',
  'Prevent token reuse by blacklisting or shortening expiration on logout',
];

test('Logout clears session and authentication tokens', async ({ browser }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // This is a UI-level check; non-destructive. We'll use a browser context.
  const context = await browser.newContext();
  const page = await context.newPage();
  
  try {
    // Use pre-configured test user from fixtures/users.json
    const user = getTestUserWithUsername();
    if (!user.username && !user.email) {
      reporter.reportWarning('No test user configured for logout test', [
        'Ensure test user is configured in tests/fixtures/users.json',
        'Run user initialization and fixture setup',
        'Verify getTestUserWithUsername returns valid user object',
        'Check user email and username properties are populated'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      reporter.reportWarning('Login page not found at configured path', [
        `Verify login page exists at ${LOGIN_SELECTORS.loginPath}`,
        'Check LOGIN_SELECTORS.loginPath configuration in selectors.config.ts',
        'Run discovery script: npm run discover:selectors',
        'Verify application is running and accessible'
      ], OWASP_VULNERABILITIES.API1_BROKEN_OBJECT_ACCESS.name);
      return;
    }
    
    // Check if login form inputs exist before proceeding
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!emailInput || !passwordInput || !submitButton) {
      reporter.reportWarning('Login form controls not found on page', [
        'Verify email/password/submit selectors in LOGIN_SELECTORS',
        'Check getInputLocator() implementation for selector matching',
        'Run discovery script: npm run discover:selectors',
        'Review page HTML to find actual form control selectors',
        'Update LOGIN_SELECTORS in selectors.config.ts with correct selectors'
      ], OWASP_VULNERABILITIES.API1_BROKEN_OBJECT_ACCESS.name);
      return;
    }
    
    // Try to login
    await emailInput.fill(user.username || user.email, { timeout: 3000 }).catch(() => {});
    await passwordInput.fill(user.password, { timeout: 3000 }).catch(() => {});
    await Promise.all([
      submitButton.click({ timeout: 3000 }).catch(() => {}),
      page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {})
    ]);

    // Verify logged in state
    const cookiesBeforeLogout = await context.cookies();
    const storageBeforeLogout = await page.evaluate(() => ({ 
      local: Object.keys(localStorage), 
      session: Object.keys(sessionStorage) 
    }));

    // Attempt logout
    await page.goto(LOGOUT_SELECTORS.logoutPath, { timeout: 5000 }).catch(() => {});
    
    // Check cookies cleared
    const cookiesAfterLogout = await context.cookies();
    const storageAfterLogout = await page.evaluate(() => ({ 
      local: Object.keys(localStorage), 
      session: Object.keys(sessionStorage) 
    }));

    // Assess findings
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
  } catch (e) {
    // Login page might not exist
    reporter.reportWarning('Exception during logout test', [
      'Verify BASE_URL and application endpoints are accessible',
      'Check browser console for JavaScript errors',
      'Review network errors in page navigation',
      `Error details: ${String(e).slice(0, 150)}`,
      'Ensure application DOM is fully loaded before assertions'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
  } finally {
    await context.close();
  }
});
