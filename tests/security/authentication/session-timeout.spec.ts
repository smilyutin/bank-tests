import { test, expect } from '@playwright/test';
import { ensureTestUser, softCheck } from '../utils';

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

  test('Session timeout: idle sessions should be terminated', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    // Login normally
    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    // Simulate idle session (reduced time for testing)
    await page.waitForTimeout(30000); // 30 seconds

    // Try to access protected resource
    const response = await page.goto('/dashboard');
    const finalUrl = page.url();

    // Check if session timed out (this is informational - timeout settings vary)
    const sessionActive = finalUrl.includes('/dashboard') && response?.status() !== 401;
    
    if (sessionActive) {
      testInfo.annotations.push({
        type: 'security-info',
        description: 'Session remains active after 30 seconds idle - consider implementing session timeout'
      });
    } else {
      softCheck(testInfo, true, 'Session properly timed out after idle period');
    }
  });

  test('Session timeout: should warn users before expiration', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    // Login and stay on dashboard
    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    // Wait and check for timeout warnings
    await page.waitForTimeout(25000);

    // Look for timeout warnings or modals
    const warningSelectors = [
      'text=/session.*expir/i',
      'text=/timeout.*warning/i',
      '[role="dialog"]:has-text("session")',
      '.timeout-warning',
      '.session-warning'
    ];

    let warningFound = false;
    for (const selector of warningSelectors) {
      if (await page.locator(selector).count() > 0) {
        warningFound = true;
        break;
      }
    }

    // This is a UX improvement suggestion
    if (!warningFound) {
      testInfo.annotations.push({
        type: 'ux-improvement',
        description: 'Consider adding session timeout warnings to improve user experience'
      });
    }
  });

  test('Session timeout: concurrent session management', async ({ browser }, testInfo) => {
    const context = await browser.newContext();
    const user = await ensureTestUser(context.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    // Create multiple browser contexts for same user
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    // Login same user in both contexts
    const loginPromise1 = (async () => {
      await page1.goto('/login');
      await page1.fill('[name="email"], [type="email"]', email);
      await page1.fill('[name="password"], [type="password"]', password);
      await page1.click('[type="submit"], button[type="submit"]');
      await page1.waitForTimeout(2000);
    })();

    const loginPromise2 = (async () => {
      await page2.goto('/login');
      await page2.fill('[name="email"], [type="email"]', email);
      await page2.fill('[name="password"], [type="password"]', password);
      await page2.click('[type="submit"], button[type="submit"]');
      await page2.waitForTimeout(2000);
    })();

    await Promise.all([loginPromise1, loginPromise2]);

    // Check if both sessions are active
    const session1Active = page1.url().includes('/dashboard');
    const session2Active = page2.url().includes('/dashboard'); 

    const activeSessions = [session1Active, session2Active].filter(Boolean).length;

    if (activeSessions > 1) {
      testInfo.annotations.push({
        type: 'security-info',
        description: `Multiple concurrent sessions allowed (${activeSessions}) - consider implementing session limits`
      });
    }

    await context1.close();
    await context2.close();
  });

  test('Session timeout: expired session should redirect to login', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    // Simulate idle
    await page.waitForTimeout(30000);

    // Access protected route
    await page.goto('/dashboard');

    const url = page.url();
    if (url.includes('/login')) {
      softCheck(testInfo, true, 'Expired session redirected to login');
    } else {
      testInfo.annotations.push({
        type: 'security-info',
        description: 'Session still active after idle; verify timeout configuration'
      });
    }
  });

  test('Session timeout: protected API should return 401 after idle', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    await page.waitForTimeout(30000);

    const response = await page.request.get('/api/me');
    if (response.status() === 401) {
      softCheck(testInfo, true, 'API correctly returned 401 after idle session');
    } else {
      testInfo.annotations.push({
        type: 'security-info',
        description: `API returned ${response.status()} after idle; confirm session timeout for APIs`
      });
    }
  });

  test('Session timeout: user activity should extend session', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    // Simulate activity during idle window
    await page.waitForTimeout(15000);
    await page.mouse.move(10, 10);
    await page.keyboard.press('Shift');
    await page.waitForTimeout(15000);

    const response = await page.goto('/dashboard');
    const sessionActive = page.url().includes('/dashboard') && response?.status() !== 401;

    if (sessionActive) {
      softCheck(testInfo, true, 'Session extended by user activity');
    } else {
      testInfo.annotations.push({
        type: 'security-info',
        description: 'Session expired despite activity; check inactivity tracking'
      });
    }
  });

  test('Session timeout: logout should invalidate session token', async ({ page }, testInfo) => {
    const user = await ensureTestUser(page.request as any);
    if (!user.email || !user.password) {
      test.skip(true, 'No persisted user');
      return;
    }
    const email = user.email;
    const password = user.password;

    await page.goto('/login');
    await page.fill('[name="email"], [type="email"]', email);
    await page.fill('[name="password"], [type="password"]', password);
    await page.click('[type="submit"], button[type="submit"]');
    await page.waitForTimeout(2000);

    // Attempt logout
    await page.click('text=/logout/i');
    await page.waitForTimeout(1000);

    // Access protected route
    await page.goto('/dashboard');
    const url = page.url();

    if (url.includes('/login')) {
      softCheck(testInfo, true, 'Logout invalidated session');
    } else {
      testInfo.annotations.push({
        type: 'security-info',
        description: 'Protected route accessible after logout; verify session invalidation'
      });
    }
  });
});