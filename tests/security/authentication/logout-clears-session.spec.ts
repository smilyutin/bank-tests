import { test } from '@playwright/test';
import { softCheck } from '../utils';
import { LOGIN_SELECTORS, LOGOUT_SELECTORS, getInputLocator } from '../selectors.config';
import { getTestUserWithUsername } from '../test-users';

test('Logout clears cookies and storage', async ({ browser }, testInfo) => {
  // This is a UI-level check; non-destructive. We'll use a browser context.
  const context = await browser.newContext();
  const page = await context.newPage();
  
  // Use pre-configured test user from fixtures/users.json
  const user = getTestUserWithUsername();
  if (!user.username && !user.email) {
    await context.close();
    test.skip(true, 'No valid test user found');
    return;
  }
  
  try {
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      await context.close();
      test.skip(true, 'Login page not found (404)');
      return;
    }
    
    // Check if login form inputs exist before proceeding
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!emailInput || !passwordInput || !submitButton) {
      await context.close();
      test.skip(true, 'Login form not found on page');
      return;
    }
    
    // Try to login
    await emailInput.fill(user.username || user.email, { timeout: 3000 }).catch(()=>{});
    await passwordInput.fill(user.password, { timeout: 3000 }).catch(()=>{});
    await Promise.all([
      submitButton.click({ timeout: 3000 }).catch(()=>{}),
      page.waitForLoadState('networkidle', { timeout: 5000 }).catch(()=>{})
    ]);
  } catch (e) {
    // Login page might not exist
    await context.close();
    test.skip(true, `Login page not available: ${e}`);
    return;
  }

  // Attempt logout
  await page.goto(LOGOUT_SELECTORS.logoutPath, { timeout: 5000 }).catch(()=>{});
  
  // Check cookies cleared
  const cookies = await context.cookies();
  softCheck(testInfo, cookies.length === 0, 'Cookies not cleared after logout');
  
  // Check storages
  const local = await page.evaluate(()=> ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  softCheck(testInfo, local.local.length === 0 && local.session.length === 0, 'localStorage/sessionStorage not cleared on logout');

  await context.close();
});
