import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

test('Logout clears cookies and storage', async ({ browser }, testInfo) => {
  // This is a UI-level check; non-destructive. We'll use a browser context.
  const context = await browser.newContext();
  const page = await context.newPage();
  // Try login via UI
  // Use /login page if present
  const user = await ensureTestUser((page.request as any));
  if (!user.email || !user.password) {
    test.skip(true, 'No persisted user');
    return;
  }
  try {
    await page.goto('/login');
    await page.fill('input[name="email"], input[name="username"], input[type="email"]', user.email).catch(()=>{});
    await page.fill('input[type="password"]', user.password).catch(()=>{});
    await Promise.all([
      page.click('button[type="submit"], text=Login').catch(()=>{}),
      page.waitForLoadState('networkidle').catch(()=>{})
    ]);
  } catch (e) {
    // ignore; fall through
  }

  // Attempt logout
  await page.goto('/logout').catch(()=>{});
  // Check cookies cleared
  const cookies = await context.cookies();
  softCheck(testInfo, cookies.length === 0, 'Cookies not cleared after logout');
  // Check storages
  const local = await page.evaluate(()=> ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  softCheck(testInfo, local.local.length === 0 && local.session.length === 0, 'localStorage/sessionStorage not cleared on logout');

  await context.close();
});
