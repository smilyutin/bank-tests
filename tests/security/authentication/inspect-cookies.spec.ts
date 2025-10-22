import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, parseSetCookieFlags, parseSetCookieValue, softCheck } from '../utils';
import { loadUsers } from '../../utils/credentials';
import { LoginPage } from '../../ui/pages/loginPage';

test('Inspect cookies and storage after UI login', async ({ browser }, testInfo) => {
  // Use persisted user if available or try to create one
  const users = loadUsers();
  const user = users && users.length ? users[0] : await ensureTestUser(({} as any));
  if (!user || !user.email || !user.password) {
    test.skip(true, 'No test user available');
    return;
  }

  const context = await browser.newContext();
  const page = await context.newPage();

  // Use the LoginPage POM for more robust interaction
  const baseURL = process.env.BASE_URL || 'http://localhost:5001';
  const login = new LoginPage(page);
  await login.goto(baseURL).catch(()=>{});
  await login.fillEmail(user.email).catch(()=>{});
  await login.fillPassword(user.password).catch(()=>{});
  // submit and wait for navigation or network idle
  await Promise.all([
    login.submit().catch(()=>{}),
    page.waitForLoadState('networkidle').catch(()=>{})
  ]);

  const cookies = await context.cookies();
  // Attach cookie summary
  const cookieSummary = cookies.map(c => ({ name: c.name, value: c.value ? (c.value.length > 32 ? c.value.slice(0,32) + '...' : c.value) : '', httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite, expires: c.expires }));
  testInfo.attach('cookies.json', { body: JSON.stringify(cookieSummary, null, 2), contentType: 'application/json' });
  console.log('Cookies:', cookieSummary);

  // Inspect localStorage and sessionStorage
  const stor = await page.evaluate(()=> ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  testInfo.attach('storage.json', { body: JSON.stringify(stor, null, 2), contentType: 'application/json' });
  console.log('Storage keys:', stor);

  await context.close();
});
