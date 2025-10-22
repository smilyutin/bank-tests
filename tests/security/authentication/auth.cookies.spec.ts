import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, parseSetCookieFlags, softCheck } from '../utils';

test('Auth cookie flags (Secure, HttpOnly, SameSite)', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  if (!user.email || !user.password) {
    test.skip(true, 'No persisted user with email/password available');
    return;
  }
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    test.skip();
    return;
  }
  const { res } = attempt as any;
  const setCookie = res.headers()['set-cookie'];
  softCheck(testInfo, !!setCookie, 'Login did not set a cookie (set-cookie header missing)');
  if (setCookie) {
    const flags = parseSetCookieFlags(setCookie as string);
    softCheck(testInfo, flags.httpOnly, 'Auth cookie missing HttpOnly flag');
    softCheck(testInfo, flags.secure || process.env.SKIP_SECURE_CHECK === '1', 'Auth cookie missing Secure flag');
    // Prefer Lax/Strict
    softCheck(testInfo, !!(flags.sameSite && /lax|strict/i.test(String(flags.sameSite))), 'Auth cookie SameSite is not Lax/Strict');
  }
});
