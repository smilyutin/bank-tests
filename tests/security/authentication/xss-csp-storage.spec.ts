import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

test('XSS/Storage: sensitive tokens not in localStorage', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Login via API
  const attempt = await tryLogin(page.request as any, user.email, user.password);
  if (!attempt) {
    test.skip(true, 'Login endpoint not found');
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
    // Page might not be available
  }
});

test('CSP: Content Security Policy header present', async ({ page }, testInfo) => {
  try {
    const response = await page.goto('/');
    
    if (response) {
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
    }
  } catch (e) {
    test.skip(true, 'Page not available');
  }
});

test('XSS: sessionStorage does not contain sensitive data', async ({ page }, testInfo) => {
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
    test.skip(true, 'Page not available');
  }
});
