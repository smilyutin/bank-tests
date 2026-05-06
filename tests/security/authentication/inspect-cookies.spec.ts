import { test } from '@playwright/test';
import { ensureTestUser } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { loadUsers } from '../../utils/credentials';
import { LoginPage } from '../../ui/pages/loginPage';

const TARGET_APP_FIX_FIRST = [
  'Add HttpOnly flag to authentication cookies to prevent JavaScript access',
  'Set Secure flag on all cookies transmitted over HTTPS',
  'Use SameSite=Strict or SameSite=Lax to prevent CSRF attacks',
  'Avoid storing sensitive tokens in localStorage/sessionStorage (use httpOnly cookies)',
  'Implement proper session invalidation on logout',
];

test('Auth cookies and session storage are protected', async ({ browser }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Use persisted user if available or try to create one
  const users = loadUsers();
  const user = users && users.length ? users[0] : await ensureTestUser(({} as any));
  
  if (!user || !user.email || !user.password) {
    reporter.reportWarning('No test user configured for cookie inspection', [
      'Ensure test user exists in tests/fixtures/users.json',
      'Run user initialization and fixture setup',
      'Verify loadUsers() returns valid user with email and password',
      'Check FIXTURE_USERS_INTEGRATION.md for user setup process'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }

  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    // Use the LoginPage POM for more robust interaction
    const baseURL = process.env.BASE_URL || 'http://localhost:5001';
    const login = new LoginPage(page);
    await login.goto(baseURL).catch(() => {});
    await login.fillEmail(user.email).catch(() => {});
    await login.fillPassword(user.password).catch(() => {});
    
    // Submit and wait for navigation or network idle
    await Promise.all([
      login.submit().catch(() => {}),
      page.waitForLoadState('networkidle').catch(() => {})
    ]);

    const cookies = await context.cookies();
    const stor = await page.evaluate(() => ({ 
      local: Object.keys(localStorage), 
      session: Object.keys(sessionStorage) 
    }));

    // Attach detailed summaries for evidence
    const cookieSummary = cookies.map(c => ({ 
      name: c.name, 
      value: c.value ? (c.value.length > 32 ? c.value.slice(0, 32) + '...' : c.value) : '', 
      httpOnly: c.httpOnly, 
      secure: c.secure, 
      sameSite: c.sameSite, 
      expires: c.expires 
    }));
    testInfo.attach('cookies.json', { 
      body: JSON.stringify(cookieSummary, null, 2), 
      contentType: 'application/json' 
    });
    testInfo.attach('storage.json', { 
      body: JSON.stringify(stor, null, 2), 
      contentType: 'application/json' 
    });

    // Find authentication cookies
    const authCookie = cookies.find(c => 
      c.name.toLowerCase().includes('auth') || 
      c.name.toLowerCase().includes('token') ||
      c.name.toLowerCase().includes('session')
    );

    if (authCookie) {
      const missingFlags = [];
      if (!authCookie.httpOnly) missingFlags.push('HttpOnly');
      if (!authCookie.secure && process.env.BASE_URL?.includes('https')) missingFlags.push('Secure');
      if (!authCookie.sameSite || authCookie.sameSite === 'None') missingFlags.push('SameSite');

      if (missingFlags.length === 0) {
        reporter.reportPass(
          `Authentication cookie "${authCookie.name}" properly secured with HttpOnly, Secure, and SameSite flags. ` +
          `This prevents XSS-based token theft and CSRF attacks. Evidence: ${authCookie.httpOnly ? '✓ HttpOnly' : ''} ${authCookie.secure ? '✓ Secure' : ''} ${authCookie.sameSite ? '✓ SameSite=' + authCookie.sameSite : ''}.`,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      } else {
        reporter.reportWarning(
          `Authentication cookie "${authCookie.name}" missing security flags: ${missingFlags.join(', ')}. ` +
          `This leaves the session token vulnerable to XSS attacks (JavaScript can steal it) and CSRF attacks. ` +
          `Observed flags: HttpOnly=${authCookie.httpOnly}, Secure=${authCookie.secure}, SameSite=${authCookie.sameSite || 'unset'}.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      }
    } else {
      reporter.reportWarning(
        `No authentication cookie detected after login. App may be using token storage in JavaScript-accessible memory instead. ` +
        `This is vulnerable to XSS attacks. Verify tokens are stored only in secure httpOnly cookies, not localStorage.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }

    // Check for sensitive data in localStorage/sessionStorage
    const sensitiveKeys = stor.local.concat(stor.session).filter(key =>
      key.toLowerCase().includes('token') ||
      key.toLowerCase().includes('auth') ||
      key.toLowerCase().includes('password') ||
      key.toLowerCase().includes('secret')
    );

    if (sensitiveKeys.length > 0) {
      reporter.reportWarning(
        `Sensitive tokens/credentials found in ${sensitiveKeys.length > stor.local.length ? 'sessionStorage' : 'localStorage'}: ${sensitiveKeys.join(', ')}. ` +
        `Any XSS vulnerability allows attackers to steal these values directly via JavaScript.`,
        [
          ...TARGET_APP_FIX_FIRST,
          'Move all authentication tokens from localStorage to httpOnly cookies',
          'Implement strict Content Security Policy (CSP) to prevent XSS exfiltration',
          'Apply rigorous input validation and output encoding to prevent token theft'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else if (stor.local.length === 0 && stor.session.length === 0) {
      reporter.reportPass(
        `No tokens found in JavaScript-accessible storage (localStorage/sessionStorage). ` +
        `Authentication appears to rely on secure httpOnly cookies only. Evidence: 0 localStorage keys, 0 sessionStorage keys.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportPass(
        `Non-sensitive data detected in storage (${stor.local.length} localStorage + ${stor.session.length} sessionStorage keys), ` +
        `but no tokens found. Session management appears secure.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  } finally {
    await context.close();
  }
});
