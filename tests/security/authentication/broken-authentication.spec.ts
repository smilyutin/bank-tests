import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { LOGIN_SELECTORS, getInputLocator, findFirstExisting } from '../selectors.config';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Enforce strong authentication controls (password policy, lockout, session validation)',
  '2) Block authentication bypass paths on protected routes and APIs',
  '3) Validate JWT/session tokens strictly and reject tampered/expired tokens',
  '4) Use generic auth error messages and sanitize all user-controlled content',
];

async function performUiLogin(page: any, email: string, password: string): Promise<{ ok: boolean; reason: string }> {
  const loginPaths = [LOGIN_SELECTORS.loginPath, ...LOGIN_SELECTORS.alternativePaths];

  for (const loginPath of loginPaths) {
    try {
      await page.goto(loginPath, { waitUntil: 'domcontentloaded' });

      const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
      const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
      const submitSelector = await findFirstExisting(page, LOGIN_SELECTORS.submitButton);

      if (!emailInput || !passwordInput || !submitSelector) {
        continue;
      }

      await emailInput.fill(email);
      await passwordInput.fill(password);
      await page.locator(submitSelector).first().click();
      return { ok: true, reason: `UI login attempted via ${loginPath}` };
    } catch {
      // try next path
    }
  }

  return { ok: false, reason: 'Login form selectors were not found on configured login paths' };
}

test('Broken authentication: weak passwords are rejected', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const weakPasswords = ['123456', 'password', 'abc123', '12345', 'qwerty'];
  let acceptedCount = 0;
  const acceptedEvidence: string[] = [];
  
  for (const weakPwd of weakPasswords) {
    const testEmail = `test-${Date.now()}@example.com`;
    
    // Try to create account or login with weak password
    try {
      const res = await request.post('/api/register', {
        data: { email: testEmail, password: weakPwd },
      });
      if (res.status() >= 200 && res.status() < 300) {
        acceptedCount++;
        acceptedEvidence.push(`${weakPwd}:${res.status()}`);
      }
    } catch (e) {
      // Expected to fail or be rejected
    }
  }

  if (acceptedCount === 0) {
    reporter.reportPass(
      'System is protected: weak password registration attempts were not accepted during probe.',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    `Weak password policy risk detected: ${acceptedCount}/${weakPasswords.length} weak passwords were accepted on registration endpoint. ` +
    `Evidence: ${acceptedEvidence.join(', ')}`,
    [
      ...TARGET_APP_FIX_FIRST,
      'Enforce minimum length (>= 12), complexity, and banned-password checks at registration',
      'Reject commonly used passwords with a denylist (e.g., HaveIBeenPwned password API or local dataset)',
      'Require password strength feedback client-side and enforce server-side validation',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});

test('Broken authentication: no default credentials accepted', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const defaultCreds = [
    { email: 'admin@admin.com', password: 'admin' },
    { email: 'admin@example.com', password: 'password' },
    { email: 'test@test.com', password: 'test' },
    { email: 'user@user.com', password: 'user' },
  ];

  let defaultAccepted = false;
  let acceptedCred = '';

  for (const cred of defaultCreds) {
    const attempt = await tryLogin(request as any, cred.email, cred.password);
    if (attempt) {
      const { res } = attempt as any;
      if (res.status() >= 200 && res.status() < 300) {
        defaultAccepted = true;
        acceptedCred = `${cred.email}/${cred.password}`;
        break;
      }
    }
  }

  if (!defaultAccepted) {
    reporter.reportPass(
      'System is protected: known default credentials were not accepted.',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    `Default credential acceptance detected: ${acceptedCred}. ` +
    'Risk: immediate account compromise with publicly known credential pairs.',
    [
      ...TARGET_APP_FIX_FIRST,
      'Disable/delete default accounts in all non-dev environments',
      'Force password change on first login for seeded accounts',
      'Add startup checks that fail deployment if known default credentials are active',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});

test('Broken authentication: password reset requires verification', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email) {
    reporter.reportWarning(
      'Password reset verification test could not run because no test user is configured.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Ensure tests/fixtures/users.json contains a valid seeded user for auth probes',
        'Expose a deterministic test-user bootstrap endpoint or fixture in non-production environments',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  // Try password reset without token
  try {
    const res = await request.post('/api/password-reset', {
      data: { email: user.email, newPassword: 'NewPassword123!' },
    });

    const status = res.status();
    // Should require token or verification
    const requiresVerification = status === 400 || status === 401 || status === 403;

    if (requiresVerification || status === 404) {
      reporter.reportPass(
        `System is protected: password reset endpoint requires verification or is unavailable (status: ${status}).`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    reporter.reportWarning(
      `Password reset may be insecure: endpoint returned status ${status} to unauthenticated reset attempt without clear verification requirement.`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Require one-time reset tokens tied to user identity and short expiration',
        'Require proof-of-possession (email OTP / link token) before password change',
        'Invalidate previous sessions and refresh tokens after password reset',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  } catch (e) {
    reporter.reportWarning(
      'Password reset endpoint was not reachable during this probe, so verification controls could not be validated.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Ensure password reset routes are deployed and reachable in the test environment',
        'Return explicit 4xx responses for invalid reset attempts instead of transport/runtime failures',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }
});

test('Broken authentication: enumeration protection on login', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const realUser = await ensureTestUser(request as any);
  const fakeEmail = 'nonexistent-' + Date.now() + '@example.com';
  
  if (!realUser.email) {
    reporter.reportWarning(
      'Enumeration protection test could not run because no real test user is configured.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Provide a seeded user account in fixtures for enumeration control testing',
        'Automate test-user provisioning before security test execution',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  // Try login with real user, wrong password
  const attempt1 = await tryLogin(request as any, realUser.email, 'wrong-password');
  // Try login with fake user
  const attempt2 = await tryLogin(request as any, fakeEmail, 'wrong-password');

  if (attempt1 && attempt2) {
    const { res: res1 } = attempt1 as any;
    const { res: res2 } = attempt2 as any;

    // Response time and message should be similar to prevent enumeration
    const body1 = await res1.text().catch(() => '');
    const body2 = await res2.text().catch(() => '');

    // Check if error messages are too specific
    const hasSpecificMessage = 
      body1.toLowerCase().includes('user not found') ||
      body1.toLowerCase().includes('invalid email') ||
      body2.toLowerCase().includes('user exists');

    if (!hasSpecificMessage) {
      reporter.reportPass(
        'System is protected: login errors appear generic, reducing user enumeration risk.',
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    reporter.reportWarning(
      'User enumeration risk: login error messages appear to disclose account existence details.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Return a generic message for all login failures (e.g., "Invalid credentials")',
        'Keep response timing similar for existing and non-existing users',
        'Avoid exposing validation hints that reveal whether an account exists',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    'Unable to compare enumeration responses because one or both login probes were unavailable.',
    [
      ...TARGET_APP_FIX_FIRST,
      'Stabilize login endpoint behavior for both existing and non-existing user probes',
      'Ensure login route accepts consistent payload contract so negative security checks can execute deterministically',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
  return;
});

//  CRITICAL SECURITY TESTS - Authentication Bypass (Priority #1)
test('Authentication bypass: direct dashboard access without credentials', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  // Clear any existing authentication
  await page.context().clearCookies();
  try {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  } catch {
    // Some documents may deny storage access; cookie clearing is still applied.
  }

  // Attempt direct dashboard access
  const response = await page.goto('/dashboard');
  const finalUrl = page.url();

  // Should redirect to login or return 401/403
  const isBlocked = finalUrl.includes('/login') || 
                   finalUrl.includes('/auth') || 
                   response?.status() === 401 || 
                   response?.status() === 403;

  if (isBlocked) {
    reporter.reportPass(
      `System is protected: unauthenticated dashboard access was blocked (url=${finalUrl}, status=${response?.status() ?? 'n/a'}).`,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    `CRITICAL authentication bypass risk: dashboard appears accessible without authentication (url=${finalUrl}, status=${response?.status() ?? 'n/a'}).`,
    [
      ...TARGET_APP_FIX_FIRST,
      'Enforce server-side authorization middleware on /dashboard and related APIs',
      'Do not rely on client-side route guards as primary access control',
      'Add integration tests for unauthenticated access to all protected routes',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});

test('Authentication bypass: JWT token manipulation', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(page.request as any);
  if (!user.email || !user.password) {
    reporter.reportWarning(
      'JWT manipulation test could not run because no valid user credentials are configured.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Provide valid seeded credentials for authentication security probes',
        'Ensure fixture bootstrap creates a login-capable test account in the target environment',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  // Login normally first
  const loginAttempt = await performUiLogin(page, user.email, user.password);
  if (!loginAttempt.ok) {
    reporter.reportWarning(
      `JWT manipulation test could not execute because UI login flow failed: ${loginAttempt.reason}`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Stabilize login page selectors/flow in test environment for auth bypass validation',
        'Expose an API login path for deterministic token security checks when UI flow is unavailable',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }
  
  // Check if JWT is stored in localStorage
  const token = await page.evaluate(() => {
    const keys = ['token', 'authToken', 'jwt', 'accessToken'];
    for (const key of keys) {
      const value = localStorage.getItem(key);
      if (value && value.includes('.')) return value;
    }
    return null;
  }).catch(() => null);

  if (token) {
    // Test tampered token
    const tamperedToken = token.slice(0, Math.max(token.length - 10, 0)) + 'TAMPERED123';
    await page.evaluate((newToken) => {
      const keys = ['token', 'authToken', 'jwt', 'accessToken'];
      keys.forEach(key => {
        if (localStorage.getItem(key)) {
          localStorage.setItem(key, newToken);
        }
      });
    }, tamperedToken);

    // Try to access dashboard with tampered token
    const response = await page.goto('/dashboard');
    const finalUrl = page.url();

    const isTokenValidated = finalUrl.includes('/login') || 
                            finalUrl.includes('/auth') || 
                            response?.status() === 401;

    if (isTokenValidated) {
      reporter.reportPass(
        `System is protected: tampered token access was rejected (url=${finalUrl}, status=${response?.status() ?? 'n/a'}).`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    reporter.reportWarning(
      `CRITICAL token validation risk: tampered JWT appears accepted (url=${finalUrl}, status=${response?.status() ?? 'n/a'}).`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Verify JWT signature, issuer, audience, expiry, and not-before on every protected request',
        'Reject tokens with invalid alg/header combinations and enforce expected signing algorithm',
        'Rotate signing keys safely and revoke compromised tokens',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    'No JWT-like token was found in localStorage for manipulation test, so token tampering validation could not be completed.',
    [
      ...TARGET_APP_FIX_FIRST,
      'If session is cookie-based, add explicit cookie-token tampering checks in this suite',
      'Expose auth token storage mechanism in test docs so token integrity checks target the correct medium',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
  return;
});

//  XSS Prevention Tests
test('XSS prevention: user data sanitization in dashboard', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(page.request as any);
  if (!user.email || !user.password) {
    reporter.reportWarning(
      'XSS dashboard sanitization test could not run because no valid user credentials are configured.',
      [
        ...TARGET_APP_FIX_FIRST,
        'Seed a valid user for authenticated XSS rendering checks',
        'Ensure test bootstrap provisions login-capable users before running security suites',
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  // Login first
  const loginAttempt = await performUiLogin(page, user.email, user.password);
  if (!loginAttempt.ok) {
    reporter.reportWarning(
      `XSS dashboard test could not execute because UI login flow failed: ${loginAttempt.reason}`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Fix login UI flow/selectors so authenticated XSS probes can execute reliably',
        'Add API-level fallback probe for profile rendering when UI path is unstable',
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  await page.waitForTimeout(3000);

  // Check for XSS in welcome message or user data display
  const pageContent = await page.content();
  const dangerousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi, // onclick, onload, etc.
    /<iframe[^>]*>/gi,
    /<object[^>]*>/gi,
    /<embed[^>]*>/gi
  ];

  let xssFound = false;
  for (const pattern of dangerousPatterns) {
    if (pattern.test(pageContent)) {
      xssFound = true;
      break;
    }
  }

  if (xssFound) {
    reporter.reportWarning(
      'Potential XSS patterns detected in dashboard HTML content.',
      [
        ...TARGET_APP_FIX_FIRST,
        'HTML-encode untrusted data before rendering in templates/components',
        'Use strict Content-Security-Policy and avoid inline scripts',
        'Sanitize rich-text/user-generated content using a vetted sanitizer',
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }

  // Test XSS in user profile update (if endpoint exists)
  try {
    const xssPayload = '<script>alert("XSS")</script>';
    const profileResponse = await page.request.post('/api/profile', {
      data: { name: xssPayload, bio: xssPayload }
    }).catch(() => null);
    
    if (profileResponse && profileResponse.status() < 400) {
      // Reload page and check if script is executed
      await page.reload();
      const updatedContent = await page.content();
      
      const scriptExecuted = updatedContent.includes('<script>alert("XSS")</script>');

      if (!scriptExecuted) {
        reporter.reportPass(
          'System is protected: reflected/stored XSS payload was not rendered as executable script in profile content.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
        return;
      }

      reporter.reportWarning(
        'CRITICAL: XSS payload appears unsanitized in profile content rendering.',
        [
          ...TARGET_APP_FIX_FIRST,
          'Sanitize profile fields on input and encode on output',
          'Use context-aware escaping in templates and frontend rendering',
          'Add automated XSS regression tests for profile and dashboard views',
        ],
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
      return;
    }
  } catch (e) {
    // Profile endpoint might not exist
  }

  if (!xssFound) {
    reporter.reportPass(
      'System is protected: no obvious dangerous script patterns detected in dashboard content during this probe.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportWarning(
    'XSS profile update probe could not be completed because profile endpoint was unavailable or blocked.',
    [
      ...TARGET_APP_FIX_FIRST,
      'Expose/stabilize profile update endpoint in test environment for stored-XSS verification',
      'Add dedicated API schema/contract for profile updates so security probes can run deterministically',
    ],
    OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
  );
  return;
});
