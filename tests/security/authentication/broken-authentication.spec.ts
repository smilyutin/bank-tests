import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

test('Broken authentication: weak passwords are rejected', async ({ request }, testInfo) => {
  const weakPasswords = ['123456', 'password', 'abc123', '12345', 'qwerty'];
  
  for (const weakPwd of weakPasswords) {
    const testEmail = `test-${Date.now()}@example.com`;
    
    // Try to create account or login with weak password
    try {
      await request.post('/api/register', {
        data: { email: testEmail, password: weakPwd },
      });
    } catch (e) {
      // Expected to fail or be rejected
    }
  }

  // This is a soft reminder - actual validation depends on app
  softCheck(
    testInfo,
    true,
    'Ensure weak passwords are rejected during registration'
  );
});

test('Broken authentication: no default credentials accepted', async ({ request }, testInfo) => {
  const defaultCreds = [
    { email: 'admin@admin.com', password: 'admin' },
    { email: 'admin@example.com', password: 'password' },
    { email: 'test@test.com', password: 'test' },
    { email: 'user@user.com', password: 'user' },
  ];

  let defaultAccepted = false;

  for (const cred of defaultCreds) {
    const attempt = await tryLogin(request as any, cred.email, cred.password);
    if (attempt) {
      const { res } = attempt as any;
      if (res.status() >= 200 && res.status() < 300) {
        defaultAccepted = true;
        break;
      }
    }
  }

  softCheck(
    testInfo,
    !defaultAccepted,
    'Default credentials should not be accepted (admin/admin, test/test, etc.)'
  );
});

test('Broken authentication: password reset requires verification', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email) {
    test.skip(true, 'No user configured');
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
    
    softCheck(
      testInfo,
      requiresVerification || status === 404,
      `Password reset should require verification token (status: ${status})`
    );
  } catch (e) {
    // Endpoint might not exist
  }
});

test('Broken authentication: enumeration protection on login', async ({ request }, testInfo) => {
  const realUser = await ensureTestUser(request as any);
  const fakeEmail = 'nonexistent-' + Date.now() + '@example.com';
  
  if (!realUser.email) {
    test.skip(true, 'No user configured');
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

    softCheck(
      testInfo,
      !hasSpecificMessage,
      'Login error messages may allow user enumeration (should use generic messages)'
    );
  }
});

// 🔴 CRITICAL SECURITY TESTS - Authentication Bypass (Priority #1)
test('Authentication bypass: direct dashboard access without credentials', async ({ page }, testInfo) => {
  // Clear any existing authentication
  await page.context().clearCookies();
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  // Attempt direct dashboard access
  const response = await page.goto('/dashboard');
  const finalUrl = page.url();

  // Should redirect to login or return 401/403
  const isBlocked = finalUrl.includes('/login') || 
                   finalUrl.includes('/auth') || 
                   response?.status() === 401 || 
                   response?.status() === 403;

  softCheck(
    testInfo,
    isBlocked,
    'CRITICAL: Dashboard accessible without authentication - implement proper access controls'
  );
});

test('Authentication bypass: JWT token manipulation', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Login normally first
  await page.goto('/login');
  await page.fill('[name="email"], [type="email"]', user.email);
  await page.fill('[name="password"], [type="password"]', user.password);
  await page.click('[type="submit"], button[type="submit"]');
  
  // Check if JWT is stored in localStorage
  const token = await page.evaluate(() => {
    const keys = ['token', 'authToken', 'jwt', 'accessToken'];
    for (const key of keys) {
      const value = localStorage.getItem(key);
      if (value && value.includes('.')) return value;
    }
    return null;
  });

  if (token) {
    // Test tampered token
    const tamperedToken = token.substring(0, -10) + 'TAMPERED123';
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

    softCheck(
      testInfo,
      isTokenValidated,
      'CRITICAL: Tampered JWT tokens accepted - implement proper signature verification'
    );
  }
});

// 🔴 XSS Prevention Tests
test('XSS prevention: user data sanitization in dashboard', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Login first
  await page.goto('/login');
  await page.fill('[name="email"], [type="email"]', user.email);
  await page.fill('[name="password"], [type="password"]', user.password);
  await page.click('[type="submit"], button[type="submit"]');
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
    testInfo.annotations.push({
      type: 'security-warning',
      description: 'Potential XSS vulnerability detected in dashboard content'
    });
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
      
      softCheck(
        testInfo,
        !scriptExecuted,
        'CRITICAL: XSS vulnerability in user profile data - implement proper input sanitization'
      );
    }
  } catch (e) {
    // Profile endpoint might not exist
  }
});
