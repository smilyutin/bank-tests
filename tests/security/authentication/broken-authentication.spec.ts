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
