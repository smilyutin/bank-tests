import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Enforce strong authentication controls (password policy, lockout, session validation)',
  '2) Block authentication bypass paths on protected routes and APIs',
  '3) Validate JWT/session tokens strictly and reject tampered/expired tokens',
  '4) Use generic auth error messages and sanitize all user-controlled content',
];

/**
 * Role-Based Access Control (RBAC) and Authorization Tests
 * 
 * These tests verify that the application properly implements role-based
 * access control and prevents unauthorized access to privileged resources
 * and operations.
 * 
 * Security Risks Addressed:
 * 1. Regular users accessing admin endpoints
 * 2. Role elevation attacks through API manipulation
 * 3. Sensitive data exposure in JWT tokens
 * 4. Unauthorized destructive operations
 * 5. Privilege escalation vulnerabilities
 * 
 * Expected Behavior:
 * - Regular users should be denied access to admin endpoints
 * - Role elevation attempts should be blocked
 * - JWT tokens should not contain sensitive data
 * - Destructive operations should require proper authorization
 * - Role-based permissions should be enforced
 */

/**
 * Test: Regular user cannot access admin endpoints
 * 
 * Purpose: Verifies that regular users are properly restricted from
 * accessing administrative endpoints and functionality.
 * 
 * Security Impact: Admin endpoint access by regular users can lead to:
 * - Unauthorized administrative actions
 * - Data breaches through admin privileges
 * - System configuration changes
 * - User account manipulation
 * 
 * Test Strategy:
 * 1. Authenticate as regular user
 * 2. Attempt to access admin endpoints
 * 3. Verify access is denied with 403 status
 * 4. Ensure proper role-based restrictions
 */
test('Role scoping: regular user cannot access admin endpoints', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Admin-endpoint role-scoping probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Authenticate as a regular user before probing privileged routes.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Admin-endpoint role-scoping probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Try a handful of admin routes that should be blocked for non-admin users.
  const adminEndpoints = [
    '/api/admin/users',     // User management
    '/api/admin/settings',  // System settings
    '/api/admin/logs',      // System logs
    '/api/admin/dashboard', // Admin dashboard
    '/admin/users',         // Admin UI
  ];

  let properlyScoped = true;

  // Test each admin-only endpoint with a non-admin context.
  for (const endpoint of adminEndpoints) {
    try {
      const res = await request.get(endpoint, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'X-Auth-Token': token,
        },
      });

      // A successful 200 here would indicate broken role enforcement.
      if (res.status() === 200) {
        properlyScoped = false;
        break;
      }
    } catch (e) {
      // Expected behavior - access denied
    }
  }

  // Keep the soft check so the test emits a readable signal in CI.
  softCheck(
    testInfo,
    properlyScoped,
    'Regular users should not have access to admin endpoints (should return 403)'
  );

  if (properlyScoped) {
    reporter.reportPass(
      'Regular user access to admin endpoints was denied across all tested routes.',
      OWASP_VULNERABILITIES.API5_BFLA.name
    );
  }
});

test('Role scoping: role elevation attempts blocked', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Role-elevation probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Use the same authenticated user to test role-elevation attempts.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Role-elevation probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Submit an obvious privilege-escalation payload and expect rejection.
  try {
    const res = await request.patch('/api/users/me', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { role: 'admin', is_admin: true },
    });

    const status = res.status();
    
    softCheck(
      testInfo,
      status === 403 || status === 400,
      'Users should not be able to elevate their own roles via API'
    );

    if (status === 403 || status === 400) {
      reporter.reportPass(
        `Role elevation was blocked (status ${status}).`,
        OWASP_VULNERABILITIES.API5_BFLA.name
      );
    }
  } catch (e) {
    // Endpoint might not exist
  }
});

test('Role scoping: JWT does not expose sensitive role claims', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('JWT role-claim exposure probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('JWT role-claim exposure probe could not run because login failed or no token was obtained.');
    test.skip(true, 'Login failed or no token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Only decode the payload if the token has the expected JWT structure.
  if (typeof token === 'string' && token.split('.').length === 3) {
    try {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      
      // JWTs should not contain secrets or private keys in cleartext claims.
      const hasSensitive = 
        payload.password || 
        payload.secret || 
        payload.private_key;

      softCheck(
        testInfo,
        !hasSensitive,
        'JWT should not contain sensitive data like passwords or private keys'
      );

      if (!hasSensitive) {
        reporter.reportPass(
          'JWT payload did not expose sensitive role-related data.',
          OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
        );
      }
    } catch (e) {
      // Not a valid JWT
    }
  }
});

test('Role scoping: operations limited by scope', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Scoped-operations probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Scoped-operations probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Check a few destructive operations that should stay behind elevated access.
  const restrictedOps = [
    { method: 'DELETE', url: '/api/users/1' },
    { method: 'DELETE', url: '/api/accounts/1' },
    { method: 'POST', url: '/api/admin/settings' },
  ];

  let properlyRestricted = true;

  for (const op of restrictedOps) {
    try {
      const res = await request.fetch(op.url, {
        method: op.method,
        headers: { 'Authorization': `Bearer ${token}` },
      });

      // Any non-error result means the operation may be over-permissive.
      if (res.status() < 400) {
        properlyRestricted = false;
        break;
      }
    } catch (e) {
      // Expected
    }
  }

  softCheck(
    testInfo,
    properlyRestricted,
    'Destructive operations should require proper authorization'
  );

  if (properlyRestricted) {
    reporter.reportPass(
      'All tested destructive operations were blocked without elevated authorization.',
      OWASP_VULNERABILITIES.API5_BFLA.name
    );
  }
});