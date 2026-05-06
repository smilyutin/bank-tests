import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'Regenerate session ID/cookie after successful authentication',
  'Invalidate pre-login session ID to prevent fixation attacks',
  'Ensure new session cookie is issued with HttpOnly and Secure flags',
  'Implement session binding: verify user identity matches session after login',
  'Use strong, unpredictable session ID generation (at least 128 bits entropy)',
  'Clear any pre-authentication session context after successful login',
];

/**
 * Session Fixation Vulnerability Tests
 * 
 * These tests verify that the application properly handles session management
 * to prevent session fixation attacks where attackers can force users to use
 * a predetermined session ID.
 * 
 * Security Risks Addressed:
 * 1. Session fixation through cookie reuse
 * 2. Session ID rotation on authentication
 * 3. Proper session invalidation
 * 
 * Expected Behavior:
 * - Session cookies should change after login
 * - Old session IDs should be invalidated
 * - New session IDs should be generated
 */

test('Session ID rotates on login to prevent fixation attacks', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const user = await ensureTestUser(request as any);
  if (!user.email || !user.password) {
    reporter.reportWarning('No test user configured for session fixation test', [
      'Ensure test credentials exist in tests/fixtures/users.json',
      'Run user initialization scripts',
      'Verify app registration endpoint is available',
      'Check FIXTURE_USERS_INTEGRATION.md for setup process'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }
  
  // Step 1: Get session cookie before login (anonymous session)
  const anon = await request.get('/');
  const anonCookie = anon.headers()['set-cookie'] || '';

  // Step 2: Perform user authentication
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    reporter.reportWarning('Login endpoint not found or unreachable', [
      'Verify /login or /api/auth endpoints exist and are accessible',
      'Check that app is running and accepting HTTP requests',
      'Review server logs for auth endpoint errors',
      'Ensure test user credentials are valid for the app'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }
  
  // Step 3: Get session cookie after login (authenticated session)
  const { res } = attempt as any;
  const authCookie = res.headers()['set-cookie'] || '';

  // Step 4: Verify session cookie changed after login
  if (authCookie && authCookie !== anonCookie) {
    reporter.reportPass(
      `Session ID properly rotated on successful authentication. ` +
      `Anonymous session cookie was replaced with authenticated session cookie. ` +
      `This prevents session fixation attacks where attackers pre-set session IDs. ` +
      `Evidence: Pre-auth cookie differs from post-auth cookie.`,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  } else if (!authCookie) {
    reporter.reportWarning(
      `No session cookie set after login. App may be using token-based authentication without proper session invalidation. ` +
      `Verify that old tokens cannot be reused after logout.`,
      TARGET_APP_FIX_FIRST,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  } else {
    reporter.reportWarning(
      `Session cookie was not rotated after login. Same session ID used before and after authentication. ` +
      `This allows attackers to conduct session fixation attacks by forcing users to use attacker-controlled session IDs. ` +
      `Impact: complete session hijacking and account takeover.`,
      TARGET_APP_FIX_FIRST,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});
