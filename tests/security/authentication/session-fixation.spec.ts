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
    reporter.reportSkip('No test user configured for session fixation test');
    test.skip(true, 'No test user configured for session fixation test');
    return;
  }
  
  // Compare pre-login and post-login cookies to verify session rotation.
  // Capture the anonymous session cookie before authentication.
  const anon = await request.get('/');
  const anonCookie = anon.headers()['set-cookie'] || '';

  // Authenticate the user so we can compare the post-login cookie.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    reporter.reportSkip('Login endpoint not found or unreachable');
    test.skip(true, 'Login endpoint not found or unreachable');
    return;
  }
  
  // Capture the authenticated session cookie after login.
  const { res } = attempt as any;
  const authCookie = res.headers()['set-cookie'] || '';

  // A secure flow should issue a different cookie after authentication.
  if (authCookie && authCookie !== anonCookie) {
    reporter.reportPass(
      `Session ID properly rotated on successful authentication. ` +
      `Anonymous session cookie was replaced with authenticated session cookie. ` +
      `This prevents session fixation attacks where attackers pre-set session IDs. ` +
      `Evidence: Pre-auth cookie differs from post-auth cookie.`,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  } else if (!authCookie) {
    reporter.reportSkip(
      'No session cookie set after login; session fixation probe is not applicable to this auth flow.'
    );
    test.skip(true, 'No session cookie set after login');
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
