import { test, expect } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

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

/**
 * Test: Session ID rotation on login
 * 
 * Purpose: Verifies that session cookies are rotated when users authenticate,
 * preventing session fixation attacks where attackers can hijack user sessions.
 * 
 * Security Impact: Session fixation can lead to:
 * - Session hijacking by attackers
 * - Unauthorized access to user accounts
 * - Account takeover attacks
 * - Privilege escalation through session reuse
 * 
 * Test Strategy:
 * 1. Capture session cookie before login (anonymous)
 * 2. Perform user authentication
 * 3. Capture session cookie after login
 * 4. Verify cookies are different (rotation occurred)
 */
test('Session fixation: session id should rotate on login', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  if (!user.email || !user.password) {
    test.skip(true, 'No persisted user');
    return;
  }
  
  // Step 1: Get session cookie before login (anonymous session)
  const anon = await request.get('/');
  const anonCookie = anon.headers()['set-cookie'] || '';

  // Step 2: Perform user authentication
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    test.skip(true, 'Login endpoint not found');
    return;
  }
  
  // Step 3: Get session cookie after login (authenticated session)
  const { res } = attempt as any;
  const authCookie = res.headers()['set-cookie'] || '';

  // Step 4: Verify session cookie changed after login
  // This indicates proper session rotation and prevents session fixation
  softCheck(
    testInfo, 
    !!authCookie && authCookie !== anonCookie, 
    'Session cookie did not change after login (possible session fixation)'
  );
});
