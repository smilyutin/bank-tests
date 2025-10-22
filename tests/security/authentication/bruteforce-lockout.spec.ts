import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

/**
 * Brute Force Attack Protection Tests
 * 
 * These tests verify that the application implements proper rate limiting and
 * account lockout mechanisms to prevent brute force attacks on authentication endpoints.
 * 
 * Security Risks Addressed:
 * 1. Brute force password attacks
 * 2. Account enumeration attacks
 * 3. Credential stuffing attacks
 * 4. Resource exhaustion through repeated requests
 * 
 * Expected Behavior:
 * - Multiple failed login attempts should trigger rate limiting
 * - Should return 429 (Too Many Requests) status code
 * - May implement progressive delays or account lockouts
 * - Should not reveal whether accounts exist or not
 */

/**
 * Test: Repeated bad logins are throttled/locked
 * 
 * Purpose: Verifies that the application implements rate limiting to prevent
 * brute force attacks by throttling or locking accounts after multiple failed attempts.
 * 
 * Security Impact: Without brute force protection:
 * - Attackers can attempt unlimited password guesses
 * - Weak passwords can be easily cracked
 * - Accounts can be compromised through systematic attacks
 * - System resources can be exhausted
 * 
 * Test Strategy:
 * 1. Attempt multiple failed logins with incorrect passwords
 * 2. Verify that rate limiting is triggered (429 status)
 * 3. Check for progressive delays or account lockouts
 */
test('Brute-force: repeated bad logins are throttled/locked', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  if (!user.email) {
    test.skip(true, 'No persisted user');
    return;
  }

  // Step 1: Attempt multiple failed logins
  // This simulates a brute force attack with incorrect passwords
  const attempts = 6;
  let throttled = false;
  
  for (let i = 0; i < attempts; i++) {
    // Step 2: Use different incorrect passwords for each attempt
    const attempt = await tryLogin(request as any, user.email, 'bad-password-' + i);
    if (!attempt) {
      // Can't test if login endpoint missing
      test.skip(true, 'Login endpoint not found');
      return;
    }
    
    // Step 3: Check response status for rate limiting
    const { res } = attempt as any;
    const status = res.status();
    
    // Step 4: Look for 429 (Too Many Requests) status indicating rate limiting
    if (status === 429) throttled = true;
    // Some apps return 401/403 but include a lockout message after many attempts; we don't fail on 401s
  }

  // Step 5: Verify that rate limiting was triggered
  softCheck(testInfo, throttled, 'Repeated failed logins did not trigger a 429 throttling response');
});
