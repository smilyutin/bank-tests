import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Add brute-force protection on login endpoints (per-IP and per-user limits)',
  '2) Return HTTP 429 with Retry-After when thresholds are exceeded',
  '3) Implement account lockout or progressive backoff after repeated failures',
  '4) Monitor and alert on repeated failed authentication attempts',
];

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
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  if (!user.email) {
    reporter.reportWarning('No test user configured for brute-force test', [
      'Ensure test user credentials exist in tests/fixtures/users.json',
      'Run user initialization and fixture setup scripts',
      'Verify app registration/user creation endpoint is working',
      'Check FIXTURE_USERS_INTEGRATION.md for user setup process'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }

  // Step 1: Attempt multiple failed logins
  // This simulates a brute force attack with incorrect passwords
  const attempts = 6;
  let throttled = false;
  let throttleReason = '';
  let throttleAtAttempt = -1;
  const statuses: number[] = [];
  let loginPath = 'unknown';
  
  for (let i = 0; i < attempts; i++) {
    // Step 2: Use different incorrect passwords for each attempt
    const attempt = await tryLogin(request as any, user.email, 'bad-password-' + i);
    if (!attempt) {
      // Can't test if login endpoint missing
      reporter.reportWarning('Login endpoint not found or unreachable for brute-force test', [
        'Verify /login or /api/auth endpoints exist and are accessible',
        'Ensure application server is running and responding to HTTP requests',
        'Check server configuration and firewall for auth endpoint access',
        'Review server logs for auth endpoint errors or crashes'
      ], OWASP_VULNERABILITIES.API2_AUTH.name);
      return;
    }
    
    // Step 3: Check response status for rate limiting
    const { res, path } = attempt as any;
    loginPath = path || loginPath;
    const status = res.status();
    statuses.push(status);
    
    // Step 4: Look for 429 (Too Many Requests) status indicating rate limiting
    if (status === 429) {
      throttled = true;
      throttleReason = `Server returned HTTP 429 on attempt ${i + 1}`;
      throttleAtAttempt = i + 1;
      break;
    }

    const headers = res.headers();
    if (headers['retry-after'] || headers['x-ratelimit-remaining'] === '0') {
      throttled = true;
      throttleReason = headers['retry-after']
        ? `Server returned Retry-After header on attempt ${i + 1}`
        : `X-RateLimit-Remaining reached 0 on attempt ${i + 1}`;
      throttleAtAttempt = i + 1;
      break;
    }
    // Some apps return 401/403 but include a lockout message after many attempts; we don't fail on 401s
  }

  // Step 5: Verify that rate limiting was triggered
  const statusSummary = `[${statuses.join(', ')}]`;

  if (throttled) {
    reporter.reportPass(
      `System is protected: brute-force throttling/lockout signal detected on ${loginPath} after ${throttleAtAttempt} failed attempts. ` +
      `Reason: ${throttleReason}. Observed status progression: ${statusSummary}. ` +
      `This helps prevent credential stuffing and password-guessing attacks.`,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    `No brute-force throttling detected: ${attempts} failed login attempts to ${loginPath} did not trigger 429 or lockout headers. ` +
    `Observed status progression: ${statusSummary}. ` +
    `Risk: attacker can perform repeated password guessing with limited friction.`,
    [
      ...TARGET_APP_FIX_FIRST,
      `Apply strict auth throttling policy on ${loginPath} (e.g., 5-10 failed attempts per minute)`,
      'Use combined controls: per-user, per-IP, and global rate limits',
      'Add temporary lockout/CAPTCHA challenge after threshold is exceeded',
      'Record auth-failure telemetry and feed SIEM detection rules',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});
