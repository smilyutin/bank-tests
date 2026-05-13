import { test } from '@playwright/test';
import { BruteForceLockoutProbe } from '../sec-objects/authentication/bruteforce-lockout.logic';

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

test('Brute-force: repeated bad logins are throttled/locked', async ({ request }, testInfo) => {
  await new BruteForceLockoutProbe().verify(request, testInfo);
});
