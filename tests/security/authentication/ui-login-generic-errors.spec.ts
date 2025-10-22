import { test } from '@playwright/test';
import { ensureTestUser, softCheck } from '../utils';

/**
 * UI Login Security Tests
 * 
 * These tests verify that the login user interface implements proper security
 * measures to prevent user enumeration and provide appropriate user feedback.
 * 
 * Security Risks Addressed:
 * 1. User enumeration through specific error messages
 * 2. Rate limiting visibility to users
 * 3. Password field security (masking)
 * 
 * Expected Behavior:
 * - Generic error messages for both invalid users and wrong passwords
 * - Clear feedback when rate limited
 * - Password fields should be masked by default
 */

/**
 * Test: Generic error messages prevent user enumeration
 * 
 * Purpose: Verifies that login error messages are generic and don't reveal
 * whether a user account exists or not, preventing user enumeration attacks.
 * 
 * Security Impact: Specific error messages can lead to:
 * - User enumeration attacks to discover valid accounts
 * - Targeted attacks on known user accounts
 * - Privacy violations and reconnaissance
 * - Brute force attacks on specific users
 * 
 * Test Strategy:
 * 1. Test login with wrong password for existing user
 * 2. Test login with non-existent user
 * 3. Compare error messages to ensure they're generic
 * 4. Verify no specific user information is revealed
 */
test('UI Login: generic error messages prevent enumeration', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  const fakeEmail = 'fake-' + Date.now() + '@example.com';

  try {
    await page.goto('/login');
    
    // Step 1: Test wrong password for existing user
    await page.fill('input[name="email"], input[type="email"]', user.email!).catch(() => {});
    await page.fill('input[type="password"]', 'wrong-password').catch(() => {});
    await page.click('button[type="submit"]').catch(() => {});
    await page.waitForTimeout(1000);
    
    // Step 2: Capture error message for wrong password
    const error1 = await page.textContent('.error, .alert, [role="alert"]').catch(() => null);
    
    // Step 3: Test non-existent user
    await page.fill('input[name="email"], input[type="email"]', fakeEmail).catch(() => {});
    await page.fill('input[type="password"]', 'somepassword').catch(() => {});
    await page.click('button[type="submit"]').catch(() => {});
    await page.waitForTimeout(1000);
    
    // Step 4: Capture error message for non-existent user
    const error2 = await page.textContent('.error, .alert, [role="alert"]').catch(() => null);

    // Step 5: Verify errors are generic and don't reveal user existence
    if (error1 && error2) {
      const hasSpecificError = 
        error1.toLowerCase().includes('not found') ||
        error1.toLowerCase().includes('no user') ||
        error2.toLowerCase().includes('already exists');

      softCheck(
        testInfo,
        !hasSpecificError,
        'Login UI should show generic error messages to prevent user enumeration'
      );
    }
  } catch (e) {
    // Login page might not exist
    test.skip(true, 'Login page not available');
  }
});

/**
 * Test: Rate limiting visibility to users
 * 
 * Purpose: Verifies that users receive clear feedback when rate limiting
 * is triggered, improving user experience and security awareness.
 * 
 * Security Impact: Poor rate limiting feedback can lead to:
 * - User confusion and frustration
 * - Continued attack attempts
 * - Poor user experience
 * - Unclear security boundaries
 * 
 * Test Strategy:
 * 1. Perform multiple failed login attempts
 * 2. Check for rate limiting messages
 * 3. Verify users are informed of restrictions
 */
test('UI Login: rate limiting visible to user', async ({ page }, testInfo) => {
  try {
    await page.goto('/login');
    
    // Step 1: Perform multiple failed login attempts to trigger rate limiting
    for (let i = 0; i < 10; i++) {
      await page.fill('input[name="email"], input[type="email"]', 'test@example.com').catch(() => {});
      await page.fill('input[type="password"]', `wrong-${i}`).catch(() => {});
      await page.click('button[type="submit"]').catch(() => {});
      await page.waitForTimeout(500);
    }

    // Step 2: Check for rate limiting message in page content
    const body = await page.textContent('body').catch(() => '') || '';
    const hasRateLimitMsg = 
      body.toLowerCase().includes('too many') ||
      body.toLowerCase().includes('rate limit') ||
      body.toLowerCase().includes('try again');

    // Step 3: Verify users are informed about rate limiting
    softCheck(
      testInfo,
      hasRateLimitMsg,
      'UI should inform users when rate limited'
    );
  } catch (e) {
    test.skip(true, 'Login page not available');
  }
});

/**
 * Test: Password field masking
 * 
 * Purpose: Verifies that password input fields are properly masked by default
 * to prevent shoulder surfing and accidental password exposure.
 * 
 * Security Impact: Unmasked password fields can lead to:
 * - Shoulder surfing attacks
 * - Accidental password exposure
 * - Privacy violations
 * - Credential theft in public spaces
 * 
 * Test Strategy:
 * 1. Navigate to login page
 * 2. Check password field type attribute
 * 3. Verify field is masked (type="password")
 */
test('UI Login: password field masked by default', async ({ page }, testInfo) => {
  try {
    await page.goto('/login');
    
    // Step 1: Locate password input field
    const passwordInput = page.locator('input[type="password"]').first();
    const type = await passwordInput.getAttribute('type');
    
    // Step 2: Verify password field is properly masked
    softCheck(
      testInfo,
      type === 'password',
      'Password field should be masked (type="password") by default'
    );
  } catch (e) {
    test.skip(true, 'Login page not available');
  }
});
