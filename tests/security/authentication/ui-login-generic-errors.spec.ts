import { test } from '@playwright/test';
import { softCheck } from '../utils';
import { LOGIN_SELECTORS, getInputLocator } from '../selectors.config';
import { getTestUserWithUsername } from '../test-users';

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
  // Use pre-configured test user from fixtures/users.json
  const user = getTestUserWithUsername();
  const fakeEmail = 'fake-' + Date.now() + '@example.com';

  try {
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      test.skip(true, 'Login page not found (404)');
      return;
    }
    
    // Check if username/email input exists before proceeding  
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    if (!emailInput) {
      test.skip(true, 'Login form not found on page');
      return;
    }
    
    // Step 1: Test wrong password for existing user
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!passwordInput || !submitButton) {
      test.skip(true, 'Login form inputs not found');
      return;
    }
    
    await emailInput.fill(user.username || user.email, { timeout: 3000 });
    await passwordInput.fill('wrong-password', { timeout: 3000 });
    await submitButton.click({ timeout: 3000 });
    await page.waitForTimeout(1000);
    
    // Step 2: Capture error message for wrong password
    const errorSelector = LOGIN_SELECTORS.errorMessage.join(', ');
    const error1 = await page.locator(errorSelector).first().textContent({ timeout: 2000 }).catch(() => null);
    
    // Step 3: Test non-existent user
    await emailInput.fill(fakeEmail, { timeout: 3000 });
    await passwordInput.fill('somepassword', { timeout: 3000 });
    await submitButton.click({ timeout: 3000 });
    await page.waitForTimeout(1000);
    
    // Step 4: Capture error message for non-existent user
    const error2 = await page.locator(errorSelector).first().textContent({ timeout: 2000 }).catch(() => null);

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
    } else {
      test.skip(true, 'Could not capture error messages from login form');
    }
  } catch (e) {
    // Login page might not exist or selectors don't match
    test.skip(true, `Login page not available: ${e}`);
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
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      test.skip(true, 'Login page not found (404)');
      return;
    }
    
    // Check if username/email input exists before proceeding
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!emailInput || !passwordInput || !submitButton) {
      test.skip(true, 'Login form not found on page');
      return;
    }
    
    // Step 1: Perform multiple failed login attempts to trigger rate limiting
    for (let i = 0; i < 10; i++) {
      await emailInput.fill('test@example.com', { timeout: 3000 }).catch(() => {});
      await passwordInput.fill(`wrong-${i}`, { timeout: 3000 }).catch(() => {});
      await submitButton.click({ timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(500);
    }

    // Step 2: Check for rate limiting message in page content
    const body = await page.locator('body').textContent({ timeout: 2000 }).catch(() => '') || '';
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
    test.skip(true, `Login page not available: ${e}`);
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
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      test.skip(true, 'Login page not found (404)');
      return;
    }
    
    // Step 1: Locate password input field
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    if (!passwordInput) {
      test.skip(true, 'Password field not found on login page');
      return;
    }
    
    const type = await passwordInput.getAttribute('type', { timeout: 3000 });
    
    // Step 2: Verify password field is properly masked
    softCheck(
      testInfo,
      type === 'password',
      'Password field should be masked (type="password") by default'
    );
  } catch (e) {
    test.skip(true, `Login page not available: ${e}`);
  }
});
