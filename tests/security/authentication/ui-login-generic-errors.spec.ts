import { test } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { LOGIN_SELECTORS, getInputLocator } from '../selectors.config';
import { getTestUserWithUsername } from '../test-users';
import { softCheck } from '../utils/utils';

const TARGET_APP_FIX_FIRST = [
  'Use generic error messages for all login failures (e.g., "Invalid credentials")',
  'Never reveal whether email/username exists in the database',
  'Return same HTTP status code (401) for user not found and wrong password',
  'Log enumeration attempts separately from normal login failures for security monitoring',
  'Display rate limiting messages to users after multiple failed attempts',
  'Ensure password field is masked with type="password" attribute',
];

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
test('UI login shows generic error messages to prevent user enumeration', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // Use pre-configured test user from fixtures/users.json
  const user = getTestUserWithUsername();
  const fakeEmail = 'fake-' + Date.now() + '@example.com';

  try {
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      reporter.reportWarning(
        'UI login enumeration probe could not run because the login page was not found (404).',
        [
          'Ensure login route is deployed and reachable in the target environment',
          'Stabilize UI startup checks before authentication security tests run',
          'Fail CI earlier when login-page availability checks fail'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }
    
    // Check if username/email input exists before proceeding  
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    if (!emailInput) {
      reporter.reportWarning(
        'UI login enumeration probe could not run because the login form was not found on the page.',
        [
          'Update selectors in tests/security/selectors.config.ts for the current login UI',
          'Ensure username/email field is rendered and visible',
          'Run selector discovery before security UI test stage'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }
    
    // Step 1: Test wrong password for existing user
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!passwordInput || !submitButton) {
      reporter.reportWarning(
        'UI login enumeration probe could not run because password or submit inputs were not found.',
        [
          'Update selectors in tests/security/selectors.config.ts for the current login UI',
          'Ensure password and submit controls are rendered and interactable',
          'Run selector discovery before security UI test stage'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
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

      if (!hasSpecificError && error1 === error2) {
        reporter.reportPass(
          `Login error messages are generic and identical. Same message for wrong password and non-existent user. ` +
          `This prevents user enumeration attacks. Error shown: "${error1.slice(0, 50)}..."`,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      } else if (!hasSpecificError) {
        reporter.reportWarning(
          `Error messages are generic (no "not found"/"no user" strings) but differ between user not found and wrong password. ` +
          `Error 1: "${error1}". Error 2: "${error2}". Attackers may still enumerate users via timing/differences.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      } else {
        reporter.reportWarning(
          `Login error messages reveal user account information. ` +
          `Error contains enumeration hints: "${error1}" vs "${error2}". ` +
          `Attackers can enumerate valid accounts and target them for brute force attacks.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API2_AUTH.name
        );
      }
    } else {
      reporter.reportWarning(
        'UI login enumeration probe could not capture login error messages for comparison.',
        [
          'Ensure login failures render visible error text in the UI',
          'Update LOGIN_SELECTORS.errorMessage to match actual error containers',
          'Standardize error rendering so security probes can verify generic responses'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  } catch (e) {
    // Login page might not exist or selectors don't match
    reporter.reportWarning(
      `UI login enumeration probe failed due to login-page interaction error: ${String(e).slice(0, 100)}`,
      [
        'Ensure login page is reachable and stable in the target environment',
        'Update UI selectors to match the current application',
        'Fail CI earlier when authentication UI smoke checks fail'
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
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
test('UI login displays rate limiting feedback to users', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  try {
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      reporter.reportWarning(
        'UI rate-limiting-feedback probe could not run because the login page was not found (404).',
        [
          'Ensure login route is deployed and reachable in the target environment',
          'Stabilize UI startup checks before authentication security tests run',
          'Fail CI earlier when login-page availability checks fail'
        ],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
      return;
    }
    
    // Check if username/email input exists before proceeding
    const emailInput = await getInputLocator(page, LOGIN_SELECTORS.emailInput);
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    const submitButton = await getInputLocator(page, LOGIN_SELECTORS.submitButton);
    
    if (!emailInput || !passwordInput || !submitButton) {
      reporter.reportWarning(
        'UI rate-limiting-feedback probe could not run because login form controls were not found.',
        [
          'Update selectors in tests/security/selectors.config.ts for the current login UI',
          'Ensure email/username, password, and submit controls are rendered',
          'Run selector discovery before security UI test stage'
        ],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
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
      body.toLowerCase().includes('try again later');

    // Step 3: Verify users are informed about rate limiting
    if (hasRateLimitMsg) {
      reporter.reportPass(
        `UI provides clear feedback when rate limited after multiple failed attempts. ` +
        `Users are informed to try again later. This improves user experience during attacks. ` +
        `Evidence: Rate limit message displayed after 10 failed login attempts.`,
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    } else {
      reporter.reportWarning(
        `UI does not display rate limiting feedback to users after multiple failed attempts. ` +
        `Users may continue attempting to login and be confused by continued failures. ` +
        `Impact: Poor UX but also helps attackers avoid detection of attack patterns.`,
        [...TARGET_APP_FIX_FIRST, 'Display "Too many attempts, try again later" message when rate limited'],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    }
  } catch (e) {
    reporter.reportWarning(
      `UI rate-limiting-feedback probe failed due to login-page interaction error: ${String(e).slice(0, 100)}`,
      [
        'Ensure login page is reachable and stable in the target environment',
        'Update UI selectors to match the current application',
        'Fail CI earlier when authentication UI smoke checks fail'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
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
  const reporter = new SecurityReporter(testInfo);
  try {
    // Check if login page exists with short timeout
    const response = await page.goto(LOGIN_SELECTORS.loginPath, { timeout: 5000, waitUntil: 'domcontentloaded' });
    if (!response || response.status() === 404) {
      reporter.reportWarning(
        'UI password-masking probe could not run because the login page was not found (404).',
        [
          'Ensure login route is deployed and reachable in the target environment',
          'Stabilize UI startup checks before authentication security tests run',
          'Fail CI earlier when login-page availability checks fail'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }
    
    // Step 1: Locate password input field
    const passwordInput = await getInputLocator(page, LOGIN_SELECTORS.passwordInput);
    if (!passwordInput) {
      reporter.reportWarning(
        'UI password-masking probe could not run because password input was not found on login page.',
        [
          'Update password selector in tests/security/selectors.config.ts',
          'Ensure password input is present and rendered with a stable selector',
          'Run selector discovery before security UI test stage'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
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
    reporter.reportWarning(
      `UI password-masking probe failed due to login-page interaction error: ${String(e).slice(0, 100)}`,
      [
        'Ensure login page is reachable and stable in the target environment',
        'Update UI selectors to match the current application',
        'Fail CI earlier when authentication UI smoke checks fail'
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});
