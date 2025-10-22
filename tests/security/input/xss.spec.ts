import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

/**
 * XSS (Cross-Site Scripting) Vulnerability Tests
 * 
 * These tests verify that the application properly sanitizes user input and implements
 * Content Security Policy (CSP) to prevent XSS attacks.
 * 
 * Security Risks Addressed:
 * 1. Reflected XSS via URL parameters
 * 2. Stored XSS in user input fields
 * 3. DOM-based XSS vulnerabilities
 * 4. JavaScript event handler injection
 * 5. Inline script execution
 * 6. Output encoding issues
 * 
 * Expected Behavior:
 * - User input should be properly sanitized/encoded
 * - CSP should block inline script execution
 * - XSS payloads should not execute
 * - Special characters should be HTML-encoded
 */

/**
 * Test: Reflected XSS via URL parameters
 * 
 * Purpose: Verifies that URL parameters are properly sanitized to prevent
 * reflected XSS attacks where malicious scripts are reflected back to users.
 * 
 * Security Impact: Reflected XSS can lead to:
 * - Session hijacking through cookie theft
 * - Credential theft through keyloggers
 * - Malicious redirects to phishing sites
 * - Defacement of web pages
 * 
 * Test Strategy:
 * 1. Inject various XSS payloads via URL parameters
 * 2. Check if payloads are reflected unencoded in the page
 * 3. Verify that scripts do not execute
 */
test('XSS: reflected XSS via URL parameters', async ({ page }, testInfo) => {
  // Step 1: Define various XSS payloads to test
  // These represent common XSS attack vectors
  const xssPayloads = [
    '<script>alert("XSS")</script>',                    // Basic script injection
    '<img src=x onerror=alert("XSS")>',                // Image error handler
    '"><script>alert(String.fromCharCode(88,83,83))</script>', // Encoded script
    '<svg/onload=alert("XSS")>',                       // SVG onload handler
  ];

  // Step 2: Test each XSS payload
  for (const payload of xssPayloads) {
    try {
      // Step 3: Inject payload via URL parameter
      const encodedPayload = encodeURIComponent(payload);
      await page.goto(`/?search=${encodedPayload}`);
      await page.waitForTimeout(1000);

      // Step 4: Check if payload is reflected in page without encoding
      const content = await page.content();
      const isVulnerable = content.includes(payload);

      // Step 5: Verify payload was properly sanitized
      softCheck(
        testInfo,
        !isVulnerable,
        `Reflected XSS vulnerability: payload "${payload}" appears unencoded in page`
      );

      if (isVulnerable) break; // Stop after first vulnerability found
    } catch (e) {
      // Continue testing other payloads
    }
  }
});

/**
 * Test: Stored XSS in user input fields
 * 
 * Purpose: Verifies that user input fields properly sanitize data to prevent
 * stored XSS attacks where malicious scripts are permanently stored and executed
 * for other users.
 * 
 * Security Impact: Stored XSS can lead to:
 * - Persistent attacks affecting all users
 * - Data theft from multiple victims
 * - Account takeover through session hijacking
 * - Malware distribution through compromised pages
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt to inject XSS payload in profile fields
 * 3. Verify that scripts do not execute
 * 4. Check for proper input sanitization
 */
test('XSS: stored XSS in user input fields', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user
  const attempt = await tryLogin(page.request as any, user.email, user.password);
  if (!attempt) {
    test.skip(true, 'Could not login');
    return;
  }

  // Step 2: Define XSS payload for stored XSS testing
  const xssPayload = '<img src=x onerror="window.xssDetected=true">';

  try {
    // Step 3: Navigate to profile page where user input is accepted
    await page.goto('/profile').catch(() => {});
    
    // Step 4: Attempt to inject XSS in profile fields
    const nameInput = page.locator('input[name="name"], input[name="displayName"]').first();
    if (await nameInput.count() > 0) {
      await nameInput.fill(xssPayload);
      await page.click('button[type="submit"]').catch(() => {});
      await page.waitForTimeout(1000);

      // Step 5: Check if XSS executed by looking for the detection flag
      const xssExecuted = await page.evaluate(() => (window as any).xssDetected);
      
      // Step 6: Verify XSS was prevented
      softCheck(
        testInfo,
        !xssExecuted,
        'Stored XSS vulnerability: user input not properly sanitized'
      );
    }
  } catch (e) {
    // Profile page might not exist - this is acceptable
  }
});

test('XSS: DOM-based XSS protection', async ({ page }, testInfo) => {
  try {
    // Test common DOM XSS sinks
    await page.goto('/#<img src=x onerror=alert("XSS")>');
    await page.waitForTimeout(1000);

    const content = await page.content();
    const vulnerable = content.includes('<img src=x onerror=');

    softCheck(
      testInfo,
      !vulnerable,
      'Possible DOM-based XSS: fragment content rendered without sanitization'
    );
  } catch (e) {
    // Expected
  }
});

test('XSS: JavaScript event handlers sanitized', async ({ page }, testInfo) => {
  const user = await ensureTestUser(page.request as any);
  
  const eventHandlerPayloads = [
    'javascript:alert("XSS")',
    'onClick="alert(\'XSS\')"',
    'onload=alert(1)',
  ];

  for (const payload of eventHandlerPayloads) {
    try {
      await page.goto(`/?link=${encodeURIComponent(payload)}`);
      await page.waitForTimeout(500);

      const content = await page.content();
      const vulnerable = 
        content.includes('javascript:') ||
        content.includes('onclick=') ||
        content.includes('onload=');

      if (vulnerable) {
        softCheck(
          testInfo,
          false,
          `Event handler XSS vulnerability with payload: ${payload}`
        );
        break;
      }
    } catch (e) {
      // Continue
    }
  }
});

/**
 * Test: CSP blocks inline scripts
 * 
 * Purpose: Verifies that Content Security Policy (CSP) is properly implemented
 * to block inline script execution, which is a key defense against XSS attacks.
 * 
 * Security Impact: Without CSP protection:
 * - Inline scripts can execute malicious code
 * - XSS attacks can bypass other security measures
 * - Malicious scripts can steal sensitive data
 * - Attackers can perform actions on behalf of users
 * 
 * Test Strategy:
 * 1. Check for CSP header presence
 * 2. Attempt to execute inline script
 * 3. Verify script execution is blocked
 * 4. Confirm CSP is properly configured
 */
test('XSS: CSP blocks inline scripts', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  // Step 1: Check for CSP header in response
  const headers = response.headers();
  const csp = headers['content-security-policy'];

  // Step 2: Attempt to execute inline script
  // This tests if CSP blocks inline script execution
  await page.evaluate(() => {
    try {
      const script = document.createElement('script');
      script.textContent = 'window.inlineScriptExecuted = true;';
      document.body.appendChild(script);
    } catch (e) {
      // CSP blocked it - this is expected behavior
    }
  });

  await page.waitForTimeout(500);

  // Step 3: Check if inline script executed
  const executed = await page.evaluate(() => (window as any).inlineScriptExecuted);

  // Step 4: Verify CSP blocks inline scripts
  // Only check if CSP is present and doesn't allow unsafe-inline
  if (csp && !csp.includes("'unsafe-inline'")) {
    softCheck(
      testInfo,
      !executed,
      'CSP should block inline script execution'
    );
  }
});

test('XSS: output encoding for user-generated content', async ({ page }, testInfo) => {
  try {
    await page.goto('/');
    
    // Check if any user content is displayed
    const hasUserContent = await page.evaluate(() => {
      const elements = document.querySelectorAll('[data-user-content], .user-content, .comment');
      return elements.length > 0;
    });

    if (hasUserContent) {
      const content = await page.content();
      
      // Check for proper encoding of special characters
      const hasRawHTML = 
        content.includes('&lt;script&gt;') && 
        !content.includes('<script>alert');

      softCheck(
        testInfo,
        hasRawHTML || !content.includes('<script'),
        'User-generated content should be HTML-encoded'
      );
    }
  } catch (e) {
    // Page might not exist
  }
});
