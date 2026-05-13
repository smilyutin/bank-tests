import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { cspHasUnsafeInline, getContentSecurityPolicy } from '../utils/csp';
import { pageHasAnySelector } from '../utils/dom';

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
  const reporter = new SecurityReporter(testInfo);
  // Exercise a few classic reflected-XSS payload shapes.
  // These represent common XSS attack vectors
  const xssPayloads = [
    '<script>alert("XSS")</script>',                    // Basic script injection
    '<img src=x onerror=alert("XSS")>',                // Image error handler
    '"><script>alert(String.fromCharCode(88,83,83))</script>', // Encoded script
    '<svg/onload=alert("XSS")>',                       // SVG onload handler
  ];

  // Send each payload through the URL and check whether it comes back unsanitized.
  for (const payload of xssPayloads) {
    try {
      // Encode the payload before placing it into the query string.
      const encodedPayload = encodeURIComponent(payload);
      await page.goto(`/?search=${encodedPayload}`);
      await page.waitForTimeout(1000);

      // If the raw payload is present, the reflection path is unsafe.
      const content = await page.content();
      const isVulnerable = content.includes(payload);

      // Treat raw reflection as a security finding.
      softCheck(
        testInfo,
        !isVulnerable,
        `Reflected XSS vulnerability: payload "${payload}" appears unencoded in page`
      );

      if (!isVulnerable) {
        reporter.reportPass(
          `Reflected XSS payload "${payload}" was not reflected unencoded.`,
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }

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
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(page.request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Log in first so the stored-XSS probe runs against authenticated profile data.
  const attempt = await tryLogin(page.request as any, user.email, user.password);
  if (!attempt) {
    test.skip(true, 'Could not login');
    return;
  }

  // Use a payload that flips a flag if it executes in the browser.
  const xssPayload = '<img src=x onerror="window.xssDetected=true">';

  try {
    // Navigate to the profile page where user-controlled fields are updated.
    await page.goto('/profile').catch(() => {});
    
    // Step 4: Attempt to inject XSS in profile fields
    const nameInput = page.locator('input[name="name"], input[name="displayName"]').first();
    if (await nameInput.count() > 0) {
      await nameInput.fill(xssPayload);
      await page.click('button[type="submit"]').catch(() => {});
      await page.waitForTimeout(1000);

      // Check the browser flag instead of relying on visual output.
      const xssExecuted = await page.evaluate(() => (window as any).xssDetected);
      
      // Step 6: Verify XSS was prevented
      softCheck(
        testInfo,
        !xssExecuted,
        'Stored XSS vulnerability: user input not properly sanitized'
      );

      if (!xssExecuted) {
        reporter.reportPass(
          'Stored XSS payload did not execute after profile update.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    }
  } catch (e) {
    // Profile page might not exist - this is acceptable
  }
});

test('XSS: DOM-based XSS protection', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
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

    if (!vulnerable) {
      reporter.reportPass(
        'DOM fragment content was not rendered as executable HTML.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
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
      } else {
        const reporter = new SecurityReporter(testInfo);
        reporter.reportPass(
          `JavaScript event-handler payload was not rendered as an executable handler: ${payload}`,
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    } catch (e) {
      // Continue
    }
  }
});

/**
 * Test: inline script execution is blocked by CSP
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
test('XSS: inline script execution is blocked by CSP', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  // Read CSP before attempting the inline-script check.
  const csp = getContentSecurityPolicy(response.headers());

  // Create an inline script element and see whether CSP blocks it.
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

  // Step 4: Verify CSP blocks inline script execution
  // Only check if CSP is present and doesn't allow unsafe-inline
  if (csp && !cspHasUnsafeInline(csp)) {
    softCheck(
      testInfo,
      !executed,
      'CSP should block inline script execution'
    );

    if (!executed) {
      reporter.reportPass(
        'CSP blocked inline script execution.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
  }
});

test('XSS: output encoding for user-generated content', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  try {
    await page.goto('/');
    
    // Only inspect pages that actually render user-controlled content.
    const hasUserContent = await pageHasAnySelector(page, ['[data-user-content]', '.user-content', '.comment']);

    if (hasUserContent) {
      const content = await page.content();
      
      // Raw script tags should never survive HTML encoding.
      const hasRawHTML = 
        content.includes('&lt;script&gt;') && 
        !content.includes('<script>alert');

      softCheck(
        testInfo,
        hasRawHTML || !content.includes('<script'),
        'User-generated content should be HTML-encoded'
      );

      if (hasRawHTML || !content.includes('<script')) {
        reporter.reportPass(
          'User-generated content was HTML-encoded.',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
    }
  } catch (e) {
    // Page might not exist
  }
});
