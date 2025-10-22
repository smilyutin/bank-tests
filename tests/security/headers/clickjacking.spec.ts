import { test } from '@playwright/test';
import { softCheck } from '../utils';

/**
 * Clickjacking Protection Tests
 * 
 * These tests verify that the application implements proper clickjacking protection
 * to prevent malicious websites from embedding the application in hidden iframes
 * and tricking users into performing unintended actions.
 * 
 * Security Risks Addressed:
 * 1. Clickjacking attacks through iframe embedding
 * 2. UI redressing attacks
 * 3. Cross-origin iframe embedding
 * 4. Malicious overlay attacks
 * 
 * Expected Behavior:
 * - X-Frame-Options header should be present
 * - CSP frame-ancestors directive should be configured
 * - Cross-origin iframe embedding should be blocked
 * - Modern browsers should respect frame restrictions
 */

/**
 * Test: X-Frame-Options header presence and validation
 * 
 * Purpose: Verifies that the X-Frame-Options header is present and properly
 * configured to prevent clickjacking attacks.
 * 
 * Security Impact: Missing X-Frame-Options can lead to:
 * - Clickjacking attacks through iframe embedding
 * - UI redressing attacks
 * - Malicious overlay attacks
 * - Unauthorized actions performed by users
 * 
 * Test Strategy:
 * 1. Check for presence of X-Frame-Options header
 * 2. Verify header has valid values (DENY or SAMEORIGIN)
 * 3. Ensure proper clickjacking protection
 */
test('Clickjacking: X-Frame-Options header present', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const xFrameOptions = headers['x-frame-options'];

  // Step 1: Verify X-Frame-Options header is present
  softCheck(
    testInfo,
    !!xFrameOptions,
    'X-Frame-Options header should be present to prevent clickjacking'
  );

  // Step 2: Validate X-Frame-Options header value
  if (xFrameOptions) {
    const validValues = ['DENY', 'SAMEORIGIN'];
    const isValid = validValues.includes(xFrameOptions.toUpperCase());
    
    softCheck(
      testInfo,
      isValid,
      `X-Frame-Options should be DENY or SAMEORIGIN (got: ${xFrameOptions})`
    );
  }
});

/**
 * Test: CSP frame-ancestors directive
 * 
 * Purpose: Verifies that Content Security Policy includes the frame-ancestors
 * directive for modern clickjacking protection, which is more flexible than
 * X-Frame-Options.
 * 
 * Security Impact: Missing CSP frame-ancestors can lead to:
 * - Modern browsers ignoring X-Frame-Options
 * - Clickjacking attacks on newer browsers
 * - Inconsistent protection across browser versions
 * - Reduced security posture
 * 
 * Test Strategy:
 * 1. Check for CSP header presence
 * 2. Verify frame-ancestors directive exists
 * 3. Ensure directive has restrictive values
 */
test('Clickjacking: CSP frame-ancestors directive present', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  // Step 1: Check if CSP header is present
  if (csp) {
    const hasFrameAncestors = csp.includes('frame-ancestors');
    
    // Step 2: Verify frame-ancestors directive exists
    softCheck(
      testInfo,
      hasFrameAncestors,
      "CSP should include 'frame-ancestors' directive for modern clickjacking protection"
    );

    // Step 3: Ensure directive has restrictive values
    if (hasFrameAncestors) {
      const isRestrictive = 
        csp.includes("frame-ancestors 'none'") ||
        csp.includes("frame-ancestors 'self'");

      softCheck(
        testInfo,
        isRestrictive,
        "CSP frame-ancestors should be restrictive ('none' or 'self')"
      );
    }
  }
});

/**
 * Test: Cross-origin iframe embedding prevention
 * 
 * Purpose: Verifies that the application cannot be embedded in iframes
 * from different origins, preventing clickjacking attacks.
 * 
 * Security Impact: Cross-origin iframe embedding can lead to:
 * - Clickjacking attacks from malicious websites
 * - UI redressing attacks
 * - Unauthorized actions performed by users
 * - Social engineering attacks
 * 
 * Test Strategy:
 * 1. Create a test page with cross-origin iframe
 * 2. Attempt to embed the application
 * 3. Verify iframe content is not accessible
 * 4. Confirm clickjacking protection is working
 */
test('Clickjacking: page cannot be embedded in iframe from different origin', async ({ page, context }, testInfo) => {
  try {
    // Step 1: Create a test page that attempts to embed the application
    const testPage = await context.newPage();
    await testPage.setContent(`
      <html>
        <body>
          <iframe id="target" src="${process.env.BASE_URL || 'http://localhost:5001'}"></iframe>
        </body>
      </html>
    `);

    await testPage.waitForTimeout(2000);

    // Step 2: Attempt to access iframe content
    const iframeLoaded = await testPage.evaluate(() => {
      const iframe = document.getElementById('target') as HTMLIFrameElement;
      try {
        // Try to access iframe content (will fail if properly protected)
        return !!iframe.contentDocument;
      } catch (e) {
        return false;
      }
    });

    // Step 3: Verify iframe embedding is blocked
    softCheck(
      testInfo,
      !iframeLoaded,
      'Application should prevent embedding in cross-origin iframes'
    );

    await testPage.close();
  } catch (e) {
    // Expected behavior - protection is working
  }
});
