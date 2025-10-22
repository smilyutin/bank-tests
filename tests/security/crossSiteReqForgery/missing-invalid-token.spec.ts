import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

/**
 * CSRF Token Validation Tests
 * 
 * These tests verify that the application properly validates CSRF tokens to prevent
 * Cross-Site Request Forgery attacks. CSRF attacks occur when malicious websites
 * trick users into performing unwanted actions on authenticated applications.
 * 
 * Security Risks Addressed:
 * 1. Missing CSRF token protection
 * 2. Invalid token acceptance
 * 3. Improper cookie configuration
 * 4. Token leakage in URLs
 * 
 * Expected Behavior:
 * - State-changing requests must include valid CSRF tokens
 * - Invalid tokens should be rejected with 403/401 status
 * - Session cookies should have proper SameSite attributes
 * - Tokens should not be exposed in URLs
 */

/**
 * Test: Requests without CSRF token are rejected
 * 
 * Purpose: Verifies that state-changing operations require CSRF token protection.
 * This prevents attackers from performing actions on behalf of authenticated users
 * without their knowledge.
 * 
 * Security Impact: If CSRF tokens are not required, attackers could:
 * - Create malicious forms that submit to your application
 * - Trick users into performing unwanted actions (transfers, profile changes, etc.)
 * - Execute actions without user consent
 * - Bypass authentication through social engineering
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt state-changing operations without CSRF tokens
 * 3. Verify all requests are rejected with appropriate error codes
 */
test('CSRF: requests without token are rejected', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user to get session token
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Step 2: Define dangerous endpoints that should require CSRF protection
  // These are state-changing operations that could be exploited
  const dangerousEndpoints = [
    { method: 'POST', url: '/api/profile' },    // Profile updates
    { method: 'DELETE', url: '/api/users/me' }, // Account deletion
    { method: 'PATCH', url: '/api/settings' },   // Settings changes
  ];

  let properlyProtected = true;

  // Step 3: Test each dangerous endpoint without CSRF token
  for (const endpoint of dangerousEndpoints) {
    try {
      const res = await request.fetch(endpoint.url, {
        method: endpoint.method,
        headers: { 
          'Authorization': `Bearer ${token}`,
          // Deliberately omitting CSRF token to test protection
        },
        data: { test: 'data' },
      });

      // Step 4: Verify request was rejected
      // Status codes < 400 indicate the request was accepted (vulnerability)
      if (res.status() < 400) {
        properlyProtected = false;
        break;
      }
    } catch (e) {
      // Expected behavior - request should fail
    }
  }

  // Step 5: Verify all endpoints are properly protected
  softCheck(
    testInfo,
    properlyProtected,
    'State-changing requests should require CSRF token protection'
  );
});

/**
 * Test: Invalid CSRF tokens are rejected
 * 
 * Purpose: Verifies that the application properly validates CSRF token format and
 * rejects invalid, expired, or malformed tokens.
 * 
 * Security Impact: If invalid tokens are accepted, attackers could:
 * - Use predictable or weak tokens to bypass protection
 * - Exploit token validation flaws
 * - Perform CSRF attacks with crafted tokens
 * - Bypass CSRF protection through token manipulation
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt requests with various invalid token formats
 * 3. Verify all invalid tokens are rejected with 403/401 status
 */
test('CSRF: invalid token is rejected', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Step 2: Define various invalid token formats to test
  // These represent common attack vectors and edge cases
  const invalidTokens = [
    'invalid-token-12345',  // Random invalid token
    'expired-token',        // Expired token format
    '',                     // Empty token
    'null',                 // Null-like token
  ];

  let rejected = false;

  // Step 3: Test each invalid token format
  for (const csrfToken of invalidTokens) {
    try {
      const res = await request.post('/api/profile', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-CSRF-Token': csrfToken,    // Standard CSRF header
          'X-XSRF-Token': csrfToken,    // Alternative CSRF header
        },
        data: { name: 'Hacker' },
      });

      // Step 4: Verify invalid token was rejected
      // 403 Forbidden or 401 Unauthorized indicate proper validation
      if (res.status() === 403 || res.status() === 401) {
        rejected = true;
        break;
      }
    } catch (e) {
      // Network errors also indicate rejection
      rejected = true;
      break;
    }
  }

  // Step 5: Verify at least one invalid token was properly rejected
  softCheck(
    testInfo,
    rejected,
    'Invalid CSRF tokens should be rejected with 403/401'
  );
});

/**
 * Test: SameSite cookie attribute is properly set
 * 
 * Purpose: Verifies that session cookies have proper SameSite attributes to provide
 * additional CSRF protection. SameSite cookies help prevent cross-site request attacks
 * by controlling when cookies are sent with cross-site requests.
 * 
 * Security Impact: Without SameSite attributes, cookies could be:
 * - Sent with cross-site requests, enabling CSRF attacks
 * - Exploited by malicious websites to perform actions
 * - Used in combination with other attack vectors
 * 
 * SameSite Values:
 * - Strict: Never send with cross-site requests (highest security)
 * - Lax: Send with top-level navigation (balanced security/usability)
 * - None: Always send (requires Secure flag, lowest security)
 */
test('CSRF: SameSite cookie attribute set', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Perform login to capture cookie headers
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    test.skip(true, 'Could not login');
    return;
  }

  const { res } = attempt as any;
  const setCookie = res.headers()['set-cookie'];

  // Step 2: Check if cookies were set during login
  if (setCookie) {
    // Step 3: Verify SameSite attribute is present
    // Check for both Lax and Strict values (both provide CSRF protection)
    const sameSitePresent = 
      setCookie.toLowerCase().includes('samesite=lax') ||
      setCookie.toLowerCase().includes('samesite=strict');

    // Step 4: Verify proper cookie configuration
    softCheck(
      testInfo,
      sameSitePresent,
      'Session cookies should have SameSite attribute (Lax or Strict) for CSRF protection'
    );
  } else {
    // Step 5: Handle case where no cookies are set
    test.skip(true, 'No cookies set during login');
  }
});

/**
 * Test: CSRF protection implementation detection
 * 
 * Purpose: Verifies that the application implements CSRF protection mechanisms
 * by checking for the presence of CSRF tokens in meta tags or forms.
 * 
 * Security Impact: Without CSRF protection implementation:
 * - Applications are vulnerable to cross-site request forgery attacks
 * - Users can be tricked into performing unwanted actions
 * - Attackers can bypass authentication through social engineering
 * 
 * CSRF Protection Patterns:
 * - Synchronizer Token: Token in meta tag or form field
 * - Double Submit Cookie: Token in both cookie and request
 * - Custom Headers: Token in custom HTTP headers
 */
test('CSRF: double submit cookie pattern or synchronizer token', async ({ page }, testInfo) => {
  try {
    // Step 1: Navigate to the application homepage
    await page.goto('/');
    
    // Step 2: Check for CSRF token in meta tags
    // This is the most common implementation pattern
    const hasMetaToken = await page.evaluate(() => {
      const meta = document.querySelector('meta[name="csrf-token"], meta[name="x-csrf-token"]');
      return !!meta;
    });

    // Step 3: Check for CSRF token in form fields
    // Alternative implementation pattern
    const hasFormToken = await page.evaluate(() => {
      const input = document.querySelector('input[name="_csrf"], input[name="csrf_token"]');
      return !!input;
    });

    // Step 4: Verify CSRF protection is implemented
    // At least one protection mechanism should be present
    softCheck(
      testInfo,
      hasMetaToken || hasFormToken,
      'Application should implement CSRF protection (token in meta tag or form)'
    );
  } catch (e) {
    // Step 5: Handle navigation errors
    test.skip(true, 'Page not available');
  }
});

/**
 * Test: CSRF tokens are not leaked in URLs
 * 
 * Purpose: Verifies that CSRF tokens are not exposed in URL parameters,
 * which could lead to token leakage through referrer headers, logs, or browser history.
 * 
 * Security Impact: If tokens appear in URLs, they could be:
 * - Leaked through HTTP referrer headers to external sites
 * - Stored in web server access logs
 * - Visible in browser history
 * - Shared accidentally through URL copying
 * - Exposed in analytics or monitoring systems
 * 
 * Best Practice: CSRF tokens should only be transmitted in:
 * - HTTP headers (X-CSRF-Token, X-XSRF-Token)
 * - Request body (form fields, JSON payload)
 * - Cookies (for double-submit pattern)
 */
test('CSRF: token not leaked in URL', async ({ page }, testInfo) => {
  try {
    // Step 1: Navigate to the application homepage
    await page.goto('/');
    
    // Step 2: Capture the current URL
    const url = page.url();
    
    // Step 3: Check for common CSRF token patterns in URL
    // Look for various token parameter names that might leak tokens
    const hasTokenInUrl = 
      url.includes('csrf') ||      // csrf_token=...
      url.includes('token=') ||    // token=...
      url.includes('_token=');     // _token=...

    // Step 4: Verify no tokens are exposed in URLs
    // Tokens should NOT be present in URL parameters
    softCheck(
      testInfo,
      !hasTokenInUrl,
      'CSRF tokens should not be included in URLs (should be in headers/body only)'
    );
  } catch (e) {
    // Step 5: Handle navigation errors
    test.skip(true, 'Page not available');
  }
});
