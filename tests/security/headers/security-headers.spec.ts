import { test, request as playwrightRequest } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Security Headers Tests
 * 
 * These tests verify that the application implements proper security headers
 * to protect against various web vulnerabilities and information disclosure.
 * 
 * Security Risks Addressed:
 * 1. Missing security headers (CSP, X-Frame-Options, etc.)
 * 2. Information disclosure through server headers
 * 3. Deprecated security headers (X-XSS-Protection)
 * 4. Improper caching of sensitive content
 * 
 * Expected Behavior:
 * - Essential security headers should be present
 * - No sensitive server information should be exposed
 * - Deprecated headers should be removed or properly configured
 * - Sensitive content should not be cached
 */

/**
 * Test: Comprehensive security headers check
 * 
 * Purpose: Verifies that all essential security headers are present
 * to protect against common web vulnerabilities.
 * 
 * Security Impact: Missing security headers can lead to:
 * - Clickjacking attacks (missing X-Frame-Options)
 * - XSS attacks (missing CSP)
 * - MIME type sniffing attacks (missing X-Content-Type-Options)
 * - Man-in-the-middle attacks (missing HSTS)
 * 
 * Test Strategy:
 * 1. Navigate to application homepage
 * 2. Check for presence of essential security headers
 * 3. Verify all required headers are configured
 */
test('Security headers: comprehensive check', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'Comprehensive security-header check could not run because homepage response was not received.',
      [
        'Ensure application root endpoint is reachable in test environment',
        'Stabilize app startup/network routing before running security scans',
        'Fail deployment when baseline health checks for root endpoint fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  
  // Step 1: Define essential security headers to check
  const securityHeaders = {
    'X-Content-Type-Options': !!headers['x-content-type-options'],
    'X-Frame-Options': !!headers['x-frame-options'],
    'Content-Security-Policy': !!headers['content-security-policy'],
    'Strict-Transport-Security': !!headers['strict-transport-security'] || !page.url().startsWith('https://'),
    'Referrer-Policy': !!headers['referrer-policy'],
    'Permissions-Policy': !!headers['permissions-policy'] || !!headers['feature-policy'],
  };

  // Step 2: Identify missing security headers
  const missing = Object.entries(securityHeaders)
    .filter(([_, present]) => !present)
    .map(([header]) => header);

  // Step 3: Verify all essential headers are present
  softCheck(
    testInfo,
    missing.length === 0,
    `Missing security headers: ${missing.join(', ') || 'none'}`
  );
});

/**
 * Test: No information disclosure through headers
 * 
 * Purpose: Verifies that server headers do not expose sensitive information
 * that could be used for reconnaissance or targeted attacks.
 * 
 * Security Impact: Information disclosure headers can lead to:
 * - Server fingerprinting and targeted attacks
 * - Technology stack identification
 * - Version-specific vulnerability exploitation
 * - Reconnaissance for further attacks
 * 
 * Test Strategy:
 * 1. Check response headers for sensitive information
 * 2. Identify headers that reveal server details
 * 3. Verify no sensitive information is exposed
 */
test('Security headers: no information disclosure', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'Information-disclosure header check could not run because homepage response was not received.',
      [
        'Ensure application root endpoint is reachable in test environment',
        'Stabilize app startup/network routing before running security scans',
        'Fail deployment when baseline health checks for root endpoint fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  
  // Step 1: Define headers that may disclose sensitive information
  const sensitiveHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
  const found: string[] = [];

  // Step 2: Check for presence of sensitive headers
  for (const header of sensitiveHeaders) {
    if (headers[header]) {
      found.push(`${header}: ${headers[header]}`);
    }
  }

  // Step 3: Verify no sensitive information is exposed
  softCheck(
    testInfo,
    found.length === 0,
    `Information disclosure headers found: ${found.join(', ') || 'none'}`
  );
});

/**
 * Test: X-XSS-Protection header deprecation
 * 
 * Purpose: Verifies that the deprecated X-XSS-Protection header is either
 * removed or properly configured to prevent security vulnerabilities.
 * 
 * Security Impact: Deprecated X-XSS-Protection header can lead to:
 * - XSS vulnerabilities due to flawed protection
 * - Security bypasses through header manipulation
 * - False sense of security
 * - Compatibility issues with modern browsers
 * 
 * Test Strategy:
 * 1. Check for presence of X-XSS-Protection header
 * 2. Verify it's not set to deprecated values
 * 3. Ensure modern CSP is used instead
 */
test('Security headers: X-XSS-Protection removed or set to 0', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'X-XSS-Protection deprecation check could not run because homepage response was not received.',
      [
        'Ensure application root endpoint is reachable in test environment',
        'Stabilize app startup/network routing before running security scans',
        'Fail deployment when baseline health checks for root endpoint fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const xssProtection = headers['x-xss-protection'];

  // Step 1: Check if deprecated X-XSS-Protection header is present
  if (xssProtection) {
    // Step 2: Verify it's not set to deprecated values
    const isDeprecatedValue = xssProtection === '1' || xssProtection.includes('mode=block');
    
    // Step 3: Ensure deprecated values are not used
    softCheck(
      testInfo,
      !isDeprecatedValue,
      'X-XSS-Protection header should be removed or set to 0 (deprecated, can cause vulnerabilities)'
    );
  }
});

/**
 * Test: Cache-Control for sensitive pages
 * 
 * Purpose: Verifies that sensitive pages have proper cache control headers
 * to prevent sensitive information from being cached by browsers or proxies.
 * 
 * Security Impact: Improper caching can lead to:
 * - Sensitive data exposure through browser cache
 * - Information leakage through proxy caches
 * - Session data persistence in cache
 * - Privacy violations and data exposure
 * 
 * Test Strategy:
 * 1. Navigate to sensitive pages (profile, account, settings)
 * 2. Check Cache-Control headers
 * 3. Verify no-store or private directives are present
 */
test('Security headers: Cache-Control for sensitive pages', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  // Step 1: Navigate to potentially sensitive pages
  await page.goto('/');
  
  const response = await page.goto('/profile').catch(() => null) || 
                   await page.goto('/account').catch(() => null) ||
                   await page.goto('/settings').catch(() => null);

  if (!response) {
    reporter.reportWarning(
      'Sensitive-page cache-control probe could not run because no candidate sensitive routes were reachable (/profile, /account, /settings).',
      [
        'Expose/document at least one authenticated sensitive route for cache-control validation',
        'Ensure test environment routes mirror production protected pages',
        'Add OpenAPI/UI route metadata so security probes can discover sensitive endpoints',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const cacheControl = headers['cache-control'];

  // Step 2: Check Cache-Control header for sensitive content protection
  if (cacheControl) {
    const hasNoStore = cacheControl.includes('no-store');
    const hasPrivate = cacheControl.includes('private');
    
    // Step 3: Verify sensitive pages prevent caching
    softCheck(
      testInfo,
      hasNoStore || hasPrivate,
      'Sensitive pages should have Cache-Control: no-store or private'
    );
  }
});

/**
 * Test: No cache for authenticated resources
 * 
 * Purpose: Verifies that authenticated API resources have proper cache control
 * to prevent sensitive user data from being cached.
 * 
 * Security Impact: Cached authenticated resources can lead to:
 * - User data exposure through cache
 * - Session information leakage
 * - Cross-user data contamination
 * - Privacy violations and data breaches
 * 
 * Test Strategy:
 * 1. Access authenticated API endpoint
 * 2. Check Cache-Control and Pragma headers
 * 3. Verify caching is disabled for user data
 */
test('Security headers: no cache for authenticated resources', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  if (!baseURL) {
    reporter.reportWarning(
      'Authenticated-resource cache-control check could not run because baseURL is not provided.',
      [
        'Set BASE_URL in .env or CI configuration before security tests run',
        'Ensure Playwright baseURL points to reachable target application',
        'Fail pipeline early when baseURL is missing',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const authCandidates = ['/api/users/me', '/api/me', '/api/user/me', '/me'];

  let response: Awaited<ReturnType<typeof api.get>> | null = null;
  let endpointUsed: string | null = null;

  for (const path of authCandidates) {
    const res = await api.get(path).catch(() => null);
    if (!res) continue;

    // Endpoint exists if not 404; 401/403 still indicates auth-related resource.
    if (res.status() !== 404) {
      response = res;
      endpointUsed = path;
      break;
    }
  }

  if (!response) {
    reporter.reportWarning(
      'No authenticated-resource endpoint responded for cache-control probe (/api/users/me, /api/me, /api/user/me, /me).',
      [
        'Expose/document a stable authenticated profile endpoint for security testing',
        'Ensure non-production environments include representative authenticated APIs',
        'Add endpoint discovery metadata (OpenAPI) for authenticated resource checks',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const cacheControl = (headers['cache-control'] || '').toLowerCase();
  const pragma = (headers['pragma'] || '').toLowerCase();
  const status = response.status();

  // Accept strict anti-cache directives for sensitive/authenticated endpoints.
  const properlyConfigured =
    cacheControl.includes('no-store') ||
    (cacheControl.includes('no-cache') && cacheControl.includes('private')) ||
    pragma === 'no-cache';

  if (!properlyConfigured) {
    reporter.reportWarning(
      `Authenticated API resource ${endpointUsed} (status ${status}) does not include safe anti-cache directives. Observed Cache-Control="${cacheControl || 'missing'}", Pragma="${pragma || 'missing'}".`,
      [
        'Add Cache-Control: no-store for authenticated and sensitive responses.',
        'At minimum, use Cache-Control: private, no-cache, must-revalidate for user-specific resources.',
        'Add Pragma: no-cache for legacy proxy compatibility.',
        'Review all /me, /profile, /account endpoints to ensure consistent no-cache behavior.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportPass(
    `Authenticated API resource ${endpointUsed} correctly disables caching (Cache-Control="${cacheControl || 'n/a'}", Pragma="${pragma || 'n/a'}").`,
    OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
  );
});

/**
 * Test: Security Headers and Server Fingerprinting (OWASP API7:2023)
 * 
 * Purpose: Verifies that the API implements proper security headers and
 * checks for potential server fingerprinting vulnerabilities.
 * 
 * Security Impact: Security misconfiguration can lead to:
 * - Clickjacking attacks through missing frame options
 * - XSS attacks through missing CSP headers
 * - Information disclosure through server headers
 * - Reduced security posture and attack surface
 * 
 * Test Strategy:
 * 1. Check for presence of security headers (CSP, X-Frame-Options, etc.)
 * 2. Identify server fingerprinting through headers
 * 3. Verify security headers are properly configured
 * 4. Document findings for security assessment
 */
test('Security Headers (OWASP API7): comprehensive security and fingerprinting check', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'OWASP API7 comprehensive header/fingerprinting check could not run because baseURL is not provided.',
      [
        'Set BASE_URL in .env or CI configuration before security tests run',
        'Ensure Playwright baseURL points to reachable target application',
        'Fail pipeline early when baseURL is missing',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const res = await api.get('/').catch(() => null);
  
  if (!res) {
    reporter.reportWarning(
      'OWASP API7 comprehensive header/fingerprinting check failed because base URL was not reachable.',
      [
        'Ensure app is running and accessible from test environment network',
        'Stabilize startup/health checks before launching security suite',
        'Fail CI earlier on base URL reachability failure to avoid partial security coverage',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }
  
  const headers = res.headers();
  
  // Step 1: Check for server fingerprinting through headers
  const server = headers['server'] || headers['x-powered-by'] || '';
  
  // Step 2: Attach server header for inspection (informational)
  if (server) {
    try {
      testInfo.attach('server-header', {
        body: server.toString(),
        contentType: 'text/plain'
      });
    } catch {}
  }
  
  // Step 3: Check for security headers presence
  const haveCT = !!(headers['content-security-policy']);
  const haveXfo = !!(headers['x-frame-options']);
  const haveXss = !!(headers['x-xss-protection'] || headers['x-content-type-options']);
  const haveHSTS = !!(headers['strict-transport-security']);
  
  const missingHeaders: string[] = [];
  if (!haveCT) missingHeaders.push('Content-Security-Policy');
  if (!haveXfo) missingHeaders.push('X-Frame-Options');
  if (!haveXss) missingHeaders.push('X-Content-Type-Options');
  if (!haveHSTS) missingHeaders.push('Strict-Transport-Security');
  
  // Step 4: Report security posture
  if (missingHeaders.length > 0) {
    reporter.reportWarning(
      `Missing ${missingHeaders.length} security headers: ${missingHeaders.join(', ')}. ${server ? `Server fingerprinting detected: ${server}` : ''}`,
      [
        'Add Content-Security-Policy header to prevent XSS attacks',
        'Add X-Frame-Options header to prevent clickjacking',
        'Add X-Content-Type-Options: nosniff to prevent MIME sniffing',
        'Add Strict-Transport-Security header to enforce HTTPS',
        'Remove or obscure Server and X-Powered-By headers to prevent fingerprinting'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'All recommended security headers are present',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});
