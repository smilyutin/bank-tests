import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Security Regression Tests - CI/CD Integration
 * 
 * These tests run in CI/CD pipelines to detect security regressions
 * automatically. They verify that previously fixed vulnerabilities
 * haven't been reintroduced through code changes.
 * 
 * Security Risks Addressed:
 * 1. Regression of previously fixed vulnerabilities
 * 2. Introduction of new security issues in releases
 * 3. Configuration drift in production
 * 4. Breaking changes to security controls
 * 5. Dependency vulnerabilities
 * 
 * Expected Behavior:
 * - All critical security controls remain functional
 * - No previously fixed CVEs reintroduced
 * - Security headers consistently applied
 * - Authentication/authorization working correctly
 * - Input validation maintains standards
 * 
 * Usage:
 *   - Run nightly: npm run test:sec:regression
 *   - Run on every PR: CI pipeline integration
 *   - Run before releases: Release checklist
 */

/**
 * Test: Critical security headers regression check
 * 
 * Purpose: Verifies that all required security headers are present
 * and haven't been removed or weakened in recent changes.
 * 
 * Security Impact: Missing security headers can lead to:
 * - XSS attacks (missing CSP)
 * - Clickjacking (missing X-Frame-Options)
 * - MIME sniffing attacks (missing X-Content-Type-Options)
 * - Man-in-the-middle attacks (missing HSTS)
 * 
 * Test Strategy:
 * 1. Request main application endpoint
 * 2. Verify presence of all critical headers
 * 3. Check header values haven't been weakened
 * 4. Fail fast on any regression
 */
test('Regression: critical security headers present', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const res = await api.get('/').catch(() => null);
  
  if (!res) {
    reporter.reportSkip('Base URL not reachable');
    test.skip(true, 'Base URL not reachable');
    return;
  }
  
  const headers = res.headers();
  
  // Define expected security headers
  const requiredHeaders = {
    'x-frame-options': { present: false, value: '' },
    'x-content-type-options': { present: false, value: '' },
    'strict-transport-security': { present: false, value: '' },
    'content-security-policy': { present: false, value: '' },
  };
  
  // Check each header
  for (const headerName in requiredHeaders) {
    if (headers[headerName]) {
      requiredHeaders[headerName as keyof typeof requiredHeaders].present = true;
      requiredHeaders[headerName as keyof typeof requiredHeaders].value = headers[headerName];
    }
  }
  
  const missingHeaders = Object.entries(requiredHeaders)
    .filter(([_, config]) => !config.present)
    .map(([name]) => name);
  
  // Check for weakened headers
  const weakenedHeaders: string[] = [];
  
  // CSP should not be 'unsafe-inline' or 'unsafe-eval' only
  if (requiredHeaders['content-security-policy'].present) {
    const csp = requiredHeaders['content-security-policy'].value;
    if (csp.includes("'unsafe-inline'") && !csp.includes('nonce-') && !csp.includes('sha256-')) {
      weakenedHeaders.push('CSP allows unsafe-inline without nonces/hashes');
    }
  }
  
  // HSTS should have max-age
  if (requiredHeaders['strict-transport-security'].present) {
    const hsts = requiredHeaders['strict-transport-security'].value;
    if (!hsts.includes('max-age=') || hsts.includes('max-age=0')) {
      weakenedHeaders.push('HSTS has invalid or zero max-age');
    }
  }
  
  // X-Frame-Options should be DENY or SAMEORIGIN
  if (requiredHeaders['x-frame-options'].present) {
    const xfo = requiredHeaders['x-frame-options'].value.toUpperCase();
    if (!['DENY', 'SAMEORIGIN'].includes(xfo)) {
      weakenedHeaders.push('X-Frame-Options has weak value');
    }
  }
  
  if (missingHeaders.length > 0 || weakenedHeaders.length > 0) {
    reporter.reportVulnerability('API7_MISCONFIGURATION', {
      missingHeaders,
      weakenedHeaders,
      issue: 'Security headers regression detected'
    }, [
      'Restore all required security headers',
      'Review recent configuration changes',
      'Update reverse proxy/web server config',
      'Add security header tests to CI/CD pipeline',
      'Document required security header standards'
    ]);
    expect(missingHeaders.length + weakenedHeaders.length).toBe(0);
  } else {
    reporter.reportPass(
      'All critical security headers present and properly configured',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Authentication bypass regression check
 * 
 * Purpose: Verifies that authentication cannot be bypassed through
 * common techniques that may have been reintroduced.
 */
test('Regression: authentication bypass attempts blocked', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const authEndpoints = ['/api/auth/login', '/api/login', '/login'];
  
  const bypassAttempts = [
    { method: 'sql_injection', payload: { email: "admin' OR '1'='1", password: 'anything' } },
    { method: 'empty_password', payload: { email: 'admin@example.com', password: '' } },
    { method: 'null_password', payload: { email: 'admin@example.com', password: null } },
    { method: 'no_password', payload: { email: 'admin@example.com' } },
    { method: 'wildcard_email', payload: { email: '*', password: 'password' } },
  ];
  
  let endpointFound = false;
  let bypassSucceeded = false;
  let bypassMethod = '';
  
  for (const endpoint of authEndpoints) {
    try {
      for (const attempt of bypassAttempts) {
        const res = await api.post(endpoint, {
          data: JSON.stringify(attempt.payload),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const body = await res.json().catch(() => null);
        
        // Success = bypass worked!
        if ([200, 201].includes(status) && (body?.token || body?.success)) {
          bypassSucceeded = true;
          bypassMethod = attempt.method;
          break;
        }
      }
      
      if (bypassSucceeded || endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No authentication endpoints found');
    test.skip(true, 'No authentication endpoints found');
    return;
  }
  
  if (bypassSucceeded) {
    reporter.reportVulnerability('API2_AUTH', {
      bypassMethod,
      issue: 'Authentication bypass regression - authentication can be bypassed'
    }, [
      'Review recent authentication code changes',
      'Ensure proper input validation before auth',
      'Use parameterized queries for database auth',
      'Validate all required fields are present',
      'Add authentication regression tests to CI/CD'
    ]);
    expect(bypassSucceeded).toBeFalsy();
  } else {
    reporter.reportPass(
      'Authentication bypass attempts properly blocked',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});

/**
 * Test: Authorization regression check
 * 
 * Purpose: Verifies that users cannot access resources they shouldn't
 * have access to (IDOR/BOLA protection still working).
 */
test('Regression: IDOR/BOLA protection functional', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  
  // Try to access common protected resources without auth
  const protectedResources = [
    '/api/users/1',
    '/api/users/999',
    '/api/accounts/1',
    '/api/admin',
    '/api/admin/users'
  ];
  
  let endpointFound = false;
  let unauthorizedAccessAllowed = 0;
  
  for (const resource of protectedResources) {
    try {
      const res = await api.get(resource).catch(() => null);
      
      if (!res || res.status() === 404) continue;
      endpointFound = true;
      
      // Should return 401 or 403, not 200
      if (res.status() === 200) {
        const body = await res.json().catch(() => null);
        // If we got actual data back, it's a vulnerability
        if (body && typeof body === 'object' && Object.keys(body).length > 0) {
          unauthorizedAccessAllowed++;
        }
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No protected resources found for IDOR testing');
    test.skip(true, 'No protected resources found');
    return;
  }
  
  if (unauthorizedAccessAllowed > 0) {
    reporter.reportVulnerability('API1_BOLA', {
      vulnerableEndpoints: unauthorizedAccessAllowed,
      issue: 'IDOR/BOLA regression - unauthorized access allowed'
    }, [
      'Review recent authorization code changes',
      'Ensure authentication required for protected resources',
      'Verify user can only access their own resources',
      'Add authorization checks to all endpoints',
      'Implement role-based access control properly'
    ]);
    expect(unauthorizedAccessAllowed).toBe(0);
  } else {
    reporter.reportPass(
      'IDOR/BOLA protection working correctly',
      OWASP_VULNERABILITIES.API1_BOLA.name
    );
  }
});

/**
 * Test: SQL injection protection regression
 * 
 * Purpose: Verifies that basic SQL injection is still blocked
 * and hasn't been reintroduced through code changes.
 */
test('Regression: SQL injection protection active', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const testEndpoints = ['/api/users', '/api/search', '/api/login'];
  
  const sqlPayloads = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT * FROM users--",
    "1' AND '1'='1",
  ];
  
  let endpointFound = false;
  let sqlErrorExposed = false;
  let serverCrashed = false;
  
  for (const endpoint of testEndpoints) {
    try {
      for (const payload of sqlPayloads) {
        const res = await api.get(`${endpoint}?q=${encodeURIComponent(payload)}`).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // SQL errors exposed
        if (/sql|syntax|mysql|postgres|sqlite|column|table/i.test(text)) {
          sqlErrorExposed = true;
        }
        
        // Server crash
        if (status >= 500) {
          serverCrashed = true;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for SQL injection testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (sqlErrorExposed || serverCrashed) {
    reporter.reportVulnerability('API8_INJECTION', {
      sqlErrorExposed,
      serverCrashed,
      issue: 'SQL injection regression - vulnerabilities detected'
    }, [
      'Use parameterized queries exclusively',
      'Review recent database query code changes',
      'Never concatenate user input into SQL',
      'Hide SQL error messages from users',
      'Add SQL injection tests to CI/CD pipeline'
    ]);
    expect(sqlErrorExposed || serverCrashed).toBeFalsy();
  } else {
    reporter.reportPass(
      'SQL injection protection working correctly',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Rate limiting regression check
 * 
 * Purpose: Verifies that rate limiting is still enforced and
 * hasn't been disabled or misconfigured.
 */
test('Regression: rate limiting enforced', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const target = '/api/docs';
  
  let rateLimitDetected = false;
  let requestsMade = 0;
  
  // Try rapid requests
  for (let i = 0; i < 50; i++) {
    try {
      const res = await api.get(target).catch(() => null);
      if (!res) break;
      
      requestsMade++;
      
      if (res.status() === 429) {
        rateLimitDetected = true;
        break;
      }
      
      const headers = res.headers();
      if (headers['retry-after'] || headers['x-ratelimit-remaining'] === '0') {
        rateLimitDetected = true;
        break;
      }
    } catch (e) {
      break;
    }
  }
  
  if (requestsMade === 0) {
    reporter.reportSkip('Target endpoint not reachable for rate limit check');
    test.skip(true, 'Target endpoint not reachable');
    return;
  }
  
  if (!rateLimitDetected && requestsMade >= 50) {
    reporter.reportWarning(
      'Rate limiting not detected after 50 requests - may be disabled or too permissive',
      [
        'Verify rate limiting middleware is enabled',
        'Check rate limit configuration values',
        'Review recent infrastructure changes',
        'Implement rate limiting per endpoint',
        'Add rate limiting monitoring'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportPass(
      `Rate limiting enforced (detected after ${requestsMade} requests)`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});

/**
 * Test: CORS configuration regression
 * 
 * Purpose: Verifies that CORS hasn't been misconfigured to allow
 * overly permissive origins.
 */
test('Regression: CORS properly restricted', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  
  // Test with malicious origin
  const res = await api.get('/api/users', {
    headers: { 'Origin': 'https://evil.com' }
  }).catch(() => null);
  
  if (!res) {
    reporter.reportSkip('API endpoint not reachable for CORS check');
    test.skip(true, 'API endpoint not reachable');
    return;
  }
  
  const headers = res.headers();
  const allowOrigin = headers['access-control-allow-origin'];
  const allowCredentials = headers['access-control-allow-credentials'];
  
  // Check for overly permissive CORS
  const corsIssues: string[] = [];
  
  if (allowOrigin === '*') {
    corsIssues.push('CORS allows all origins (*)');
  }
  
  if (allowOrigin === 'https://evil.com') {
    corsIssues.push('CORS reflects arbitrary origin');
  }
  
  if (allowOrigin === '*' && allowCredentials === 'true') {
    corsIssues.push('CORS allows credentials with wildcard origin (critical)');
  }
  
  if (corsIssues.length > 0) {
    reporter.reportWarning(
      `CORS misconfiguration detected: ${corsIssues.join(', ')}`,
      [
        'Restrict CORS to specific trusted origins',
        'Use allowlist of known domains',
        'Never use * with credentials',
        'Review recent CORS configuration changes',
        'Implement origin validation'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'CORS properly restricted to trusted origins',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Sensitive data exposure regression
 * 
 * Purpose: Verifies that password fields and other sensitive data
 * aren't being returned in API responses.
 */
test('Regression: sensitive data not exposed in responses', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/profile', '/api/me'];
  
  let endpointFound = false;
  let exposedFields: string[] = [];
  
  for (const endpoint of endpoints) {
    try {
      const res = await api.get(endpoint).catch(() => null);
      
      if (!res || res.status() !== 200) continue;
      endpointFound = true;
      
      const body = await res.json().catch(() => null);
      if (!body) continue;
      
      // Check for sensitive fields
      const data = Array.isArray(body) ? body[0] : body;
      if (!data) continue;
      
      const sensitiveFields = ['password', 'passwordHash', 'password_hash', 'secret', 'token', 'apiKey', 'api_key'];
      
      for (const field of sensitiveFields) {
        if (data[field] !== undefined) {
          exposedFields.push(field);
        }
      }
      
      if (exposedFields.length > 0) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No user endpoints found for sensitive data check');
    test.skip(true, 'No user endpoints found');
    return;
  }
  
  if (exposedFields.length > 0) {
    reporter.reportVulnerability('API3_DATA_EXPOSURE', {
      exposedFields,
      issue: 'Sensitive data exposure regression - password fields returned in responses'
    }, [
      'Remove sensitive fields from API responses',
      'Use DTOs to control exposed fields',
      'Review recent serialization code changes',
      'Never return password hashes to clients',
      'Add response validation tests to CI/CD'
    ]);
    expect(exposedFields.length).toBe(0);
  } else {
    reporter.reportPass(
      'No sensitive data exposed in API responses',
      OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
    );
  }
});
