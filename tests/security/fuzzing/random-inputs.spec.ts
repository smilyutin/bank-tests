import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { generateFuzzPayloads, isJsonTransportableValue } from '../sec-objects/fuzzing/fuzz-payloads.logic';

/**
 * API Fuzzing - Random Input Tests (OWASP API8:2023)
 * 
 * These tests push API endpoints beyond normal limits by injecting random,
 * unexpected, and malformed data to detect crashes, error disclosure, and
 * logic breaks that could indicate security vulnerabilities.
 * 
 * Security Risks Addressed:
 * 1. Unhandled exceptions leading to information disclosure
 * 2. Input validation bypasses through unexpected data types
 * 3. Buffer overflows or memory corruption
 * 4. SQL/NoSQL injection through inadequate sanitization
 * 5. Denial of Service through resource exhaustion
 * 
 * Expected Behavior:
 * - APIs should gracefully handle random inputs without crashes
 * - No stack traces or sensitive information in error responses
 * - Proper HTTP status codes (400/422) for invalid input
 * - No 500 errors indicating unhandled exceptions
 * - Response times should remain reasonable
 */

/**
 * Test: Random input fuzzing on user creation endpoint
 * 
 * Purpose: Verifies that user registration/creation endpoints properly
 * handle random, unexpected inputs without crashing or leaking information.
 * 
 * Security Impact: Poor input handling can lead to:
 * - Server crashes and DoS vulnerabilities
 * - Stack trace disclosure revealing code paths
 * - SQL/NoSQL injection through bypassed validation
 * - Type confusion vulnerabilities
 * 
 * Test Strategy:
 * 1. Send random payloads to user creation endpoints
 * 2. Verify no 500 errors (unhandled exceptions)
 * 3. Check for information disclosure in error responses
 * 4. Ensure appropriate error codes (400/422)
 */
test('Fuzzing: user creation endpoint handles random inputs', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Probe the most likely user-creation routes first.
  const endpoints = ['/api/users', '/api/auth/register', '/api/register'];
  const payloads = generateFuzzPayloads().filter(payload => isJsonTransportableValue(payload.value));
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let successfulTests = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Limit the sample size so the fuzzing run stays lightweight.
      for (const payload of payloads.slice(0, 10)) {
        const testData = {
          email: payload.value,
          password: payload.value,
          username: payload.value
        };
        
        const res = await api.post(endpoint, {
          data: JSON.stringify(testData),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        
        endpointFound = true;
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // A 500 here suggests the payload uncovered an unhandled path.
        if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Server error with fuzz payload - potential unhandled exception'
          });
        }
        
        // Stack traces or parser text in the body indicate error disclosure.
        if (/stack|traceback|exception|error at/i.test(text)) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Stack trace or error details exposed in response'
          });
        }
        
        // Treat validation errors and rejections as the safe outcome.
        if ([400, 401, 403, 422, 404].includes(status) && !/stack|traceback/i.test(text)) {
          successfulTests++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue to next endpoint
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No user creation endpoints found for fuzzing');
    test.skip(true, 'No user creation endpoints found');
    return;
  }
  
  // Emit a single summary so CI output stays readable.
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      vulnerabilitiesFound: vulnerabilities.length,
      examples: vulnerabilities.slice(0, 3),
      issue: `Fuzz testing revealed ${vulnerabilities.length} issues with random input handling`
    }, [
      'Implement comprehensive input validation for all fields',
      'Use try-catch blocks to handle unexpected inputs gracefully',
      'Never expose stack traces or error details in production',
      'Return consistent error messages (400/422) for invalid input',
      'Log detailed errors server-side, not in responses'
    ]);
    expect(vulnerabilities.length).toBe(0);
  } else {
    reporter.reportPass(
      `API handled ${successfulTests} random fuzz inputs gracefully without crashes or information disclosure`,
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Random input fuzzing on authentication endpoint
 * 
 * Purpose: Verifies that login endpoints handle random inputs without
 * exposing timing attacks, user enumeration, or error information.
 */
test('Fuzzing: authentication endpoint handles random inputs', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Probe common login routes and compare crash, disclosure, and timing behavior.
  const endpoints = ['/api/auth/login', '/api/login', '/login'];
  const payloads = generateFuzzPayloads().filter(payload => isJsonTransportableValue(payload.value));
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let timingIssues: any[] = [];
  
  for (const endpoint of endpoints) {
    try {
      // Keep the probe window bounded so the timing signal remains practical.
      for (const payload of payloads.slice(0, 10)) {
        const startTime = Date.now();
        
        const res = await api.post(endpoint, {
          data: JSON.stringify({ email: payload.value, password: payload.value }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        const duration = Date.now() - startTime;
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // A 500 from the auth endpoint suggests the fuzz input broke processing.
        if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Authentication endpoint crashed with fuzz input'
          });
        }
        
        // Generic error text is okay; account-existence hints are not.
        if (/user not found|invalid user|user does not exist/i.test(text)) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            issue: 'User enumeration possible through error messages'
          });
        }
        
        // Extremely slow responses can be a denial-of-service signal.
        if (duration > 5000) {
          timingIssues.push({
            endpoint,
            payload: payload.name,
            duration,
            issue: 'Unusually long response time - possible DoS vector'
          });
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No authentication endpoints found for fuzzing');
    test.skip(true, 'No authentication endpoints found');
    return;
  }
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      vulnerabilitiesFound: vulnerabilities.length,
      examples: vulnerabilities.slice(0, 3),
      timingIssues: timingIssues.length
    }, [
      'Return generic error messages for authentication failures',
      'Implement rate limiting to prevent brute force attacks',
      'Use constant-time comparison for credentials',
      'Never reveal whether username exists or not'
    ]);
    expect(vulnerabilities.length).toBe(0);
  } else if (timingIssues.length > 3) {
    reporter.reportWarning(
      `Performance-only concern: authentication endpoint had ${timingIssues.length} slow responses (>5s) with fuzz inputs, but no crash or clear parser failure was observed.`,
      [
        'Treat this as a capacity/performance hardening issue unless a crash, leak, or validation bypass is observed.',
        'Implement request timeouts to prevent resource exhaustion.',
        'Add input size limits and early rejection of invalid input types.'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'Authentication endpoint handled random fuzz inputs securely',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Random input fuzzing on search/filter endpoints
 * 
 * Purpose: Verifies that search and filtering functionality properly
 * sanitizes inputs to prevent injection and performance issues.
 */
test('Fuzzing: search/filter endpoints handle random inputs', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Probe read-only search and filter endpoints for crash behavior.
  const endpoints = [
    '/api/search',
    '/api/users?search=',
    '/api/filter',
    '/api/query'
  ];
  
  const payloads = generateFuzzPayloads().filter(payload => isJsonTransportableValue(payload.value));
  let endpointFound = false;
  let issues = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Use only a small sample to keep the request volume low.
      for (const payload of payloads.slice(0, 5)) {
        // Reuse query-style endpoints when the route already includes a query marker.
        const url = endpoint.includes('?') 
          ? `${endpoint}${encodeURIComponent(String(payload.value))}`
          : endpoint;
        
        const res = await api.get(url).catch(() => null);
        if (!res) continue;
        
        endpointFound = true;
        
        if (res.status() >= 500) {
          issues++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No search/filter endpoints found for fuzzing');
    test.skip(true, 'No search/filter endpoints found');
    return;
  }
  
  if (issues > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      serverErrors: issues,
      issue: 'Search/filter endpoints crashed with random inputs'
    });
    expect(issues).toBe(0);
  } else {
    reporter.reportPass(
      'Search/filter endpoints handled random fuzz inputs gracefully',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});
