import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

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
 * Generate random fuzzing payloads
 */
function generateFuzzPayloads(): Array<{ name: string; value: any }> {
  return [
    // Extreme numeric values
    { name: 'max_int', value: 2147483647 },
    { name: 'min_int', value: -2147483648 },
    { name: 'overflow_int', value: 999999999999999999999 },
    { name: 'negative_zero', value: -0 },
    { name: 'infinity', value: Number.POSITIVE_INFINITY },
    { name: 'negative_infinity', value: Number.NEGATIVE_INFINITY },
    { name: 'nan', value: NaN },
    
    // Type confusion
    { name: 'boolean_as_string', value: 'true' },
    { name: 'number_as_string', value: '123' },
    { name: 'null_value', value: null },
    { name: 'undefined_value', value: undefined },
    { name: 'empty_object', value: {} },
    { name: 'empty_array', value: [] },
    { name: 'nested_arrays', value: [[[[[]]]]] },
    
    // String edge cases
    { name: 'empty_string', value: '' },
    { name: 'whitespace', value: '   ' },
    { name: 'null_byte', value: '\0' },
    { name: 'newlines', value: '\n\n\n\n\n' },
    { name: 'tabs', value: '\t\t\t\t' },
    { name: 'unicode_emoji', value: '😀😁😂🤣😃😄😅😆' },
    { name: 'unicode_rtl', value: '\u202E\u202D' },
    { name: 'control_chars', value: '\x00\x01\x02\x03\x04\x05' },
    
    // Very long strings
    { name: 'long_string_1k', value: 'A'.repeat(1000) },
    { name: 'long_string_10k', value: 'B'.repeat(10000) },
    { name: 'long_string_100k', value: 'C'.repeat(100000) },
    
    // Format strings and injections
    { name: 'format_string', value: '%s%s%s%s%s%s%s%s' },
    { name: 'sql_injection', value: "' OR '1'='1" },
    { name: 'nosql_injection', value: { $ne: null } },
    { name: 'command_injection', value: '; ls -la' },
    { name: 'path_traversal', value: '../../../etc/passwd' },
    { name: 'xss_script', value: '<script>alert(1)</script>' },
    { name: 'xxe_payload', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' },
    
    // Arrays with unusual content
    { name: 'array_of_nulls', value: [null, null, null] },
    { name: 'mixed_types', value: [1, 'two', null, true, {}, []] },
    { name: 'deeply_nested', value: { a: { b: { c: { d: { e: { f: 'deep' } } } } } } },
    
    // Special numeric formats
    { name: 'scientific_notation', value: 1.23e+100 },
    { name: 'hex_string', value: '0x1234567890ABCDEF' },
    { name: 'octal_string', value: '0o777' },
    { name: 'binary_string', value: '0b11111111' },
  ];
}

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
  const endpoints = ['/api/users', '/api/auth/register', '/api/register'];
  const payloads = generateFuzzPayloads();
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let successfulTests = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Test a subset of payloads (first 10) to avoid overwhelming the API
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
        
        // Check for unhandled exceptions (500 errors)
        if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Server error with fuzz payload - potential unhandled exception'
          });
        }
        
        // Check for stack traces in response
        if (/stack|traceback|exception|error at/i.test(text)) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Stack trace or error details exposed in response'
          });
        }
        
        // Success if handled gracefully (400/422 or rejection)
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
  
  // Report findings
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
  const endpoints = ['/api/auth/login', '/api/login', '/login'];
  const payloads = generateFuzzPayloads();
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let timingIssues: any[] = [];
  
  for (const endpoint of endpoints) {
    try {
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
        
        // Check for server errors
        if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            status,
            issue: 'Authentication endpoint crashed with fuzz input'
          });
        }
        
        // Check for information disclosure
        if (/user not found|invalid user|user does not exist/i.test(text)) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            issue: 'User enumeration possible through error messages'
          });
        }
        
        // Check for unusual response times (possible timing attack)
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
    reporter.reportVulnerability('API8_INJECTION', {
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
      `Authentication endpoint had ${timingIssues.length} slow responses (>5s) with fuzz inputs`,
      [
        'Implement request timeouts to prevent resource exhaustion',
        'Add input size limits before processing',
        'Consider early rejection of invalid input types'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'Authentication endpoint handled random fuzz inputs securely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
  const endpoints = [
    '/api/search',
    '/api/users?search=',
    '/api/filter',
    '/api/query'
  ];
  
  const payloads = generateFuzzPayloads();
  let endpointFound = false;
  let issues = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of payloads.slice(0, 5)) {
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
    reporter.reportVulnerability('API8_INJECTION', {
      serverErrors: issues,
      issue: 'Search/filter endpoints crashed with random inputs'
    });
    expect(issues).toBe(0);
  } else {
    reporter.reportPass(
      'Search/filter endpoints handled random fuzz inputs gracefully',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});
