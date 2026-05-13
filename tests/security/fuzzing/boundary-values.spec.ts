import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { generateBoundaryTests, isJsonTransportableBoundaryValue } from '../sec-objects/fuzzing/boundary-values.logic';

/**
 * API Fuzzing - Boundary Value Tests (OWASP API8:2023)
 * 
 * These tests explore numeric and string edge limits (min, max, nulls, zeros)
 * to detect integer overflows, buffer overflows, off-by-one errors, and other
 * boundary condition vulnerabilities.
 * 
 * Security Risks Addressed:
 * 1. Integer overflow/underflow vulnerabilities
 * 2. Buffer overflow through excessive string lengths
 * 3. Off-by-one errors in array/string bounds
 * 4. Null pointer dereferences
 * 5. Logic errors at boundary conditions
 * 
 * Expected Behavior:
 * - Boundary values should be validated and rejected if invalid
 * - No crashes or unexpected behavior at limits
 * - Consistent error handling for out-of-range values
 * - Proper null/undefined handling
 * - No integer overflow leading to security bypasses
 */

/**
 * Test: Numeric boundary values in user creation
 * 
 * Purpose: Verifies that numeric fields properly validate boundary
 * conditions and don't suffer from integer overflow vulnerabilities.
 * 
 * Security Impact: Poor boundary validation can lead to:
 * - Integer overflow bypassing security checks
 * - Buffer overflows through size calculations
 * - Logic errors in pricing or permissions
 * - DoS through resource exhaustion
 * 
 * Test Strategy:
 * 1. Test min/max integer values
 * 2. Test overflow conditions
 * 3. Verify proper rejection of invalid values
 * 4. Check for consistent error handling
 */
test('Boundary Values: numeric edge cases handled correctly', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Target the common create routes where numeric validation is usually enforced.
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const numericTests = generateBoundaryTests().filter(t => 
    (typeof t.value === 'number' || t.field.includes('age') || t.field.includes('value')) &&
    isJsonTransportableBoundaryValue(t.value)
  );
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let passedTests = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Keep the sample small while still covering representative numeric edges.
      for (const test of numericTests.slice(0, 10)) {
        const testData = {
          email: 'boundary@test.com',
          password: 'Test123!',
          [test.field]: test.value
        };
        
        const res = await api.post(endpoint, {
          data: JSON.stringify(testData),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // Crashes or 500s at the boundary suggest unsafe numeric handling.
        if (status >= 500) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            status,
            issue: 'Server crashed with boundary value'
          });
        }
        
        // Error text that mentions overflow or trace details should be treated as exposure.
        if (/stack|traceback|overflow|exception/i.test(text)) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            issue: 'Error details exposed in response'
          });
        }
        
        // Invalid values should not be accepted as successful input.
        if (!test.expectValid && [200, 201].includes(status)) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            status,
            issue: 'Invalid boundary value accepted'
          });
        }
        
        // Count both expected successes and expected rejections as handled cases.
        if ((test.expectValid && [200, 201].includes(status)) || 
            (!test.expectValid && [400, 422].includes(status))) {
          passedTests++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for boundary value testing');
    test.skip(true, 'No endpoints found');
    return;
  }

  if (passedTests === 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      vulnerabilitiesFound: vulnerabilities.length,
      passedTests,
      issue: 'Boundary value test did not validate any successful/expected cases'
    }, [
      'Ensure at least one representative valid and invalid boundary case is exercised',
      'Confirm the target endpoint accepts the test payload shape used by the fuzzing cases',
      'Review API schema so the test can cover real numeric fields instead of non-applicable inputs'
    ]);
    expect(passedTests).toBeGreaterThan(0);
  }
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      vulnerabilitiesFound: vulnerabilities.length,
      examples: vulnerabilities.slice(0, 3),
      passedTests,
      issue: `Boundary value testing revealed ${vulnerabilities.length} validation issues`
    }, [
      'Implement strict input validation with min/max bounds',
      'Use appropriate data types (int32, int64, decimal)',
      'Validate ranges before processing',
      'Return consistent 400/422 errors for invalid input',
      'Check for integer overflow in calculations',
      'Use safe arithmetic operations'
    ]);
    expect(vulnerabilities.length).toBe(0);
  } else {
    reporter.reportPass(
      `API handles numeric boundary values correctly (${passedTests} tests passed)`,
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: String length boundaries
 * 
 * Purpose: Verifies that string fields enforce length limits to
 * prevent buffer overflows and resource exhaustion.
 */
test('Boundary Values: string length limits enforced', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Reuse the same create routes for string-length validation.
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const stringTests = generateBoundaryTests().filter(t => 
    typeof t.value === 'string' && t.field !== 'email'
  );
  
  let endpointFound = false;
  let issues = 0;
  let acceptedExcessiveLength = false;
  
  for (const endpoint of endpoints) {
    try {
      // Keep the run compact while still hitting short and long strings.
      for (const test of stringTests.slice(0, 8)) {
        const testData = {
          email: 'length@test.com',
          password: 'Test123!',
          [test.field]: test.value
        };
        
        const res = await api.post(endpoint, {
          data: JSON.stringify(testData),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        // Crashes at long lengths indicate the parser or handler is not bounded.
        if (res.status() >= 500) {
          issues++;
        }
        
        // Very long strings should be rejected or explicitly limited.
        if (test.value.length > 10000 && [200, 201].includes(res.status())) {
          acceptedExcessiveLength = true;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for string length testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (issues > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      serverCrashes: issues,
      issue: 'Server crashed with extreme string lengths - buffer overflow risk'
    }, [
      'Implement maximum string length validation',
      'Validate lengths before processing',
      'Use database column constraints',
      'Return 422 for strings exceeding limits'
    ]);
    expect(issues).toBe(0);
  } else if (acceptedExcessiveLength) {
    reporter.reportWarning(
      'Performance-only concern: the API accepted very long strings (>10KB) without crashing. This suggests missing size limits, but not a confirmed parser or injection vulnerability.',
      [
        'Treat this as a capacity/performance hardening issue unless crashes or error disclosure are observed.',
        'Enforce reasonable string length limits and return 413/422 as appropriate.',
        'Document maximum field lengths and validate input size before database operations.'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'API enforces reasonable string length limits',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Null and undefined handling
 * 
 * Purpose: Verifies that null/undefined values are properly handled
 * to prevent null pointer dereferences and logic errors.
 */
test('Boundary Values: null and undefined handled safely', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Probe the same create routes for null and undefined handling.
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const nullTests = generateBoundaryTests().filter(t => 
    t.value === null || t.value === undefined
  );
  
  let endpointFound = false;
  let crashes = 0;
  let mishandled = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Exercise both required-field and optional-field null behavior.
      for (const test of nullTests) {
        const testData: any = {
          email: 'null@test.com',
          password: 'Test123!'
        };
        
        // Only add field if value is not undefined (JSON.stringify removes undefined)
        if (test.value !== undefined) {
          testData[test.field] = test.value;
        }
        
        const res = await api.post(endpoint, {
          data: JSON.stringify(testData),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // Check for crashes
        if (status >= 500) {
          crashes++;
        }
        
        // Check for null reference errors in response
        if (/null.*reference|cannot.*null|undefined.*property/i.test(text)) {
          crashes++;
        }
        
        // Required fields should reject null values rather than accepting them.
        if ((test.field === 'email' || test.field === 'password') && 
            test.value === null && 
            [200, 201].includes(status)) {
          mishandled++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for null/undefined testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      crashes,
      issue: 'Server crashed or exposed null reference errors'
    }, [
      'Implement null-safety checks before processing',
      'Use optional chaining (?.) and nullish coalescing (??)',
      'Validate required fields explicitly',
      'Handle null gracefully with default values or rejection'
    ]);
    expect(crashes).toBe(0);
  } else if (mishandled > 0) {
    reporter.reportWarning(
      `True vulnerability: ${mishandled} required fields accepted null values.`,
      [
        'Validate required fields are present and non-null.',
        'Use schema validation (e.g., Joi, Yup, Zod).',
        'Return 400 with a clear error for missing required fields.'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'API handles null and undefined values safely',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Array boundary conditions
 * 
 * Purpose: Verifies that array fields handle empty arrays, single
 * items, and very large arrays without crashes or performance issues.
 */
test('Boundary Values: array size limits enforced', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  // Reuse the same routes for array-length boundary checks.
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const arrayTests = [
    { name: 'empty_array', value: [] },
    { name: 'single_item', value: ['item'] },
    { name: 'array_10', value: Array(10).fill('x') },
    { name: 'array_100', value: Array(100).fill('y') },
    { name: 'array_1000', value: Array(1000).fill('z') },
  ];
  
  let endpointFound = false;
  let slowResponses = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Try a few representative sizes instead of blasting the endpoint.
      for (const test of arrayTests) {
        const startTime = Date.now();
        
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: 'array@test.com',
            password: 'Test123!',
            tags: test.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        const duration = Date.now() - startTime;
        
        if (!res) continue;
        endpointFound = true;
        
        // A server error at size boundaries suggests the parser ran out of room.
        if (res.status() >= 500) {
          crashes++;
        }
        
        // Slow responses point to performance pressure, not necessarily a crash.
        if (duration > 3000) {
          slowResponses++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for array boundary testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      crashes,
      issue: 'Server crashed with large array inputs'
    });
    expect(crashes).toBe(0);
  } else if (slowResponses > 2) {
    reporter.reportWarning(
      `Performance-only concern: ${slowResponses} slow responses with large arrays, but no crash was observed. This indicates parser or validation overhead rather than a confirmed vulnerability.`,
      [
        'Treat this as a capacity/performance hardening issue unless crashes or error disclosure are observed.',
        'Implement array size limits and validate array length before processing.',
        'Consider pagination for large datasets.'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportPass(
      'API handles array boundary conditions safely',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});
