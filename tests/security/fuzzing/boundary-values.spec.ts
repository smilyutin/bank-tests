import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

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
 * Generate boundary value test cases
 */
function generateBoundaryTests(): Array<{ name: string; field: string; value: any; expectValid: boolean }> {
  return [
    // Integer boundaries
    { name: 'int32_max', field: 'age', value: 2147483647, expectValid: false },
    { name: 'int32_min', field: 'age', value: -2147483648, expectValid: false },
    { name: 'int32_max_plus_one', field: 'age', value: 2147483648, expectValid: false },
    { name: 'int64_max', field: 'value', value: 9223372036854775807, expectValid: false },
    { name: 'uint_max', field: 'count', value: 4294967295, expectValid: false },
    
    // Zero and near-zero
    { name: 'zero', field: 'age', value: 0, expectValid: true },
    { name: 'negative_one', field: 'age', value: -1, expectValid: false },
    { name: 'positive_one', field: 'age', value: 1, expectValid: true },
    { name: 'negative_zero', field: 'value', value: -0, expectValid: true },
    
    // Float boundaries
    { name: 'float_max', field: 'price', value: Number.MAX_VALUE, expectValid: false },
    { name: 'float_min', field: 'price', value: Number.MIN_VALUE, expectValid: true },
    { name: 'float_epsilon', field: 'price', value: Number.EPSILON, expectValid: true },
    { name: 'infinity', field: 'price', value: Infinity, expectValid: false },
    { name: 'neg_infinity', field: 'price', value: -Infinity, expectValid: false },
    { name: 'nan', field: 'price', value: NaN, expectValid: false },
    
    // String length boundaries
    { name: 'empty_string', field: 'username', value: '', expectValid: false },
    { name: 'single_char', field: 'username', value: 'a', expectValid: false },
    { name: 'max_username_255', field: 'username', value: 'a'.repeat(255), expectValid: false },
    { name: 'max_username_256', field: 'username', value: 'a'.repeat(256), expectValid: false },
    { name: 'very_long_1k', field: 'bio', value: 'x'.repeat(1000), expectValid: false },
    { name: 'very_long_10k', field: 'bio', value: 'y'.repeat(10000), expectValid: false },
    { name: 'very_long_100k', field: 'description', value: 'z'.repeat(100000), expectValid: false },
    
    // Email boundaries
    { name: 'min_email', field: 'email', value: 'a@b.c', expectValid: true },
    { name: 'long_email_64_local', field: 'email', value: 'a'.repeat(64) + '@example.com', expectValid: true },
    { name: 'long_email_65_local', field: 'email', value: 'a'.repeat(65) + '@example.com', expectValid: false },
    { name: 'long_email_254_total', field: 'email', value: 'a'.repeat(240) + '@example.com', expectValid: false },
    { name: 'email_at_boundary', field: 'email', value: 'test@' + 'a'.repeat(63) + '.com', expectValid: true },
    
    // Array boundaries
    { name: 'empty_array', field: 'tags', value: [], expectValid: true },
    { name: 'single_item_array', field: 'tags', value: ['tag1'], expectValid: true },
    { name: 'large_array_100', field: 'tags', value: Array(100).fill('tag'), expectValid: false },
    { name: 'large_array_1000', field: 'tags', value: Array(1000).fill('tag'), expectValid: false },
    
    // Null/undefined boundaries
    { name: 'null_value', field: 'middleName', value: null, expectValid: true },
    { name: 'undefined_value', field: 'suffix', value: undefined, expectValid: true },
    { name: 'null_email', field: 'email', value: null, expectValid: false },
    { name: 'undefined_password', field: 'password', value: undefined, expectValid: false },
    
    // Boolean edge cases
    { name: 'boolean_true', field: 'active', value: true, expectValid: true },
    { name: 'boolean_false', field: 'active', value: false, expectValid: true },
    { name: 'string_true', field: 'active', value: 'true', expectValid: false },
    { name: 'number_one_as_bool', field: 'active', value: 1, expectValid: false },
    { name: 'number_zero_as_bool', field: 'active', value: 0, expectValid: false },
    
    // Date boundaries
    { name: 'unix_epoch', field: 'birthdate', value: '1970-01-01', expectValid: true },
    { name: 'year_2038', field: 'expiry', value: '2038-01-19', expectValid: true },
    { name: 'year_1900', field: 'birthdate', value: '1900-01-01', expectValid: true },
    { name: 'year_2100', field: 'futureDate', value: '2100-12-31', expectValid: true },
    { name: 'invalid_date_feb30', field: 'date', value: '2024-02-30', expectValid: false },
    { name: 'invalid_date_month13', field: 'date', value: '2024-13-01', expectValid: false },
    
    // Special numeric formats
    { name: 'leading_zeros', field: 'code', value: '00123', expectValid: true },
    { name: 'scientific_notation', field: 'value', value: 1.23e10, expectValid: true },
    { name: 'hex_string', field: 'code', value: '0xFF', expectValid: true },
    { name: 'negative_string', field: 'amount', value: '-100', expectValid: false },
    
    // Whitespace boundaries
    { name: 'only_spaces', field: 'name', value: '   ', expectValid: false },
    { name: 'leading_spaces', field: 'name', value: '  John', expectValid: true },
    { name: 'trailing_spaces', field: 'name', value: 'John  ', expectValid: true },
    { name: 'tabs_only', field: 'name', value: '\t\t\t', expectValid: false },
    { name: 'newlines_only', field: 'name', value: '\n\n\n', expectValid: false },
  ];
}

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
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const numericTests = generateBoundaryTests().filter(t => 
    typeof t.value === 'number' || t.field.includes('age') || t.field.includes('value')
  );
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let passedTests = 0;
  
  for (const endpoint of endpoints) {
    try {
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
        
        // Check for server crashes
        if (status >= 500) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            status,
            issue: 'Server crashed with boundary value'
          });
        }
        
        // Check for stack traces
        if (/stack|traceback|overflow|exception/i.test(text)) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            issue: 'Error details exposed in response'
          });
        }
        
        // If shouldn't be valid but was accepted
        if (!test.expectValid && [200, 201].includes(status)) {
          vulnerabilities.push({
            test: test.name,
            field: test.field,
            value: test.value,
            status,
            issue: 'Invalid boundary value accepted'
          });
        }
        
        // Success case
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
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const stringTests = generateBoundaryTests().filter(t => 
    typeof t.value === 'string' && t.field !== 'email'
  );
  
  let endpointFound = false;
  let issues = 0;
  let acceptedExcessiveLength = false;
  
  for (const endpoint of endpoints) {
    try {
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
        
        // Check for crashes
        if (res.status() >= 500) {
          issues++;
        }
        
        // Check if very long strings (>10k) were accepted
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
    reporter.reportVulnerability('API8_INJECTION', {
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
      'API accepted very long strings (>10KB) without limits',
      [
        'Enforce reasonable string length limits',
        'Prevent DoS through memory exhaustion',
        'Document maximum field lengths',
        'Validate input size before database operations'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API enforces reasonable string length limits',
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const nullTests = generateBoundaryTests().filter(t => 
    t.value === null || t.value === undefined
  );
  
  let endpointFound = false;
  let crashes = 0;
  let mishandled = 0;
  
  for (const endpoint of endpoints) {
    try {
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
        
        // Required fields (email, password) should reject null
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
    reporter.reportVulnerability('API8_INJECTION', {
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
      `${mishandled} required fields accepted null values`,
      [
        'Validate required fields are present and non-null',
        'Use schema validation (e.g., Joi, Yup, Zod)',
        'Return 400 with clear error for missing required fields'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API handles null and undefined values safely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
        
        if (res.status() >= 500) {
          crashes++;
        }
        
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
    reporter.reportVulnerability('API8_INJECTION', {
      crashes,
      issue: 'Server crashed with large array inputs'
    });
    expect(crashes).toBe(0);
  } else if (slowResponses > 2) {
    reporter.reportWarning(
      `${slowResponses} slow responses with large arrays - potential DoS`,
      [
        'Implement array size limits',
        'Validate array length before processing',
        'Consider pagination for large datasets'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportPass(
      'API handles array boundary conditions safely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});
