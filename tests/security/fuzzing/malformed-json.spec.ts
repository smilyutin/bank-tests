import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * API Fuzzing - Malformed JSON Tests (OWASP API8:2023)
 * 
 * These tests verify that APIs properly handle malformed, invalid, or
 * edge-case JSON payloads without crashing, exposing errors, or allowing
 * security bypasses through parser vulnerabilities.
 * 
 * Security Risks Addressed:
 * 1. JSON parser crashes leading to DoS
 * 2. Error messages exposing internal server details
 * 3. Type confusion through unexpected JSON structures
 * 4. Injection through JSON smuggling or parser bugs
 * 5. Resource exhaustion through deeply nested objects
 * 
 * Expected Behavior:
 * - Malformed JSON should return 400 (Bad Request)
 * - No stack traces or parser errors in responses
 * - Consistent error handling across all endpoints
 * - No server crashes (500 errors)
 * - Reasonable processing time even for complex payloads
 */

/**
 * Generate malformed JSON payloads
 */
function generateMalformedPayloads(): Array<{ name: string; payload: string; contentType?: string }> {
  return [
    // Invalid JSON syntax
    { name: 'unclosed_brace', payload: '{"email": "test@example.com"' },
    { name: 'unclosed_bracket', payload: '["item1", "item2"' },
    { name: 'trailing_comma', payload: '{"email": "test@example.com",}' },
    { name: 'missing_comma', payload: '{"email": "test@example.com" "password": "test"}' },
    { name: 'single_quotes', payload: "{'email': 'test@example.com'}" },
    { name: 'unquoted_keys', payload: '{email: "test@example.com"}' },
    { name: 'double_comma', payload: '{"email": "test@example.com",, "password": "test"}' },
    { name: 'leading_comma', payload: '{,"email": "test@example.com"}' },
    
    // Empty/null payloads
    { name: 'empty_string', payload: '' },
    { name: 'null_string', payload: 'null' },
    { name: 'undefined_string', payload: 'undefined' },
    { name: 'whitespace_only', payload: '   \n\t  ' },
    { name: 'just_brackets', payload: '{}' },
    { name: 'just_array', payload: '[]' },
    
    // Type mismatches
    { name: 'number_as_json', payload: '12345' },
    { name: 'boolean_as_json', payload: 'true' },
    { name: 'plain_text', payload: 'this is not json' },
    { name: 'html_content', payload: '<html><body>test</body></html>' },
    { name: 'xml_content', payload: '<?xml version="1.0"?><root></root>' },
    
    // Deeply nested structures
    { name: 'deep_nesting_10', payload: '{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}' },
    { name: 'deep_nesting_50', payload: JSON.stringify(createDeeplyNested(50)) },
    { name: 'deep_nesting_100', payload: JSON.stringify(createDeeplyNested(100)) },
    
    // Very large payloads
    { name: 'large_array_1k', payload: JSON.stringify(Array(1000).fill('item')) },
    { name: 'large_array_10k', payload: JSON.stringify(Array(10000).fill('x')) },
    { name: 'large_string_1mb', payload: `{"data": "${'A'.repeat(1000000)}"}` },
    
    // Special characters and encoding
    { name: 'null_bytes', payload: '{"email": "test\u0000@example.com"}' },
    { name: 'unicode_escapes', payload: '{"email": "\\u0074\\u0065\\u0073\\u0074"}' },
    { name: 'utf8_bom', payload: '\uFEFF{"email": "test@example.com"}' },
    { name: 'mixed_encodings', payload: '{"email": "тест@example.com"}' },
    { name: 'emoji_keys', payload: '{"😀": "test", "😁": "value"}' },
    
    // Invalid escaping
    { name: 'invalid_escape', payload: '{"email": "test\\xexample.com"}' },
    { name: 'incomplete_unicode', payload: '{"email": "\\u00"}' },
    { name: 'backslash_spam', payload: '{"email": "\\\\\\\\\\\\"}' },
    
    // Duplicate keys (JSON allows, but could cause issues)
    { name: 'duplicate_keys', payload: '{"email": "first@example.com", "email": "second@example.com"}' },
    { name: 'case_sensitive_dups', payload: '{"Email": "test1@example.com", "email": "test2@example.com"}' },
    
    // Number edge cases
    { name: 'leading_zeros', payload: '{"age": 0123}' },
    { name: 'hex_numbers', payload: '{"value": 0xFF}' },
    { name: 'scientific_extreme', payload: '{"value": 1e308}' },
    { name: 'negative_zero', payload: '{"value": -0}' },
    
    // Arrays with issues
    { name: 'array_trailing_comma', payload: '{"items": [1,2,3,]}' },
    { name: 'array_leading_comma', payload: '{"items": [,1,2,3]}' },
    { name: 'mixed_array_commas', payload: '{"items": [1,,2,,3]}' },
    
    // Control characters
    { name: 'newline_in_string', payload: '{"text": "line1\nline2"}' },
    { name: 'tab_in_string', payload: '{"text": "col1\tcol2"}' },
    { name: 'carriage_return', payload: '{"text": "test\r\nvalue"}' },
    
    // Comments (not valid in JSON)
    { name: 'single_line_comment', payload: '{"email": "test@example.com"} // comment' },
    { name: 'multi_line_comment', payload: '{"email": /* comment */ "test@example.com"}' },
    
    // Wrong content-type
    { name: 'form_urlencoded', payload: 'email=test@example.com&password=test', contentType: 'application/x-www-form-urlencoded' },
    { name: 'plain_text_type', payload: '{"email": "test"}', contentType: 'text/plain' },
    { name: 'xml_type', payload: '{"email": "test"}', contentType: 'application/xml' },
  ];
}

/**
 * Helper to create deeply nested objects
 */
function createDeeplyNested(depth: number): any {
  let obj: any = { value: 'deep' };
  for (let i = 0; i < depth; i++) {
    obj = { nested: obj };
  }
  return obj;
}

/**
 * Test: Malformed JSON handling in user creation
 * 
 * Purpose: Verifies that user creation endpoints properly reject malformed
 * JSON without crashing or exposing internal error details.
 * 
 * Security Impact: Poor JSON parsing can lead to:
 * - DoS through parser crashes
 * - Information disclosure via error messages
 * - Security bypass through parser bugs
 * - Type confusion vulnerabilities
 * 
 * Test Strategy:
 * 1. Send various malformed JSON payloads
 * 2. Verify consistent 400 Bad Request responses
 * 3. Check no stack traces or parser errors exposed
 * 4. Ensure no 500 errors (crashes)
 */
test('Malformed JSON: user creation endpoint handles invalid JSON', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register', '/api/register'];
  const payloads = generateMalformedPayloads();
  
  let endpointFound = false;
  let serverCrashes = 0;
  let informationLeaks = 0;
  let improperHandling = 0;
  let testResults: any[] = [];
  
  for (const endpoint of endpoints) {
    try {
      // Test subset of payloads to avoid overwhelming API
      for (const { name, payload, contentType } of payloads.slice(0, 15)) {
        const res = await api.post(endpoint, {
          data: payload,
          headers: { 'Content-Type': contentType || 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // Check for server crashes (500 errors)
        if (status >= 500) {
          serverCrashes++;
          testResults.push({
            payload: name,
            status,
            issue: 'Server crashed with malformed JSON'
          });
        }
        
        // Check for information disclosure in error messages
        if (/SyntaxError|JSON\.parse|unexpected token|invalid json|parser error/i.test(text)) {
          informationLeaks++;
          testResults.push({
            payload: name,
            status,
            issue: 'Parser error details exposed in response'
          });
        }
        
        // Check for stack traces
        if (/at\s+\w+\s+\(.*:\d+:\d+\)|^\s+at\s/m.test(text)) {
          informationLeaks++;
          testResults.push({
            payload: name,
            status,
            issue: 'Stack trace exposed in response'
          });
        }
        
        // Should return 400, not 200/201
        if ([200, 201].includes(status) && payload !== '{}') {
          improperHandling++;
          testResults.push({
            payload: name,
            status,
            issue: 'Malformed JSON accepted as valid'
          });
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue to next endpoint
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No user creation endpoints found for malformed JSON testing');
    test.skip(true, 'No user creation endpoints found');
    return;
  }
  
  // Report findings
  const totalIssues = serverCrashes + informationLeaks + improperHandling;
  
  if (totalIssues > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      serverCrashes,
      informationLeaks,
      improperHandling,
      totalIssues,
      examples: testResults.slice(0, 5),
      issue: `Malformed JSON handling revealed ${totalIssues} security issues`
    }, [
      'Implement robust JSON parsing with try-catch blocks',
      'Return generic 400 errors without parser details',
      'Never expose stack traces or internal errors',
      'Validate content-type header before parsing',
      'Set limits on JSON complexity (depth, size)',
      'Use schema validation after parsing'
    ]);
    expect(totalIssues).toBe(0);
  } else {
    reporter.reportPass(
      'API handles malformed JSON gracefully without crashes or information disclosure',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Deeply nested JSON handling
 * 
 * Purpose: Verifies that APIs reject or handle deeply nested JSON
 * to prevent stack overflow and DoS attacks.
 */
test('Malformed JSON: deeply nested structures handled safely', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  let endpointFound = false;
  let crashed = false;
  let slowResponses = 0;
  
  for (const endpoint of endpoints) {
    try {
      // Test increasingly deep nesting
      for (const depth of [10, 50, 100, 500]) {
        const startTime = Date.now();
        const payload = JSON.stringify(createDeeplyNested(depth));
        
        const res = await api.post(endpoint, {
          data: payload,
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        const duration = Date.now() - startTime;
        
        if (!res) continue;
        endpointFound = true;
        
        if (res.status() >= 500) {
          crashed = true;
          break;
        }
        
        if (duration > 5000) {
          slowResponses++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for deep nesting test');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashed) {
    reporter.reportVulnerability('API8_INJECTION', {
      issue: 'Server crashed with deeply nested JSON - DoS vulnerability',
      depth: 'various'
    }, [
      'Implement JSON depth limits (e.g., max 20 levels)',
      'Use iterative parsing instead of recursive',
      'Set request size limits',
      'Return 400 for overly complex payloads'
    ]);
    expect(crashed).toBeFalsy();
  } else if (slowResponses > 2) {
    reporter.reportWarning(
      `${slowResponses} slow responses (>5s) with deeply nested JSON - potential DoS vector`,
      [
        'Implement JSON depth and complexity limits',
        'Add request timeouts to prevent resource exhaustion',
        'Consider early rejection of complex structures'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API handles deeply nested JSON safely without crashes',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Large payload handling
 * 
 * Purpose: Verifies that APIs enforce size limits and handle
 * extremely large JSON payloads without resource exhaustion.
 */
test('Malformed JSON: large payload limits enforced', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  let endpointFound = false;
  let acceptedLargePayload = false;
  let crashed = false;
  
  for (const endpoint of endpoints) {
    try {
      // Try progressively larger payloads
      const sizes = [1000, 10000, 100000]; // characters
      
      for (const size of sizes) {
        const largeData = {
          email: 'test@example.com',
          data: 'A'.repeat(size)
        };
        
        const res = await api.post(endpoint, {
          data: JSON.stringify(largeData),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        if (res.status() >= 500) {
          crashed = true;
          break;
        }
        
        // Should reject very large payloads (>100KB)
        if (size >= 100000 && [200, 201].includes(res.status())) {
          acceptedLargePayload = true;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for large payload test');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashed) {
    reporter.reportVulnerability('API4_RATE_LIMIT', {
      issue: 'Server crashed with large JSON payload - resource exhaustion vulnerability'
    }, [
      'Implement request size limits (e.g., 1MB max)',
      'Return 413 Payload Too Large for oversized requests',
      'Configure web server/reverse proxy limits',
      'Validate content-length header before reading body'
    ]);
    expect(crashed).toBeFalsy();
  } else if (acceptedLargePayload) {
    reporter.reportWarning(
      'API accepted very large payloads (>100KB) - potential DoS risk',
      [
        'Implement payload size limits',
        'Return 413 for oversized requests',
        'Document maximum payload sizes',
        'Monitor memory usage during request processing'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportPass(
      'API enforces reasonable payload size limits',
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});
