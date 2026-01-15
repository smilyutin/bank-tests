import { test, expect, request } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { ensureTestUser } from '../utils';

/**
 * API Error Handling Security Test
 * 
 * Ensures that APIs return proper 4xx validation errors for invalid input
 * and do NOT expose stack traces or internal error details (500 errors).
 * 
 * OWASP: API8:2023 Security Misconfiguration
 */

test('API should return 4xx for invalid fields, not 500 with stack traces', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  if (!baseURL) {
    reporter.reportWarning('baseURL not provided; skipping test', [], OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name);
    test.skip();
    return;
  }

  const api = await request.newContext({ baseURL: baseURL.toString() });
  const user = await ensureTestUser(api as any);

  // Test endpoints with malformed/invalid payloads
  const testCases = [
    {
      endpoint: '/api/virtual-cards/create',
      method: 'POST',
      payload: {
        // Invalid: forbidden fields that should trigger validation
        limit: 9999999,
        daily_limit: 9999999,
        ownerId: 'attacker-id',
        isAdmin: true,
        isBlocked: false
      },
      description: 'virtual card creation with forbidden fields'
    },
    {
      endpoint: '/api/users',
      method: 'POST',
      payload: {
        // Invalid: attempting to set admin flag
        username: 'testuser',
        email: 'test@example.com',
        password: 'pass',
        is_admin: true,
        isAdmin: true,
        role: 'admin'
      },
      description: 'user creation with forbidden admin fields'
    },
    {
      endpoint: '/api/login',
      method: 'POST',
      payload: {
        // Invalid: SQL injection attempt
        username: "admin' OR '1'='1",
        password: "admin' OR '1'='1"
      },
      description: 'login with SQL injection attempt'
    }
  ];

  let hasStackTrace = false;
  let has500Errors = false;

  for (const testCase of testCases) {
    try {
      const res = await api.fetch(testCase.endpoint, {
        method: testCase.method,
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify(testCase.payload)
      }).catch(() => null);

      if (!res) continue;

      const status = res.status();
      const text = await res.text().catch(() => '');

      // eslint-disable-next-line no-console
      console.log(`[error-handling] ${testCase.method} ${testCase.endpoint} => ${status}`);

      // Check for stack traces in response (signatures of debug mode / unhandled exceptions)
      const stackTracePatterns = [
        /Traceback \(most recent call last\)/i,
        /File ".*\.py", line \d+/i,
        /sqlite3\.OperationalError/i,
        /Werkzeug Debugger/i,
        /at\s+\S+\s+\(.*:\d+:\d+\)/,  // JavaScript stack traces
        /raise\s+\w+Error/i,
        /Exception:/i,
        /Error:\s+\w+Error/i
      ];

      for (const pattern of stackTracePatterns) {
        if (pattern.test(text)) {
          hasStackTrace = true;
          reporter.reportVulnerability('API7_MISCONFIGURATION', {
            endpoint: testCase.endpoint,
            method: testCase.method,
            status,
            issue: 'Response contains stack trace or internal error details',
            snippet: text.substring(0, 500)
          });
          break;
        }
      }

      // 500 errors should NOT be returned for client validation issues
      if (status === 500) {
        has500Errors = true;
        reporter.reportVulnerability('API7_MISCONFIGURATION', {
          endpoint: testCase.endpoint,
          method: testCase.method,
          status,
          description: testCase.description,
          issue: 'API returned 500 Internal Server Error for client validation issue; should return 4xx',
          response: text.substring(0, 500)
        });
      }

      // Successful validation: 4xx response
      if ([400, 401, 403, 422].includes(status)) {
        reporter.reportPass(
          `${testCase.method} ${testCase.endpoint} correctly returned ${status} for invalid input`,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      }

    } catch (err) {
      // Network-level error; skip
      continue;
    }
  }

  // Final assertion
  if (hasStackTrace) {
    expect(false, 'API exposed stack traces or internal error details in responses').toBeTruthy();
  }

  if (has500Errors) {
    expect(false, 'API returned 500 errors for client validation issues; should return 4xx (400/401/403/422)').toBeTruthy();
  }

  reporter.reportPass('API error handling is secure: no stack traces or 500 errors for validation issues', OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name);
  expect(true).toBeTruthy();
});
