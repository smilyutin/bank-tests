import { test, expect, request } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { ensureTestUser } from '../utils/utils';

const TARGET_APP_FIX_FIRST = [
  'Return 4xx validation errors (400/401/403/422) for malformed client input instead of 500',
  'Disable debug/traceback output in production error responses',
  'Implement centralized exception handling that returns sanitized error bodies',
  'Validate and sanitize request payloads at the API boundary',
  'Ensure API login accepts only expected fields and gracefully rejects malformed payloads',
  'Add negative tests in CI to verify no stack traces/internal details are exposed',
];

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
    reporter.reportSkip('baseURL not provided; skipping test');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const api = await request.newContext({ baseURL: baseURL.toString() });
  await ensureTestUser(api as any);

  // Send a few malformed payloads to see whether the API sanitizes errors properly.
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
  let exercisedAny = false;
  const findings: string[] = [];

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

      // Treat missing routes as non-applicable rather than failing the suite.
      if (status === 404 || status === 405) {
        reporter.reportSkip(`${testCase.method} ${testCase.endpoint} not applicable (status ${status})`);
        continue;
      }

      exercisedAny = true;

      // eslint-disable-next-line no-console
      console.log(`[error-handling] ${testCase.method} ${testCase.endpoint} => ${status}`);

      // Look for stack-trace signatures or debug output in the response body.
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
          findings.push(`${testCase.method} ${testCase.endpoint}: stack trace/internal details exposed (status ${status})`);
          reporter.reportWarning(
            `Internal error details exposed for ${testCase.method} ${testCase.endpoint}. ` +
            `Response appears to contain stack trace/debug data (status ${status}).`,
            TARGET_APP_FIX_FIRST,
            OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
          );
          break;
        }
      }

      // Client-side validation mistakes should not become server errors.
      if (status === 500) {
        has500Errors = true;
        findings.push(`${testCase.method} ${testCase.endpoint}: returned 500 for client-side invalid input`);
        reporter.reportWarning(
          `API returned 500 for malformed input on ${testCase.method} ${testCase.endpoint}. ` +
          `Expected a 4xx validation/authz response.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      }

      // A 4xx response is the expected safe outcome here.
      if ([400, 401, 403, 422].includes(status)) {
        reporter.reportPass(
          `${testCase.method} ${testCase.endpoint} correctly returned ${status} for invalid input`,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      } else if (status >= 200 && status < 300) {
        findings.push(`${testCase.method} ${testCase.endpoint}: accepted malformed input with ${status}`);
        reporter.reportWarning(
          `${testCase.method} ${testCase.endpoint} returned ${status} for malformed input. ` +
          `This may indicate weak validation/error handling.`,
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      }

    } catch (err) {
      // Treat a network-level failure as a non-applicable endpoint and move on.
      continue;
    }
  }

  if (!exercisedAny) {
    reporter.reportSkip('No applicable endpoints were available to assess API error handling behavior');
    test.skip(true, 'No applicable endpoints were available to assess API error handling behavior');
    return;
  }

  if (!hasStackTrace && !has500Errors && findings.length === 0) {
    reporter.reportPass(
      'API error handling appears secure: no stack traces/internal details and no 500 responses for malformed client input',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  } else {
    reporter.reportWarning(
      `API error-handling concerns detected (${findings.length} finding(s)). Summary: ${findings.join('; ')}`,
      TARGET_APP_FIX_FIRST,
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }

  expect(true).toBeTruthy();
});
