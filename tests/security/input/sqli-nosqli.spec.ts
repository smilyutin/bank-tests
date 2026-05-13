import { test, request as playwrightRequest } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * SQL Injection and NoSQL Injection Tests
 * 
 * These tests verify that the application properly protects against
 * SQL injection and NoSQL injection attacks by using parameterized queries
 * and proper input validation.
 * 
 * Security Risks Addressed:
 * 1. SQL injection in authentication forms
 * 2. SQL injection in search/filter parameters
 * 3. NoSQL injection in MongoDB queries
 * 4. Error-based SQL injection
 * 5. Input sanitization in API endpoints
 * 
 * Expected Behavior:
 * - Parameterized queries should prevent SQL injection
 * - Input validation should reject malicious payloads
 * - Error messages should not expose database information
 * - NoSQL operators should be properly escaped
 */

/**
 * Test: SQL injection in login form
 * 
 * Purpose: Verifies that the login form is protected against SQL injection
 * attacks that could bypass authentication or expose database information.
 * 
 * Security Impact: SQL injection in login can lead to:
 * - Authentication bypass through SQL manipulation
 * - Database information disclosure
 * - Unauthorized access to user accounts
 * - Database structure exposure
 * 
 * Test Strategy:
 * 1. Attempt SQL injection payloads in login form
 * 2. Verify authentication is not bypassed
 * 3. Check for SQL error messages in responses
 * 4. Ensure proper parameterized queries are used
 */
test('SQLi: SQL injection in login form', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  // Try a small set of classic login-bypass payloads.
  const sqlPayloads = [
    "' OR '1'='1",                    // Classic authentication bypass
    "admin' --",                      // Comment-based injection
    "' OR 1=1 --",                    // Boolean-based injection
    "'; DROP TABLE users; --",        // Destructive injection
    "1' UNION SELECT NULL, NULL, NULL --", // Union-based injection
  ];

  // Feed each payload into the login helper and check whether it is accepted.
  for (const payload of sqlPayloads) {
    const attempt = await tryLogin(request as any, payload, 'password');
    
    if (attempt) {
      const { res } = attempt as any;
      const status = res.status();

      // A 2xx login response for a payload like this would be a strong warning.
      const vulnerable = status >= 200 && status < 300;
      
      if (vulnerable) {
        softCheck(
          testInfo,
          false,
          `SQL Injection vulnerability: payload "${payload}" may have succeeded`
        );
        break;
      }

      // Search for database-specific error text that should stay hidden.
      try {
        const body = await res.text();
        const hasSQLError = 
          body.includes('SQL syntax') ||
          body.includes('mysql_') ||
          body.includes('PostgreSQL') ||
          body.includes('ORA-') ||
          body.includes('sqlite3');

        softCheck(
          testInfo,
          !hasSQLError,
          'SQL error messages exposed in response (information disclosure)'
        );

        if (!hasSQLError) {
          reporter.reportPass(
            'SQL injection payloads did not bypass login and no SQL errors were exposed.',
            OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
          );
        }
      } catch (e) {
        // Continue testing other payloads
      }
    }
  }
});

test('SQLi: parameterized queries for search/filter', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportWarning(
      'SQLi search/filter probe could not run because no valid test user credentials are configured.',
      [
        'Seed a login-capable test user in tests/fixtures/users.json',
        'Automate test-user provisioning before injection security tests run',
        'Fail CI earlier if required auth fixtures are missing'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportWarning(
      'SQLi search/filter probe could not run because login failed or no bearer token was obtained.',
      [
        'Ensure login endpoint is reachable and returns an auth token for test users',
        'If auth is cookie-based, add equivalent authenticated-request coverage to this suite',
        'Document auth transport mechanism so injection probes use the correct credential type'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const { token } = attempt as any;
  const sqlPayloads = [
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "1 UNION SELECT * FROM users",
  ];

  for (const payload of sqlPayloads) {
    try {
      const res = await request.get(`/api/users?search=${encodeURIComponent(payload)}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      const status = res.status();
      
      // Should return 400 or filter safely
      if (status === 500) {
        const body = await res.text().catch(() => '');
        const hasSQLError = 
          body.includes('SQL') ||
          body.includes('syntax error');

        softCheck(
          testInfo,
          !hasSQLError,
          'SQL injection may be present (500 error with SQL keywords)'
        );
        break;
      }
    } catch (e) {
      // Endpoint might not exist
    }
  }
});

/**
 * Test: NoSQL injection in MongoDB queries
 * 
 * Purpose: Verifies that the application protects against NoSQL injection
 * attacks that could bypass authentication in MongoDB-based systems.
 * 
 * Security Impact: NoSQL injection can lead to:
 * - Authentication bypass through operator injection
 * - Unauthorized data access
 * - Database manipulation
 * - Privilege escalation
 * 
 * Test Strategy:
 * 1. Attempt NoSQL injection payloads in login requests
 * 2. Verify authentication is not bypassed
 * 3. Check for successful token generation
 * 4. Ensure MongoDB operators are properly escaped
 */
test('NoSQLi: MongoDB injection in queries', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  // Use MongoDB-style operators that should not be interpreted as query syntax.
  const noSQLPayloads = [
    { email: { $gt: '' }, password: { $gt: '' } },    // Greater than empty string
    { email: { $ne: null }, password: { $ne: null } }, // Not equal to null
    { $where: 'this.password.length > 0' },            // JavaScript injection
  ];

  // Submit each payload and see whether the login endpoint accepts it.
  for (const payload of noSQLPayloads) {
    try {
      const res = await request.post('/api/login', {
        data: payload,
        headers: { 'content-type': 'application/json' },
      });

      const status = res.status();
      const vulnerable = status >= 200 && status < 300;

      // A successful auth response here would mean the query was not safely bound.
      if (vulnerable) {
        try {
          const body = await res.json();
          // A real token here would confirm the bypass.
          if (body.token || body.access_token) {
            softCheck(
              testInfo,
              false,
              'NoSQL Injection vulnerability: MongoDB operator injection may be possible'
            );
            break;
          }

          reporter.reportPass(
            'NoSQL injection payloads did not bypass authentication.',
            OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
          );
        } catch (e) {
          // Continue testing other payloads
        }
      }
    } catch (e) {
      // Expected - payload rejected
    }
  }
});

test('SQLi: error-based SQL injection detection', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportWarning(
      'Error-based SQLi probe could not run because no valid test user credentials are configured.',
      [
        'Seed a login-capable test user in tests/fixtures/users.json',
        'Automate test-user provisioning before injection security tests run',
        'Fail CI earlier if required auth fixtures are missing'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportWarning(
      'Error-based SQLi probe could not run because login failed or no bearer token was obtained.',
      [
        'Ensure login endpoint is reachable and returns an auth token for test users',
        'If auth is cookie-based, add equivalent authenticated-request coverage to this suite',
        'Document auth transport mechanism so injection probes use the correct credential type'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const { token } = attempt as any;

  // Error-based payloads should produce generic failures, not database clues.
  const errorPayloads = [
    "1' AND 1=CONVERT(int, (SELECT @@version)) --",
    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version))) --",
  ];

  for (const payload of errorPayloads) {
    try {
      const res = await request.get(`/api/users/${payload}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      const body = await res.text().catch(() => '');
      // Database vendor strings in the body suggest information disclosure.
      const hasDBInfo = 
        body.includes('MySQL') ||
        body.includes('PostgreSQL') ||
        body.includes('Microsoft SQL') ||
        body.includes('@@version');

      softCheck(
        testInfo,
        !hasDBInfo,
        'Database information exposed through error-based SQL injection'
      );

      if (hasDBInfo) break;

      reporter.reportPass(
        'Error-based SQL injection payloads did not expose database information.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    } catch (e) {
      // Continue
    }
  }
});

test('SQLi/NoSQLi: input sanitization in API endpoints', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportWarning(
      'Input-sanitization injection probe could not run because no valid test user credentials are configured.',
      [
        'Seed a login-capable test user in tests/fixtures/users.json',
        'Automate test-user provisioning before injection security tests run',
        'Fail CI earlier if required auth fixtures are missing'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportWarning(
      'Input-sanitization injection probe could not run because login failed or no bearer token was obtained.',
      [
        'Ensure login endpoint is reachable and returns an auth token for test users',
        'If auth is cookie-based, add equivalent authenticated-request coverage to this suite',
        'Document auth transport mechanism so injection probes use the correct credential type'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  const { token } = attempt as any;

  // Probe a few mixed SQL/NoSQL patterns against a profile update route.
  const injectionPatterns = [
    "'; DELETE FROM users WHERE '1'='1",
    "1' UNION ALL SELECT NULL--",
    "admin'/**/OR/**/1=1--",
  ];

  let properlyProtected = true;

  for (const pattern of injectionPatterns) {
    try {
      const res = await request.post('/api/profile', {
        headers: { 'Authorization': `Bearer ${token}` },
        data: { name: pattern, bio: pattern },
      });

      // Any 500 here suggests the endpoint is not safely validating input.
      const status = res.status();
      if (status === 500) {
        properlyProtected = false;
        break;
      }
    } catch (e) {
      // Expected
    }
  }

  softCheck(
    testInfo,
    properlyProtected,
    'API should properly sanitize input to prevent injection attacks'
  );

  if (properlyProtected) {
    reporter.reportPass(
      'API input sanitization prevented the tested SQL/NoSQL injection patterns.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Injection Vulnerability Detection (OWASP API8:2023)
 * 
 * Purpose: Verifies that API endpoints properly handle malicious input
 * and do not leak sensitive information through error responses.
 * 
 * Security Impact: Injection vulnerabilities can lead to:
 * - SQL injection enabling database access
 * - Command injection allowing system compromise
 * - Information disclosure through error messages
 * - Data corruption and integrity violations
 * 
 * Test Strategy:
 * 1. Send SQL injection payload to various endpoints
 * 2. Check for server errors (500 status codes)
 * 3. Verify no sensitive information in error responses
 * 4. Ensure graceful error handling
 */
test('Injection (OWASP API8): SQL/command injection probe should not return server error', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'Injection probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running injection security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const probePaths = ['/api/users', '/api/auth', '/api/docs', '/'];
  const payload = "' OR '1'='1"; // Basic SQL injection payload
  let probed = false;
  
  // Try the same payload against a few likely probe targets.
  for (const p of probePaths) {
    try {
      // Send the payload in a query parameter so the backend has to parse it.
      const res = await api.get(p + `?q=${encodeURIComponent(payload)}`);
      probed = true;
      
      // Look for server errors or explicit exception text in the response body.
      const text = await res.text().catch(() => '');
      const hasStackTrace = /stack|exception|traceback/i.test(text);
      
      if (res.status() >= 500) {
        reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
          endpoint: p,
          payload,
          statusCode: res.status(),
          hasStackTrace,
          issue: 'Server error detected with injection payload - potential SQL/command injection vulnerability'
        });
      } else if (hasStackTrace) {
        reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
          endpoint: p,
          payload,
          statusCode: res.status(),
          hasStackTrace: true,
          issue: 'Stack trace or exception details exposed in response - information disclosure vulnerability'
        });
      } else {
        reporter.reportPass(
          'API handled injection payload gracefully without server errors or information disclosure',
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }
      break;
    } catch (e) {
      // Continue testing other endpoints
    }
  }
  
  // Skip cleanly when the environment does not expose any probeable endpoints.
  if (!probed) {
    reporter.reportWarning(
      'Injection probe could not run because no probeable endpoints responded.',
      [
        'Expose/document at least one API endpoint that accepts query input for injection checks',
        'Ensure CI target includes representative routes for security probing',
        'Add route metadata so tests can discover valid probe targets'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
});
