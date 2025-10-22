import { test, request as playwrightRequest } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';
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
  // Step 1: Define common SQL injection payloads
  const sqlPayloads = [
    "' OR '1'='1",                    // Classic authentication bypass
    "admin' --",                      // Comment-based injection
    "' OR 1=1 --",                    // Boolean-based injection
    "'; DROP TABLE users; --",        // Destructive injection
    "1' UNION SELECT NULL, NULL, NULL --", // Union-based injection
  ];

  // Step 2: Test each SQL injection payload
  for (const payload of sqlPayloads) {
    const attempt = await tryLogin(request as any, payload, 'password');
    
    if (attempt) {
      const { res } = attempt as any;
      const status = res.status();

      // Step 3: Verify SQL injection did not succeed
      const vulnerable = status >= 200 && status < 300;
      
      if (vulnerable) {
        softCheck(
          testInfo,
          false,
          `SQL Injection vulnerability: payload "${payload}" may have succeeded`
        );
        break;
      }

      // Step 4: Check for SQL error messages in response
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
      } catch (e) {
        // Continue testing other payloads
      }
    }
  }
});

test('SQLi: parameterized queries for search/filter', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
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
  const user = await ensureTestUser(request as any);
  
  // Step 1: Define NoSQL injection payloads using MongoDB operators
  const noSQLPayloads = [
    { email: { $gt: '' }, password: { $gt: '' } },    // Greater than empty string
    { email: { $ne: null }, password: { $ne: null } }, // Not equal to null
    { $where: 'this.password.length > 0' },            // JavaScript injection
  ];

  // Step 2: Test each NoSQL injection payload
  for (const payload of noSQLPayloads) {
    try {
      const res = await request.post('/api/login', {
        data: payload,
        headers: { 'content-type': 'application/json' },
      });

      const status = res.status();
      const vulnerable = status >= 200 && status < 300;

      // Step 3: Check if authentication was bypassed
      if (vulnerable) {
        try {
          const body = await res.json();
          // Step 4: Verify no authentication token was generated
          if (body.token || body.access_token) {
            softCheck(
              testInfo,
              false,
              'NoSQL Injection vulnerability: MongoDB operator injection may be possible'
            );
            break;
          }
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
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Test error-based injection
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
    } catch (e) {
      // Continue
    }
  }
});

test('SQLi/NoSQLi: input sanitization in API endpoints', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Try common injection patterns
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

      // Should reject or sanitize malicious input
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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const probePaths = ['/api/users', '/api/auth', '/api/docs', '/'];
  const payload = "' OR '1'='1"; // Basic SQL injection payload
  let probed = false;
  
  // Step 1: Test injection payload on various endpoints
  for (const p of probePaths) {
    try {
      // Step 2: Send injection payload as query parameter
      const res = await api.get(p + `?q=${encodeURIComponent(payload)}`);
      probed = true;
      
      // Step 3: Verify no server errors (500+ status codes)
      const text = await res.text().catch(() => '');
      const hasStackTrace = /stack|exception|traceback/i.test(text);
      
      if (res.status() >= 500) {
        reporter.reportVulnerability('API8_INJECTION', {
          endpoint: p,
          payload,
          statusCode: res.status(),
          hasStackTrace,
          issue: 'Server error detected with injection payload - potential SQL/command injection vulnerability'
        });
      } else if (hasStackTrace) {
        reporter.reportVulnerability('API8_INJECTION', {
          endpoint: p,
          payload,
          statusCode: res.status(),
          hasStackTrace: true,
          issue: 'Stack trace or exception details exposed in response - information disclosure vulnerability'
        });
      } else {
        reporter.reportPass(
          'API handled injection payload gracefully without server errors or information disclosure',
          OWASP_VULNERABILITIES.API8_INJECTION.name
        );
      }
      break;
    } catch (e) {
      // Continue testing other endpoints
    }
  }
  
  // Step 5: Skip if no endpoints were probeable
  if (!probed) {
    reporter.reportSkip('No probeable endpoints for injection test');
    test.skip(true, 'No probeable endpoints for injection test');
    return;
  }
});
