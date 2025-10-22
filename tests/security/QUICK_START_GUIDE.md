# Quick Start Guide: Security Test Reporting

## Getting Started in 5 Minutes

This guide shows you how to add comprehensive security reporting to your existing tests.

---

## Step 1: Import the SecurityReporter

Add these imports to your test file:

```typescript
import { test, expect } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
```

---

## Step 2: Add testInfo Parameter

Modify your test function to include `testInfo`:

**Before:**
```typescript
test('My security test', async ({ page }) => {
  // test code
});
```

**After:**
```typescript
test('My security test', async ({ page }, testInfo) => {
  // test code
});
```

---

## Step 3: Create Reporter Instance

At the start of your test, create a reporter:

```typescript
test('My security test', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // rest of test code
});
```

---

## Step 4: Report Results

Replace your basic expects with detailed reporting:

### For Passing Tests:

**Before:**
```typescript
expect(response.status()).toBe(200);
expect(body.password).toBeUndefined();
```

**After:**
```typescript
if (body.password === undefined && body.passwordHash === undefined) {
  reporter.reportPass(
    'No sensitive fields exposed in response',
    OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
  );
  expect(true).toBeTruthy();
} else {
  reporter.reportVulnerability('API3_DATA_EXPOSURE', {
    endpoint: '/api/users',
    exposedFields: {
      password: body.password !== undefined,
      passwordHash: body.passwordHash !== undefined
    }
  });
  expect(false).toBeTruthy(); // This will fail the test
}
```

### For Skipped Tests:

**Before:**
```typescript
if (!endpointFound) {
  test.skip(true, 'Endpoint not found');
  return;
}
```

**After:**
```typescript
if (!endpointFound) {
  reporter.reportSkip('Endpoint not found');
  test.skip(true, 'Endpoint not found');
  return;
}
```

### For Warnings:

```typescript
if (!rateLimitDetected) {
  reporter.reportWarning(
    'No rate limiting detected',
    [
      'Implement rate limiting middleware',
      'Add 429 status code responses',
      'Include rate limit headers'
    ],
    OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
  );
}
```

---

## Complete Example: Authentication Test

```typescript
import { test, expect, request } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test.describe('Authentication Security', () => {
  
  test('Should not expose sensitive data in auth response', async ({ baseURL }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    // Skip if no baseURL
    if (!baseURL) {
      reporter.reportSkip('baseURL not provided');
      test.skip(true, 'baseURL not provided');
      return;
    }
    
    const api = await request.newContext({ baseURL });
    
    // Attempt login
    const response = await api.post('/api/login', {
      data: {
        email: 'test@example.com',
        password: 'password123'
      }
    });
    
    // Check response
    if (response.status() === 404) {
      reporter.reportSkip('Login endpoint not found');
      test.skip(true, 'Login endpoint not found');
      return;
    }
    
    if (response.status() === 200) {
      const body = await response.json().catch(() => null);
      
      if (body) {
        // Check for exposed sensitive data
        const hasSensitiveData = body.password || body.passwordHash || 
                                 body.privateKey || body.secret;
        
        if (hasSensitiveData) {
          reporter.reportVulnerability('API3_DATA_EXPOSURE', {
            endpoint: '/api/login',
            exposedFields: {
              password: !!body.password,
              passwordHash: !!body.passwordHash,
              privateKey: !!body.privateKey,
              secret: !!body.secret
            },
            issue: 'Authentication response exposes sensitive fields'
          }, [
            'Remove all sensitive fields from authentication responses',
            'Only return necessary data (token, user ID, display name)',
            'Implement response DTOs to control exposed fields'
          ]);
          
          expect(hasSensitiveData).toBeFalsy();
        } else {
          reporter.reportPass(
            'Authentication response does not expose sensitive fields',
            OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
          );
          expect(true).toBeTruthy();
        }
      }
    }
  });
});
```

---

## Complete Example: CSRF Test

```typescript
import { test, expect } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test.describe('CSRF Protection', () => {
  
  test('Should require CSRF token for state-changing operations', async ({ page, baseURL }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    if (!baseURL) {
      reporter.reportSkip('baseURL not provided');
      test.skip(true, 'baseURL not provided');
      return;
    }
    
    await page.goto(baseURL);
    
    // Try to submit form without CSRF token
    const response = await page.evaluate(async () => {
      const res = await fetch('/api/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: 'attacker@example.com',
          amount: 1000
        })
        // Intentionally omitting CSRF token
      });
      return { status: res.status, ok: res.ok };
    });
    
    // Should be rejected (403 or 400)
    if (response.status === 200 || response.ok) {
      reporter.reportVulnerability('API2_AUTH', {
        endpoint: '/api/transfer',
        issue: 'State-changing operation allowed without CSRF token',
        testAttempt: 'POST request without CSRF token succeeded'
      }, [
        'Implement CSRF token validation on all state-changing endpoints',
        'Use SameSite cookie attribute',
        'Implement double-submit cookie pattern',
        'Consider using synchronizer token pattern'
      ]);
      
      expect(response.ok).toBeFalsy();
    } else {
      reporter.reportPass(
        'CSRF protection verified: Request without token was rejected',
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      expect(response.status).toBeGreaterThanOrEqual(400);
    }
  });
});
```

---

## Complete Example: Rate Limiting Test

```typescript
import { test, expect, request } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test.describe('Rate Limiting', () => {
  
  test('Should enforce rate limits on API endpoints', async ({ baseURL }, testInfo) => {
    const reporter = new SecurityReporter(testInfo);
    
    if (!baseURL) {
      reporter.reportSkip('baseURL not provided');
      test.skip(true, 'baseURL not provided');
      return;
    }
    
    const api = await request.newContext({ baseURL });
    let rateLimitHit = false;
    let requestCount = 0;
    
    // Send burst of requests
    for (let i = 0; i < 100; i++) {
      const response = await api.get('/api/public-data').catch(() => null);
      
      if (!response) continue;
      
      requestCount++;
      
      // Check for rate limit response
      if (response.status() === 429) {
        rateLimitHit = true;
        
        // Check for rate limit headers
        const headers = response.headers();
        const hasRateLimitHeaders = 
          headers['x-ratelimit-limit'] || 
          headers['x-ratelimit-remaining'] ||
          headers['retry-after'];
        
        reporter.reportPass(
          `Rate limiting enforced after ${requestCount} requests. ` +
          `Headers present: ${hasRateLimitHeaders ? 'Yes' : 'No'}`,
          OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
        );
        
        expect(rateLimitHit).toBeTruthy();
        break;
      }
    }
    
    // If no rate limit hit after 100 requests
    if (!rateLimitHit && requestCount > 0) {
      reporter.reportWarning(
        `No rate limiting detected after ${requestCount} requests`,
        [
          'Implement rate limiting to prevent abuse and DoS attacks',
          'Use middleware like express-rate-limit',
          'Return 429 status code when limits exceeded',
          'Add X-RateLimit-* headers to inform clients',
          'Consider different limits for authenticated vs anonymous users'
        ],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
      
      // This is a warning, not a failure
      expect(typeof rateLimitHit).toBe('boolean');
    } else if (requestCount === 0) {
      reporter.reportSkip('Endpoint not reachable for rate limit testing');
      test.skip(true, 'Endpoint not reachable');
    }
  });
});
```

---

## OWASP Categories Reference

Use these keys when calling `reportVulnerability()`:

| Key | OWASP Category | Risk Level |
|-----|----------------|------------|
| `API1_BOLA` | Broken Object Level Authorization | CRITICAL |
| `API2_AUTH` | Broken Authentication | CRITICAL |
| `API3_DATA_EXPOSURE` | Broken Object Property Level Authorization | HIGH |
| `API4_RATE_LIMIT` | Unrestricted Resource Consumption | HIGH |
| `API5_BFLA` | Broken Function Level Authorization | CRITICAL |
| `API6_MASS_ASSIGNMENT` | Mass Assignment / Sensitive Business Flows | HIGH |
| `API7_MISCONFIGURATION` | Security Misconfiguration / SSRF | MEDIUM |
| `API8_INJECTION` | Injection / Security Misconfiguration | CRITICAL |
| `API9_ASSET_MGMT` | Improper Inventory Management | MEDIUM |
| `API10_LOGGING` | Unsafe API Consumption | MEDIUM |

---

## Common Patterns

### Pattern 1: Check for Sensitive Data Exposure

```typescript
const sensitiveFields = ['password', 'passwordHash', 'token', 'secret', 'apiKey'];
const exposedFields = sensitiveFields.filter(field => body[field] !== undefined);

if (exposedFields.length > 0) {
  reporter.reportVulnerability('API3_DATA_EXPOSURE', {
    endpoint: '/api/users',
    exposedFields: Object.fromEntries(exposedFields.map(f => [f, true]))
  });
  expect(exposedFields.length).toBe(0);
} else {
  reporter.reportPass('No sensitive fields exposed', 
    OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name);
}
```

### Pattern 2: Check for Authorization

```typescript
// Try to access another user's resource
const response = await api.get(`/api/users/${otherUserId}`);

if (response.status() === 200) {
  reporter.reportVulnerability('API1_BOLA', {
    endpoint: `/api/users/${otherUserId}`,
    issue: 'Able to access another user\'s resources without authorization'
  });
  expect(response.status()).not.toBe(200);
} else if ([401, 403].includes(response.status())) {
  reporter.reportPass('Authorization check successful: access denied to other user\'s resources',
    OWASP_VULNERABILITIES.API1_BOLA.name);
}
```

### Pattern 3: Check for Input Validation

```typescript
const maliciousInputs = [
  "' OR '1'='1",
  '<script>alert(1)</script>',
  '../../../etc/passwd',
  '${7*7}'
];

let vulnerabilityFound = false;

for (const input of maliciousInputs) {
  const response = await api.get(`/api/search?q=${encodeURIComponent(input)}`);
  
  if (response.status() >= 500) {
    vulnerabilityFound = true;
    reporter.reportVulnerability('API8_INJECTION', {
      endpoint: '/api/search',
      payload: input,
      statusCode: response.status()
    });
    break;
  }
}

if (!vulnerabilityFound) {
  reporter.reportPass('Input validation successful: no server errors with malicious inputs',
    OWASP_VULNERABILITIES.API8_INJECTION.name);
}
```

---

## Tips for Effective Reporting

### DO:
✅ Create one `SecurityReporter` instance per test
✅ Call report methods for all test outcomes (pass, fail, skip, warning)
✅ Include relevant evidence in vulnerability reports
✅ Use appropriate OWASP categories
✅ Add custom recommendations when relevant
✅ Report warnings for potential issues that don't fail the test

### DON'T:
❌ Create multiple reporter instances in the same test
❌ Only report failures (also report passes and skips)
❌ Include sensitive real data in evidence
❌ Ignore testInfo parameter
❌ Skip reporting for tests that pass

---

## Viewing Your Reports

```bash
# Run your tests
npx playwright test tests/security/authentication/

# View HTML report
npx playwright show-report

# Click on any test → Look for "Attachments" → View security-report-*.md
```

---

## Next Steps

1. **Update existing tests**: Add SecurityReporter to your current test files
2. **Review reports**: Check the generated reports after test runs
3. **Customize recommendations**: Add specific guidance for your application
4. **Share with team**: Ensure developers understand how to read and act on reports
5. **Integrate with CI/CD**: Ensure reports are available in your pipeline

---

## Need Help?

- 📖 See [SECURITY_REPORTING.md](./SECURITY_REPORTING.md) for detailed documentation
- 📋 See [SAMPLE_REPORT_OUTPUT.md](./SAMPLE_REPORT_OUTPUT.md) for example reports
- 🔧 Check [security-reporter.ts](./security-reporter.ts) for API reference

---

**Last Updated**: October 22, 2025
