# Security Test Reporting Patterns

## 🎯 Quick Reference

This guide shows you exactly how to add SecurityReporter to any security test file.

## 📋 Step-by-Step Pattern

### 1. Add Imports

```typescript
// At the top of your test file
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
```

### 2. Add testInfo Parameter

```typescript
// Before:
test('My security test', async ({ page }) => {

// After:
test('My security test', async ({ page }, testInfo) => {
```

### 3. Create Reporter Instance

```typescript
test('My security test', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // rest of test
});
```

### 4. Add Reporting Based on Test Type

## 🔐 Authorization Tests (IDOR, BOLA)

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('IDOR: users cannot access other users resources', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // Login and get token
  const attempt = await tryLogin(request, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Could not login or obtain token');
    test.skip(true, 'Could not login');
    return;
  }
  
  // Try to access another user's resource
  const res = await request.get(`/api/users/${otherUserId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  // Check if vulnerability exists
  if (res.status() === 200) {
    reporter.reportVulnerability('API1_BOLA', {
      endpoint: `/api/users/${otherUserId}`,
      statusCode: res.status(),
      issue: 'Able to access another user\'s resource without authorization'
    });
    expect(res.status()).not.toBe(200);
  } else if ([401, 403].includes(res.status())) {
    reporter.reportPass(
      'Authorization correctly blocks access to other users\' resources',
      OWASP_VULNERABILITIES.API1_BOLA.name
    );
  }
});
```

## 🔑 Authentication Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('Broken Authentication: weak password', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  // Try to create account with weak password
  const res = await request.post('/api/register', {
    data: { email: 'test@example.com', password: '123' }
  });
  
  if (res.status() === 201 || res.status() === 200) {
    reporter.reportVulnerability('API2_AUTH', {
      endpoint: '/api/register',
      password: '123',
      issue: 'Weak password accepted - no password strength validation'
    }, [
      'Implement password strength requirements (min 8 chars, mixed case, numbers, symbols)',
      'Use libraries like zxcvbn for password strength checking',
      'Display password strength meter to users'
    ]);
    expect(res.status()).toBeGreaterThanOrEqual(400);
  } else {
    reporter.reportPass(
      'Weak passwords correctly rejected',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});
```

## 🛡️ CSRF Protection Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('CSRF: state-changing operation requires token', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  await page.goto('/');
  
  // Try state-changing operation without CSRF token
  const response = await page.evaluate(async () => {
    const res = await fetch('/api/transfer', {
      method: 'POST',
      body: JSON.stringify({ to: 'attacker@example.com', amount: 1000 })
    });
    return { status: res.status, ok: res.ok };
  });
  
  if (response.ok || response.status === 200) {
    reporter.reportVulnerability('API2_AUTH', {
      endpoint: '/api/transfer',
      issue: 'State-changing operation succeeded without CSRF token'
    });
    expect(response.ok).toBeFalsy();
  } else {
    reporter.reportPass(
      'CSRF protection verified: request without token rejected',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});
```

## 🔒 Security Headers Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('Security Headers: CSP present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const response = await page.goto('/');
  if (!response) {
    reporter.reportSkip('No response received');
    test.skip(true, 'No response');
    return;
  }
  
  const headers = response.headers();
  const hasCSP = !!headers['content-security-policy'];
  
  if (!hasCSP) {
    reporter.reportWarning(
      'Content-Security-Policy header missing',
      [
        'Add CSP header to prevent XSS attacks',
        'Start with restrictive policy: default-src \'self\'',
        'Use nonces for inline scripts',
        'Report violations to a logging endpoint'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'Content-Security-Policy header present',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});
```

## 💉 Injection/XSS Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('XSS: input sanitization', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const xssPayload = '<script>alert(1)</script>';
  
  // Submit XSS payload
  await page.fill('#input', xssPayload);
  await page.click('#submit');
  
  // Check if payload executed
  const dialogAppeared = await page.evaluate(() => {
    return document.body.innerHTML.includes('<script>alert(1)</script>');
  });
  
  if (dialogAppeared) {
    reporter.reportVulnerability('API8_INJECTION', {
      payload: xssPayload,
      issue: 'XSS payload not sanitized - reflected in HTML'
    });
    expect(dialogAppeared).toBeFalsy();
  } else {
    reporter.reportPass(
      'XSS payload correctly sanitized',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});
```

## ⚡ Rate Limiting Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('Rate Limiting: DoS protection', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  let rateLimitHit = false;
  
  for (let i = 0; i < 100; i++) {
    const res = await request.get('/api/public');
    
    if (res.status() === 429) {
      rateLimitHit = true;
      break;
    }
  }
  
  if (rateLimitHit) {
    reporter.reportPass(
      'Rate limiting enforced after burst of requests',
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportWarning(
      'No rate limiting detected after 100 requests',
      [
        'Implement rate limiting middleware',
        'Return 429 status when limits exceeded',
        'Add rate limit headers (X-RateLimit-*)',
        'Set appropriate limits per endpoint'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});
```

## 🔗 CORS Tests

**Pattern:**

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('CORS: restricted origins', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const res = await request.get('/api/data', {
    headers: { 'Origin': 'https://evil.com' }
  });
  
  const allowOrigin = res.headers()['access-control-allow-origin'];
  
  if (allowOrigin === '*') {
    reporter.reportWarning(
      'CORS allows all origins (*) - potential security risk',
      [
        'Restrict CORS to specific trusted origins',
        'Use allowlist of known domains',
        'Avoid wildcards in production',
        'Implement origin validation'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  } else {
    reporter.reportPass(
      'CORS properly restricts origins',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});
```

## 📚 All OWASP Keys Reference

```typescript
// Use these exact keys with reportVulnerability()

'API1_BOLA'          // Broken Object Level Authorization
'API2_AUTH'          // Broken Authentication
'API3_DATA_EXPOSURE' // Excessive Data Exposure
'API4_RATE_LIMIT'    // Lack of Resources & Rate Limiting
'API5_BFLA'          // Broken Function Level Authorization
'API6_MASS_ASSIGNMENT'// Mass Assignment
'API7_MISCONFIGURATION'// Security Misconfiguration
'API8_INJECTION'     // Injection
'API9_ASSET_MGMT'    // Improper Assets Management
'API10_LOGGING'      // Insufficient Logging
```

## 🎯 Common Patterns Summary

### For Vulnerability Found:
```typescript
reporter.reportVulnerability('API*_CATEGORY', {
  endpoint: '/api/path',
  issue: 'What went wrong',
  ...evidence
});
expect(failCondition).toBeFalsy();
```

### For Test Passed:
```typescript
reporter.reportPass(
  'What was verified',
  OWASP_VULNERABILITIES.API*_CATEGORY.name
);
expect(passCondition).toBeTruthy();
```

### For Test Skipped:
```typescript
reporter.reportSkip('Why test was skipped');
test.skip(true, 'Reason');
return;
```

### For Warning:
```typescript
reporter.reportWarning(
  'Issue description',
  ['Recommendation 1', 'Recommendation 2'],
  OWASP_VULNERABILITIES.API*_CATEGORY.name
);
```

## ✅ Checklist for Each Test File

- [ ] Import SecurityReporter
- [ ] Add testInfo parameter to all tests
- [ ] Create reporter instance at start of each test
- [ ] Report SKIP for tests that can't run
- [ ] Report PASS when security control works
- [ ] Report FAIL/Vulnerability when issue found
- [ ] Report WARNING for minor concerns
- [ ] Include evidence in vulnerability reports
- [ ] Use correct OWASP category key

## 🚀 Quick Commands

```bash
# Test a single file after adding reporting
npx playwright test tests/security/path/to/file.spec.ts

# Generate Allure report
npm run allure:serve

# See console output with reporting
npx playwright test tests/security/ --reporter=list
```

---

**Copy these patterns to add comprehensive security reporting to any test!** 🎉
