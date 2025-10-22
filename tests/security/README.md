# Security Test Suite

Comprehensive security testing suite covering OWASP Top 10 and common web application vulnerabilities.

## Test Categories

### 🚨 Abuse
Tests for protection against abuse and resource exhaustion:
- **abuse/payload-size.spec.ts** - Validates server rejects oversized payloads
- **abuse/rate-limit.spec.ts** - Ensures API implements rate limiting

### 🔌 API Security
OWASP API Top 10 security tests:
- **api/api-top10.spec.ts** - Mass assignment, broken object level authorization

### 🔐 Authentication
Tests for secure authentication mechanisms:
- **authentication/auth.cookies.spec.ts** - Cookie security flags (HttpOnly, Secure, SameSite)
- **authentication/broken-authentication.spec.ts** - Weak passwords, default credentials
- **authentication/bruteforce-lockout.spec.ts** - Brute-force protection and account lockout
- **authentication/inspect-cookies.spec.ts** - Cookie and storage inspection after login
- **authentication/jwt.spec.ts** - JWT token security and validation
- **authentication/logout-clears-session.spec.ts** - Session cleanup on logout
- **authentication/session-fixation.spec.ts** - Protection against session fixation attacks
- **authentication/ui-login-generic-errors.spec.ts** - User enumeration protection
- **authentication/xss-csp-storage.spec.ts** - Token storage security, CSP

### 🔒 Authorization
Tests for proper access control:
- **authorization/idor.spec.ts** - Insecure Direct Object Reference protection
- **authorization/roleScoping.spec.ts** - Role-based access control validation
- **authorization/rbac-matrix.json** - Role permission test scenarios

### 🌐 CORS
Cross-Origin Resource Sharing security:
- **cors/cors.spec.ts** - CORS policy validation, origin whitelisting, preflight handling

### 🛡️ CSRF (Cross-Site Request Forgery)
Protection against CSRF attacks:
- **csrf.spec.ts** - Basic CSRF token validation
- **crossSiteReqForgery/csrf-rotation.spec.ts** - Token rotation on sensitive actions
- **crossSiteReqForgery/missing-invalid-token.spec.ts** - Token requirement enforcement

### 📋 Headers
Security header validation:
- **headers.spec.ts** - Basic security headers check
- **headers/clickjacking.spec.ts** - X-Frame-Options, frame-ancestors
- **headers/csp.spec.ts** - Content Security Policy validation
- **headers/hsts.spec.ts** - Strict-Transport-Security (HSTS)
- **headers/nosniff.spec.ts** - X-Content-Type-Options
- **headers/permissions-policy.spec.ts** - Permissions-Policy (Feature-Policy)
- **headers/referrer-policy.spec.ts** - Referrer-Policy validation
- **headers/security-headers.spec.ts** - Comprehensive header audit

### 📝 Input Validation
Protection against injection attacks:
- **input/file-upload.spec.ts** - File upload security (extensions, size, path traversal)
- **input/sqli-nosqli.spec.ts** - SQL and NoSQL injection protection
- **input/xss.spec.ts** - Cross-Site Scripting (XSS) prevention

### 🔗 Supply Chain
Third-party dependency security:
- **supply-chain/csp-sri.spec.ts** - Subresource Integrity (SRI) for external resources
- **supply-chain/dependency-security.spec.ts** - Package dependency auditing
- **supply-chain/third-party-scripts.spec.ts** - Third-party script validation

## Running Tests

### Run all security tests
```bash
npm run test:sec
```

### Run specific category
```bash
npx playwright test tests/security/abuse
npx playwright test tests/security/api
npx playwright test tests/security/authentication
npx playwright test tests/security/authorization
npx playwright test tests/security/cors
npx playwright test tests/security/crossSiteReqForgery
npx playwright test tests/security/headers
npx playwright test tests/security/input
npx playwright test tests/security/supply-chain
```

### Run single test file
```bash
npx playwright test tests/security/abuse/rate-limit.spec.ts
```

## Configuration

### Environment Variables
- `BASE_URL` - Target application URL (default: http://localhost:5001)
- `SECURITY_SOFT=1` - Run tests in soft mode (warnings instead of failures)
- `SECURITY_LOGIN_PATH` - Custom login endpoint path
- `SECURITY_TOKEN_FIELD` - Custom token field name in responses
- `SECURITY_TOKEN_COOKIE` - Custom token cookie name
- `SKIP_SECURE_CHECK=1` - Skip Secure cookie flag check (for local dev)

### Soft Mode
When `SECURITY_SOFT=1` is set, security test failures are reported as warnings with annotations instead of failing the test suite. Useful for:
- Initial security assessment
- CI/CD where you want visibility without blocking deployments
- Gradual security hardening

## Test Utilities

Located in `utils.ts`:
- `ensureTestUser()` - Creates or retrieves test user
- `tryLogin()` - Attempts login with credentials
- `parseSetCookieFlags()` - Parses cookie security flags
- `softCheck()` - Conditional assertion based on SECURITY_SOFT mode

## Coverage

This test suite covers:
- ✅ OWASP Top 10 2021
- ✅ Authentication & Session Management
- ✅ Access Control (Authorization)
- ✅ Input Validation & Sanitization
- ✅ Cryptographic Security
- ✅ Security Headers
- ✅ API Security
- ✅ Supply Chain Security
- ✅ Business Logic Abuse

## Best Practices

1. **Run regularly** - Include in CI/CD pipeline
2. **Review failures** - Each failure indicates a potential vulnerability
3. **Update regularly** - Keep tests current with new attack vectors
4. **Customize** - Adapt tests to your application's specific needs
5. **Don't skip** - All tests serve important security purposes

## Contributing

When adding new security tests:
1. Place in appropriate category folder
2. Use `softCheck()` for assertions
3. Handle missing endpoints gracefully with `test.skip()`
4. Include clear failure messages
5. Document the vulnerability being tested

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Content Security Policy Reference](https://content-security-policy.com/)
