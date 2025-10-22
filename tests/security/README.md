# Security Test Suite

Comprehensive security testing suite covering OWASP API Security Top 10 2023, fuzzing, input anomaly detection, and CI/CD security regression testing.

## 📊 Quick Stats

- **70+ security tests** across 11 categories
- **Full OWASP API Top 10 2023** coverage
- **Allure reporting** with severity levels and trends
- **CI/CD integration** for continuous security validation
- **Historical tracking** for regression detection

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
- **authorization/idor.spec.ts** - Insecure Direct Object Reference protection (OWASP API1)
- **authorization/roleScoping.spec.ts** - Role-based access control validation (OWASP API5)
- **authorization/mass-assignment.spec.ts** - Mass assignment protection (OWASP API6) ✨ NEW
- **authorization/data-exposure.spec.ts** - Excessive data exposure detection (OWASP API3) ✨ NEW
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
- **input/sqli-nosqli.spec.ts** - SQL and NoSQL injection protection (OWASP API8)
- **input/xss.spec.ts** - Cross-Site Scripting (XSS) prevention

### 🎲 Fuzzing (API Fuzzing)
Pushes APIs beyond normal limits to detect crashes and logic breaks:
- **fuzzing/random-inputs.spec.ts** - Random data injection, type confusion (10 payloads) ✨ NEW
- **fuzzing/malformed-json.spec.ts** - Invalid JSON, deep nesting, large payloads (52 variations) ✨ NEW
- **fuzzing/boundary-values.spec.ts** - Min/max values, null handling, array limits (65 test cases) ✨ NEW

### 🔍 Input Anomalies
Targets unsafe handling of special characters, encodings, and uncommon input:
- **input-attack/unicode.spec.ts** - Unicode normalization, homographs, zero-width chars (35 attacks) ✨ NEW
- **input-attack/escape-chars.spec.ts** - SQL/XSS/command injection, escaping (70+ sequences) ✨ NEW
- **input-attack/file-traversal.spec.ts** - Directory traversal, encoding bypass (45 techniques) ✨ NEW

### 🔄 CI/CD Security Regression
Continuous security validation and regression detection:
- **ci/security-regression.spec.ts** - Nightly regression checks (7 critical controls) ✨ NEW
- **ci/token-expiration.spec.ts** - Token lifecycle validation (4 tests) ✨ NEW
- **ci/scan-results-audit.spec.ts** - Historical vulnerability tracking and trends ✨ NEW

### 🔗 Supply Chain
Third-party dependency security:
- **supply-chain/csp-sri.spec.ts** - Subresource Integrity (SRI) for external resources
- **supply-chain/dependency-security.spec.ts** - Package dependency auditing
- **supply-chain/third-party-scripts.spec.ts** - Third-party script validation

## Running Tests

### Run all security tests
```bash
npm run test:sec

# With Allure reporting
npm run test:sec:report
npm run allure:serve
```

### Run specific category
```bash
# Traditional security tests
npx playwright test tests/security/abuse
npx playwright test tests/security/authentication
npx playwright test tests/security/authorization
npx playwright test tests/security/cors
npx playwright test tests/security/crossSiteReqForgery
npx playwright test tests/security/headers
npx playwright test tests/security/input
npx playwright test tests/security/supply-chain

# NEW: Advanced security tests
npx playwright test tests/security/fuzzing
npx playwright test tests/security/input-attack
npx playwright test tests/security/ci
```

### Run single test file
```bash
npx playwright test tests/security/abuse/rate-limit.spec.ts
npx playwright test tests/security/fuzzing/random-inputs.spec.ts
npx playwright test tests/security/ci/security-regression.spec.ts
```

### Generate Allure Reports
```bash
# Generate and view interactive report
npm run allure:serve

# Generate static report
npm run allure:generate
npm run allure:open
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

### OWASP API Security Top 10 2023
- ✅ **API1** - Broken Object Level Authorization (BOLA/IDOR)
- ✅ **API2** - Broken Authentication (JWT, tokens, sessions)
- ✅ **API3** - Broken Object Property Level Authorization (Data Exposure)
- ✅ **API4** - Unrestricted Resource Consumption (Rate Limiting)
- ✅ **API5** - Broken Function Level Authorization (BFLA)
- ✅ **API6** - Mass Assignment
- ✅ **API7** - Security Misconfiguration (Headers, CORS)
- ✅ **API8** - Injection (SQL, NoSQL, XSS, Command, Path Traversal)
- ✅ **API9** - Improper Assets Management
- ✅ **API10** - Insufficient Logging & Monitoring

### Additional Security Testing
- ✅ **Fuzzing** - Random inputs, malformed JSON, boundary values
- ✅ **Input Anomalies** - Unicode attacks, escape sequences, file traversal
- ✅ **CI/CD Integration** - Regression detection, token lifecycle, trend analysis
- ✅ **CSRF Protection** - Token validation and rotation
- ✅ **Supply Chain** - Dependency security, SRI validation

## 📊 Reporting Features

### SecurityReporter
All tests use the comprehensive SecurityReporter for detailed findings:
- ✅ **Pass/Fail/Warning/Skip** statuses
- 🔴 **Risk levels** (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- 📋 **Actionable recommendations** (5-8 per vulnerability)
- 🔧 **Step-by-step remediation** guides
- 📚 **OWASP references** with links
- 📊 **Evidence capture** (JSON payloads)

### Allure Integration
Beautiful interactive reports with:
- Severity-based categorization (blocker, critical, normal, minor)
- OWASP API Top 10 tagging
- Historical trend tracking
- Timeline visualization
- Detailed attachments and evidence

### CI/CD Reports
- Historical test result tracking (last 30 runs)
- Regression detection and alerting
- Security posture trend analysis
- Release quality gates
- OWASP coverage metrics

## Best Practices

1. **Run regularly** - Include in CI/CD pipeline (use `ci/` tests)
2. **Review failures** - Each failure indicates a potential vulnerability
3. **Fix critical/high first** - Prioritize by risk level
4. **Track trends** - Use scan-results-audit for historical analysis
5. **Update regularly** - Keep tests current with new attack vectors
6. **Customize** - Adapt tests to your application's specific needs
7. **Don't skip** - All tests serve important security purposes
8. **Use Allure** - Beautiful reports make findings actionable

## Contributing

When adding new security tests:
1. Place in appropriate category folder
2. **Import SecurityReporter**: `import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter'`
3. **Create reporter instance**: `const reporter = new SecurityReporter(testInfo)`
4. **Report outcomes**:
   - `reporter.reportVulnerability('API*_CATEGORY', evidence)`
   - `reporter.reportPass('description', OWASP.name)`
   - `reporter.reportWarning('description', recommendations)`
   - `reporter.reportSkip('reason')`
5. Use `softCheck()` for backwards compatibility
6. Handle missing endpoints gracefully with `test.skip()`
7. Include clear failure messages with evidence
8. Document the vulnerability being tested
9. Map to OWASP category when applicable

**See:** `ADD_REPORTING_PATTERNS.md` for copy-paste integration examples

## 📚 Documentation

| Document | Purpose |
|----------|----------|
| **README.md** | This file - test suite overview |
| **ALLURE_INTEGRATION_GUIDE.md** | Complete Allure reporting guide |
| **ADD_REPORTING_PATTERNS.md** | Copy-paste patterns for adding SecurityReporter |
| **SECURITY_REPORTING.md** | Full SecurityReporter API reference |
| **SAMPLE_REPORT_OUTPUT.md** | Example security report outputs |
| **QUICK_START_GUIDE.md** | 5-minute integration guide |
| **FUZZING_AND_CI_IMPLEMENTATION.md** | Fuzzing and CI test documentation |
| **IMPLEMENTATION_SUMMARY.md** | Technical implementation details |

## Resources

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Allure Framework Documentation](https://docs.qameta.io/allure/)
