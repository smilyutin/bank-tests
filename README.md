# Bank Tests - Enterprise Security Testing Framework

*Last workflow trigger: 2025-10-24 14:32 UTC*

Comprehensive Playwright TypeScript test suite with **70+ security tests** covering OWASP API Security Top 10 2023, fuzzing, input anomalies, and CI/CD regression testing.

## Quick Start

```bash
# Install dependencies
npm install
npx playwright install

# Run all tests
npm test

# Run security tests with Allure reporting
npm run test:sec
npm run allure:serve
```

## Test Suite Overview

| Category | Tests | Coverage |
|----------|-------|----------|
| **API Tests** | 5+ | User creation, authentication, CRUD |
| **UI Tests** | 3+ | Signup flows, navigation |
| **Security Tests** | 70+ | OWASP API Top 10 2023, Fuzzing, CI/CD |

## Security Testing (70+ Tests)

### OWASP API Security Top 10 2023 - Full Coverage

- **API1** - Broken Object Level Authorization (IDOR)
- **API2** - Broken Authentication (JWT, sessions, tokens)
- **API3** - Data Exposure (sensitive fields)
- **API4** - Rate Limiting & Resource Consumption
- **API5** - Broken Function Level Authorization
- **API6** - Mass Assignment
- **API7** - Security Misconfiguration (headers, CORS)
- **API8** - Injection (SQL, XSS, path traversal, Unicode)
- **API9** - Improper Assets Management
- **API10** - Insufficient Logging & Monitoring

### Advanced Security Testing

- **Fuzzing** (10 tests) - Random inputs, malformed JSON, boundary values
- **Input Anomalies** (14 tests) - Unicode, escape sequences, file traversal
- **CI/CD Regression** (15 tests) - Automated security validation, token lifecycle

### Security Test Categories

```
tests/security/
├── abuse/              Rate limiting, payload size
├── authentication/     JWT, sessions, cookies, brute-force
├── authorization/      IDOR, RBAC, mass assignment, data exposure
├── cors/               CORS policy validation
├── crossSiteReqForgery/ CSRF token validation
├── headers/            CSP, HSTS, X-Frame-Options, etc.
├── input/              XSS, SQL injection, file upload
├── fuzzing/            Random inputs, malformed JSON, boundaries
├── input-attack/       Unicode, escape chars, path traversal
├── ci/                 Regression, token expiry, audit
└── supply-chain/       Dependency security, SRI
```

## Reporting & Visualization

### Allure Reports
Beautiful interactive reports with:
- Dashboard with pass/fail statistics
- Severity-based categorization (blocker, critical, normal, minor)
- OWASP API Top 10 tagging
- Historical trend tracking
- Direct links to OWASP documentation

```bash
# Generate and view Allure report
npm run allure:serve
  or 
npm run report:allure

# Generate static report
npm run allure:generate
npm run allure:open
```

### SecurityReporter
Every test includes comprehensive reporting:
- **Status**: Pass/Fail/Warning/Skip
- **Risk Level**: CRITICAL/HIGH/MEDIUM/LOW/INFO
- **Recommendations**: 5-8 actionable fixes
- **Remediation Steps**: Step-by-step guides
- **OWASP References**: Direct documentation links
- **Evidence**: JSON payload captures

## Running Tests

### All Tests
```bash
npm test                    # All tests (API, UI, Security)
npm run test:api           # API tests only
npm run test:ui            # UI tests only
npm run test:sec           # Security tests only
```

### Security Test Suites
```bash
# Traditional security tests
npx playwright test tests/security/authentication
npx playwright test tests/security/authorization
npx playwright test tests/security/headers

# Advanced security tests
npx playwright test tests/security/fuzzing          # API fuzzing
npx playwright test tests/security/input-attack     # Input anomalies
npx playwright test tests/security/ci               # CI/CD regression

# Specific test file
npx playwright test tests/security/fuzzing/random-inputs.spec.ts
```

### With Reporting
```bash
# Run with Allure reporting
npm run test:sec:report
npm run allure:serve

# CI/CD with historical tracking
npx playwright test tests/security/ci/scan-results-audit.spec.ts
```

## Configuration

### Environment Variables
```bash
# Base configuration
BASE_URL=http://localhost:5001        # Target API URL

# Security test modes
SECURITY_SOFT=1                       # Warnings instead of failures

# CI/CD integration
GIT_COMMIT=abc123                     # For historical tracking
GIT_BRANCH=main                       # For trend analysis
```

### Defaults
- **Base URL**: http://localhost:5001
- **API docs**: http://localhost:5001/api/docs/
- **Test mode**: Strict (failures fail the run)

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Tests
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run security tests
        run: npm run test:sec
      
      - name: Security regression check
        run: npx playwright test tests/security/ci/
      
      - name: Generate Allure report
        if: always()
        run: npm run allure:generate
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: allure-report/
```

### Test Modes for CI

**PR Checks (Soft Mode)**
```bash
SECURITY_SOFT=1 npm run test:sec
```
- Warnings instead of failures
- Visibility without blocking merges
- Good for initial security assessment

**Main Branch (Strict Mode)**
```bash
npm run test:sec
```
- Failures block deployment
- Enforce security standards
- Release quality gates

## 📚 Documentation

Comprehensive documentation in `tests/security/`:

| Document | Purpose |
|----------|---------|
| [README.md](tests/security/README.md) | Test suite overview |
| [ALLURE_INTEGRATION_GUIDE.md](tests/security/ALLURE_INTEGRATION_GUIDE.md) | Allure reporting guide |
| [FUZZING_AND_CI_IMPLEMENTATION.md](tests/security/FUZZING_AND_CI_IMPLEMENTATION.md) | Fuzzing & CI tests |
| [ADD_REPORTING_PATTERNS.md](tests/security/ADD_REPORTING_PATTERNS.md) | Copy-paste integration patterns |
| [SECURITY_REPORTING.md](tests/security/SECURITY_REPORTING.md) | SecurityReporter API reference |
| [QUICK_START_GUIDE.md](tests/security/QUICK_START_GUIDE.md) | 5-minute integration guide |

## 🎓 Key Features

✅ **70+ Security Tests** covering all OWASP API Security Top 10 2023  
✅ **Allure Reporting** with beautiful interactive dashboards  
✅ **SecurityReporter** with detailed vulnerability information  
✅ **CI/CD Integration** for continuous security validation  
✅ **Historical Tracking** with trend analysis and regression detection  
✅ **Fuzzing & Input Anomalies** for comprehensive attack surface testing  
✅ **Non-Destructive** - safe to run against production  
✅ **Graceful Degradation** - skips when endpoints not found  

## 📖 Resources

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [Playwright Documentation](https://playwright.dev/)
- [Allure Framework](https://docs.qameta.io/allure/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)

## 🤝 Contributing

See [tests/security/README.md](tests/security/README.md#contributing) for guidelines on adding new security tests with SecurityReporter integration.

---

**🎉 Ready to test? Run `npm run test:sec && npm run allure:serve` to see your security posture!**
