# Security Testing Quick Reference

## 🚀 Quick Commands

```bash
# Run all security tests
npm run test:sec

# Run specific categories
npm run test:sec:fuzzing          # Fuzzing tests (10)
npm run test:sec:input-attack     # Input anomaly tests (14)
npm run test:sec:ci               # CI/CD regression tests (15)
npm run test:sec:regression       # Regression check only
npm run test:sec:audit            # Historical audit only

# Generate reports
npm run allure:serve              # Interactive Allure report
npm run allure:generate           # Static report
npx playwright show-report        # HTML report
```

## 📁 Test File Structure

```
tests/security/
├── fuzzing/                   # 10 tests - API fuzzing
│   ├── random-inputs.spec.ts
│   ├── malformed-json.spec.ts
│   └── boundary-values.spec.ts
│
├── input-attack/              # 14 tests - Input anomalies
│   ├── unicode.spec.ts
│   ├── escape-chars.spec.ts
│   └── file-traversal.spec.ts
│
├── ci/                        # 15 tests - CI/CD regression
│   ├── security-regression.spec.ts
│   ├── token-expiration.spec.ts
│   └── scan-results-audit.spec.ts
│
├── authorization/             # 5 tests - Access control
│   ├── idor.spec.ts
│   ├── roleScoping.spec.ts
│   ├── mass-assignment.spec.ts      ✨ NEW
│   └── data-exposure.spec.ts        ✨ NEW
│
├── authentication/            # 9 tests - Auth & sessions
├── headers/                   # 8 tests - Security headers
├── input/                     # 3 tests - Injection
├── abuse/                     # 2 tests - Rate limiting
├── cors/                      # 1 test - CORS
├── crossSiteReqForgery/       # 2 tests - CSRF
└── supply-chain/              # 3 tests - Dependencies
```

## 🎯 OWASP API Security Top 10 Mapping

| OWASP | Category | Tests | Files |
|-------|----------|-------|-------|
| **API1** | BOLA/IDOR | 3 | `authorization/idor.spec.ts`, `ci/security-regression.spec.ts` |
| **API2** | Auth | 13 | `authentication/*`, `ci/token-expiration.spec.ts` |
| **API3** | Data Exposure | 4 | `authorization/data-exposure.spec.ts`, `ci/security-regression.spec.ts` |
| **API4** | Rate Limiting | 4 | `abuse/rate-limit.spec.ts`, `fuzzing/boundary-values.spec.ts` |
| **API5** | BFLA | 2 | `authorization/roleScoping.spec.ts` |
| **API6** | Mass Assignment | 3 | `authorization/mass-assignment.spec.ts` |
| **API7** | Misconfig | 10 | `headers/*`, `cors/*`, `ci/security-regression.spec.ts` |
| **API8** | Injection | 32 | `input/*`, `fuzzing/*`, `input-attack/*` |
| **API9** | Assets | 3 | `supply-chain/*` |
| **API10** | Logging | 1 | `ci/scan-results-audit.spec.ts` |

## 💡 Common Use Cases

### Add SecurityReporter to Any Test

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('My test', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  // Test logic here...
  
  if (vulnerabilityFound) {
    reporter.reportVulnerability('API8_INJECTION', {
      endpoint: '/api/users',
      payload: 'malicious input',
      issue: 'SQL injection detected'
    });
    expect(vulnerabilityFound).toBeFalsy();
  } else {
    reporter.reportPass(
      'No vulnerabilities detected',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});
```

### Run Tests in CI/CD

```yaml
# GitHub Actions
- name: Security Tests
  run: npm run test:sec
  
- name: Regression Check
  run: npm run test:sec:regression
  
- name: Generate Report
  if: always()
  run: npm run allure:generate
```

### Check Historical Trends

```bash
# Run audit to see trends
npm run test:sec:audit

# Check allure-results/ directory for history
ls -la allure-results/

# View test-results/security-test-history.json
cat test-results/security-test-history.json | jq
```

## 📊 OWASP Category Keys

```typescript
// Use these keys with reportVulnerability()
'API1_BOLA'              // Broken Object Level Authorization
'API2_AUTH'              // Broken Authentication
'API3_DATA_EXPOSURE'     // Excessive Data Exposure
'API4_RATE_LIMIT'        // Unrestricted Resource Consumption
'API5_BFLA'              // Broken Function Level Authorization
'API6_MASS_ASSIGNMENT'   // Mass Assignment
'API7_MISCONFIGURATION'  // Security Misconfiguration
'API8_INJECTION'         // Injection
'API9_ASSET_MGMT'        // Improper Assets Management
'API10_LOGGING'          // Insufficient Logging
```

## 🎨 Risk Levels

```typescript
SecurityRiskLevel.CRITICAL  // 🔴 Fix immediately
SecurityRiskLevel.HIGH      // 🟠 Fix before release
SecurityRiskLevel.MEDIUM    // 🟡 Fix soon
SecurityRiskLevel.LOW       // 🟢 Address when possible
SecurityRiskLevel.INFO      // ℹ️  Informational
```

## 📋 Test Status Types

```typescript
SecurityTestStatus.PASS     // ✅ Test passed
SecurityTestStatus.FAIL     // ❌ Vulnerability found
SecurityTestStatus.WARNING  // ⚠️  Concern detected
SecurityTestStatus.SKIP     // ⏭️  Test skipped
```

## 🔍 Quick Troubleshooting

### Tests Skipping?
```bash
# Check baseURL is set
echo $BASE_URL

# Or set it explicitly
BASE_URL=http://localhost:5001 npm run test:sec
```

### No Allure Reports?
```bash
# Install Allure command-line
npm install -g allure-commandline

# Or use Homebrew (Mac)
brew install allure

# Generate report
npm run allure:serve
```

### Empty Test Results?
```bash
# Check allure-results directory
ls -la allure-results/

# Run tests first
npm run test:sec

# Then generate report
npm run allure:serve
```

### TypeScript Errors?
```bash
# Check imports are correct
# Should be: '../security-reporter' (relative path)

# Ensure testInfo parameter is added
# test('name', async ({ page }, testInfo) => { ... })
```

## 📖 Documentation Quick Links

| Need to... | Read this... |
|------------|--------------|
| Add reporting to tests | `ADD_REPORTING_PATTERNS.md` |
| Understand Allure | `ALLURE_INTEGRATION_GUIDE.md` |
| See example reports | `SAMPLE_REPORT_OUTPUT.md` |
| Get started in 5 min | `QUICK_START_GUIDE.md` |
| Full API reference | `SECURITY_REPORTING.md` |
| Learn about fuzzing | `FUZZING_AND_CI_IMPLEMENTATION.md` |
| Technical details | `IMPLEMENTATION_SUMMARY.md` |

## 🎯 Test Execution Order

### For New Projects
1. Run all security tests: `npm run test:sec`
2. Review Allure report: `npm run allure:serve`
3. Fix CRITICAL and HIGH issues
4. Re-run tests
5. Establish baseline: `npm run test:sec:audit`

### For Existing Projects
1. Run regression check: `npm run test:sec:regression`
2. Run historical audit: `npm run test:sec:audit`
3. Review new findings
4. Fix regressions immediately
5. Run full suite: `npm run test:sec`

### For CI/CD
1. PR checks: `SECURITY_SOFT=1 npm run test:sec`
2. Main branch: `npm run test:sec` (strict)
3. Nightly: `npm run test:sec:regression`
4. Weekly: `npm run test:sec:audit`
5. Pre-release: All tests + audit

## 🔢 Test Counts by Category

```
Fuzzing:           10 tests  (random, malformed, boundary)
Input Anomalies:   14 tests  (unicode, escape, traversal)
CI/Regression:     15 tests  (regression, tokens, audit)
Authorization:      5 tests  (IDOR, RBAC, mass-assign, data)
Authentication:     9 tests  (JWT, session, cookies, brute)
Headers:            8 tests  (CSP, HSTS, XFO, etc.)
Input:              3 tests  (XSS, SQLi, file upload)
Abuse:              2 tests  (rate limit, payload size)
CORS:               1 test   (CORS policy)
CSRF:               2 tests  (token validation)
Supply Chain:       3 tests  (dependencies, SRI)
───────────────────────────────────────────────────
Total:             72 tests
```

## ⚡ Performance Tips

```bash
# Run tests in parallel (default)
npm run test:sec

# Run specific file only
npx playwright test tests/security/fuzzing/random-inputs.spec.ts

# Run tests matching pattern
npx playwright test -g "OWASP"

# Run with specific workers
npx playwright test tests/security/ --workers=4

# Debug mode (headed)
npx playwright test tests/security/fuzzing/ --headed --debug
```

## 🎓 Best Practices Checklist

- [ ] Always add `testInfo` parameter to tests
- [ ] Create `SecurityReporter` instance at start
- [ ] Report outcomes (pass/fail/skip/warning)
- [ ] Include evidence in vulnerability reports
- [ ] Use correct OWASP category keys
- [ ] Handle missing endpoints gracefully
- [ ] Map to OWASP when applicable
- [ ] Add to CI/CD pipeline
- [ ] Review Allure reports regularly
- [ ] Track trends with scan-results-audit

## 🆘 Getting Help

1. Check relevant documentation in `tests/security/`
2. Review `ADD_REPORTING_PATTERNS.md` for examples
3. Inspect `security-reporter.ts` for implementation
4. Look at existing tests for patterns
5. Check Allure report for detailed findings

---

**💡 Pro Tip:** Bookmark this file for quick reference during test development!
