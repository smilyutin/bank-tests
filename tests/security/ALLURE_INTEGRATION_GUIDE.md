# Allure Reporting Integration Guide

## 🎯 Overview

All security tests now support **Allure Reports** for beautiful, interactive test result visualization with:
- ✅ OWASP API Security Top 10 categorization
- 🔴 Risk-based severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- 📊 Trend graphs and historical data
- 📋 Detailed vulnerability reports with evidence
- 🔗 Links to OWASP documentation

## Quick Start

### Run Tests with Allure Reporting

```bash
# Run security tests and generate Allure results
npm run test:sec

# Generate and open Allure report
npm run allure:serve

# Or generate static report
npm run allure:generate
npm run allure:open
```

### View Reports

Once tests run, Allure automatically:
1. Captures all SecurityReporter data
2. Categorizes by severity (blocker, critical, normal, minor)
3. Tags by OWASP category (API1, API2, etc.)
4. Groups by feature and epic
5. Adds links to OWASP references

## 📊 Allure Features

### Automatic Metadata

The `SecurityReporter` automatically adds:

| Metadata | Description | Example |
|----------|-------------|---------|
| **Severity** | blocker, critical, normal, minor, trivial | CRITICAL → blocker |
| **Epic** | OWASP API Security Top 10 | All security tests |
| **Feature** | Test category | Mass assignment, Data exposure |
| **Tags** | OWASP category | API3, API6, API8 |
| **Links** | OWASP documentation | Direct links to cheat sheets |

### Risk Level Mapping

| SecurityReporter | Allure Severity |
|------------------|-----------------|
| CRITICAL | blocker |
| HIGH | critical |
| MEDIUM | normal |
| LOW | minor |
| INFO | trivial |

### Test Status Visualization

- ✅ **PASS** - Green checkmark, security control verified
- **FAIL** - Red X, vulnerability found with full details
- ⚠️ **WARNING** - Yellow triangle, passed but with concerns
- ⏭️ **SKIP** - Gray dash, test couldn't run

## 🎨 Allure Report Features

### Dashboard View

```
╔═══════════════════════════════════════╗
║   OWASP API Security Test Results    ║
╠═══════════════════════════════════════╣
║ Total Tests:        30                ║
║ Passed:             24  (80%)         ║
║ Failed:              2  (7%)          ║
║ Warnings:            3  (10%)         ║
║ Skipped:             1  (3%)          ║
╠═══════════════════════════════════════╣
║ Critical Issues:     0                ║
║ High Risk:           2                ║
║ Medium Risk:         0                ║
║ Low Risk:            3                ║
╚═══════════════════════════════════════╝
```

### Categories View

Allure automatically groups vulnerabilities:
- **Critical Security Issues** - All CRITICAL risk findings
- **High Risk Vulnerabilities** - All HIGH risk findings
- **OWASP API1** - Broken Object Level Authorization
- **OWASP API2** - Broken Authentication
- **OWASP API3** - Data Exposure
- etc.

### Suites View

Tests organized by:
- authorization/ (mass-assignment, data-exposure, idor, roleScoping)
- authentication/ (broken-auth, jwt, bruteforce, session-fixation)
- headers/ (csp, hsts, security-headers, clickjacking)
- input/ (xss, sqli, injection)
- abuse/ (rate-limit, payload-size)

### Timeline View

Visual timeline showing:
- Test execution order
- Duration of each test
- Parallel execution visualization
- Failed test highlighting

### Behaviors View

Tests grouped by:
- **Epic**: OWASP API Security Top 10
- **Feature**: Mass Assignment, Data Exposure, etc.
- **Story**: Individual test scenarios

## 📝 Example Integration

### Before (Without Reporting)

```typescript
test('Check password exposure', async ({ baseURL }) => {
  const response = await api.get('/api/users/123');
  const body = await response.json();
  
  expect(body.password).toBeUndefined();
});
```

### After (With Allure Reporting)

```typescript
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('Check password exposure', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await api.get('/api/users/123');
  const body = await response.json();
  
  if (body.password !== undefined) {
    reporter.reportVulnerability('API3_DATA_EXPOSURE', {
      endpoint: '/api/users/123',
      exposedFields: { password: true },
      issue: 'Password exposed in API response'
    });
    expect(body.password).toBeUndefined();
  } else {
    reporter.reportPass(
      'No sensitive fields exposed',
      OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
    );
  }
});
```

### Allure Report Output

The above test generates an Allure report with:

**Test Details:**
- ✅ Status: PASS
- 🟠 Severity: critical (if failed)
- 🏷️ Epic: OWASP API Security Top 10
- 🏷️ Feature: Data Exposure
- 🏷️ Tag: API3
- 🔗 Links: 2 OWASP references

**Attachments:**
- `security-report-[timestamp].md` - Full markdown report
- Evidence JSON with endpoint and exposed fields

**Description:**
"No sensitive fields exposed in API response. API3:2023 - Broken Object Property Level Authorization verified."

## Advanced Configuration

### Custom Categories

Edit `playwright.config.ts`:

```typescript
categories: [
  {
    name: 'Authentication Failures',
    matchedStatuses: ['failed'],
    messageRegex: '.*API2.*'
  },
  {
    name: 'Injection Vulnerabilities',
    matchedStatuses: ['failed'],
    messageRegex: '.*API8.*'
  }
]
```

### Environment Info

Automatically includes:
- Test Suite: Bank API Security Tests
- Framework: Playwright + OWASP
- Node Version: v20.19.4
- Base URL: (from config)

### Historical Trends

Keep `allure-results/history` folder to see:
- Pass/fail trends over time
- Test duration changes
- Flaky test detection
- Execution time optimization

## 📊 Report Sections

### Overview

- Total execution time
- Pass rate percentage
- Severity distribution pie chart
- Test status bar chart
- Trend graph (with history)

### Suites

- Test files organized by directory
- Pass/fail status per file
- Execution time per suite
- Expandable test details

### Graphs

- **Status** - Pass/Fail/Skip distribution
- **Severity** - Blocker/Critical/Normal/Minor
- **Duration** - Test execution times
- **Timeline** - Chronological execution view
- **Categories** - Custom vulnerability grouping

### Behaviors

- **Epics** - OWASP API Security Top 10
- **Features** - Individual security concerns
- **Stories** - Specific test scenarios

## 🎯 Best Practices

### 1. Always Use SecurityReporter

```typescript
// ✅ Good
const reporter = new SecurityReporter(testInfo);
reporter.reportPass('Test passed');

// ❌ Bad
expect(condition).toBeTruthy(); // No reporting
```

### 2. Provide Evidence

```typescript
// ✅ Good - With evidence
reporter.reportVulnerability('API3_DATA_EXPOSURE', {
  endpoint: '/api/users',
  exposedFields: { password: true },
  responseTime: 150
});

// ❌ Bad - No evidence
reporter.reportVulnerability('API3_DATA_EXPOSURE', {});
```

### 3. Use Correct OWASP Keys

```typescript
// ✅ Good
reporter.reportVulnerability('API3_DATA_EXPOSURE', evidence);

// ❌ Bad
reporter.reportVulnerability('data_exposure', evidence); // Invalid key
```

### 4. Report All Outcomes

```typescript
if (vulnerable) {
  reporter.reportVulnerability(...);
} else if (!endpointFound) {
  reporter.reportSkip('Endpoint not found');
} else if (minorIssue) {
  reporter.reportWarning('Minor concern', recommendations);
} else {
  reporter.reportPass('Security verified');
}
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Security Tests
  run: npm run test:sec
  
- name: Generate Allure Report
  if: always()
  run: npm run allure:generate
  
- name: Publish Allure Report
  if: always()
  uses: simple-elf/allure-report-action@master
  with:
    allure_results: allure-results
    allure_history: allure-history
    
- name: Upload Allure Results
  if: always()
  uses: actions/upload-artifact@v3
  with:
    name: allure-results
    path: allure-results/
```

### GitLab CI

```yaml
test:
  script:
    - npm run test:sec
    - npm run allure:generate
  artifacts:
    paths:
      - allure-report/
    when: always
```

### Jenkins

```groovy
stage('Security Tests') {
  steps {
    sh 'npm run test:sec'
  }
  post {
    always {
      allure([
        includeProperties: false,
        jdk: '',
        results: [[path: 'allure-results']]
      ])
    }
  }
}
```

## 📸 Screenshots

### Main Dashboard
- Summary statistics
- Trend graph
- Severity distribution
- Test duration chart

### Test Details
- Full test steps
- Attachments (security reports)
- Execution logs
- Evidence JSON

### Categories
- Critical Security Issues
- High Risk Vulnerabilities
- By OWASP category

## 🎓 Learning Resources

- [Allure Framework Docs](https://docs.qameta.io/allure/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [Playwright Reporter API](https://playwright.dev/docs/test-reporters)

## 🔍 Troubleshooting

### No Allure Command Found

```bash
# Install Allure command-line tool
npm install -g allure-commandline
# Or use: brew install allure (Mac)
```

### Empty Allure Results

```bash
# Ensure tests are running
npx playwright test tests/security/

# Check allure-results directory
ls -la allure-results/
```

### Old Data in Report

```bash
# Clean old results
rm -rf allure-results allure-report
npm run test:sec
npm run allure:serve
```

---

**🎉 You're all set! Run `npm run allure:serve` to see beautiful security test reports!**
