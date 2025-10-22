import { test, expect } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Security Scan Results Audit (CI/CD Integration)
 * 
 * These tests compare current security test results against historical
 * data to detect regressions, track trends, and ensure security posture
 * is improving over time.
 * 
 * Security Risks Addressed:
 * 1. Undetected security regressions
 * 2. Gradual degradation of security posture
 * 3. Fixed vulnerabilities being reintroduced
 * 4. Lack of security metrics and trends
 * 5. Missing accountability for security issues
 * 
 * Expected Behavior:
 * - Track test pass/fail rates over time
 * - Alert on new failures
 * - Celebrate improvements
 * - Maintain audit trail
 * - Generate trend reports
 * 
 * Usage:
 *   - Run after security tests: npm run test:sec && npm run audit:results
 *   - Run in CI: Automatic comparison with baseline
 *   - Run weekly: Generate trend reports
 */

/**
 * Historical results file path
 */
const RESULTS_DIR = path.join(__dirname, '../../../test-results');
const HISTORY_FILE = path.join(RESULTS_DIR, 'security-test-history.json');

/**
 * Interface for historical test results
 */
interface SecurityTestRun {
  timestamp: string;
  commit?: string;
  branch?: string;
  totalTests: number;
  passed: number;
  failed: number;
  skipped: number;
  warnings: number;
  criticalIssues: number;
  highRiskIssues: number;
  mediumRiskIssues: number;
  lowRiskIssues: number;
  owaspCoverage: {
    [key: string]: {
      tests: number;
      passed: number;
      failed: number;
    };
  };
  failedTests: Array<{
    name: string;
    category: string;
    risk: string;
    issue: string;
  }>;
}

/**
 * Load historical test results
 */
function loadHistory(): SecurityTestRun[] {
  try {
    if (fs.existsSync(HISTORY_FILE)) {
      const data = fs.readFileSync(HISTORY_FILE, 'utf-8');
      return JSON.parse(data);
    }
  } catch (e) {
    console.warn('Could not load test history:', e);
  }
  return [];
}

/**
 * Save test results to history
 */
function saveToHistory(run: SecurityTestRun): void {
  try {
    // Ensure directory exists
    if (!fs.existsSync(RESULTS_DIR)) {
      fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }
    
    const history = loadHistory();
    history.push(run);
    
    // Keep only last 30 runs
    const trimmed = history.slice(-30);
    
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(trimmed, null, 2));
  } catch (e) {
    console.warn('Could not save test history:', e);
  }
}

/**
 * Get latest test results from Allure or Playwright report
 */
function getCurrentResults(): SecurityTestRun | null {
  try {
    // Try to read from allure-results
    const allureDir = path.join(__dirname, '../../../allure-results');
    
    if (!fs.existsSync(allureDir)) {
      return null;
    }
    
    // Read all result JSON files
    const files = fs.readdirSync(allureDir)
      .filter(f => f.endsWith('-result.json'));
    
    if (files.length === 0) {
      return null;
    }
    
    const results: SecurityTestRun = {
      timestamp: new Date().toISOString(),
      commit: process.env.GIT_COMMIT || process.env.GITHUB_SHA || 'unknown',
      branch: process.env.GIT_BRANCH || process.env.GITHUB_REF_NAME || 'unknown',
      totalTests: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      warnings: 0,
      criticalIssues: 0,
      highRiskIssues: 0,
      mediumRiskIssues: 0,
      lowRiskIssues: 0,
      owaspCoverage: {},
      failedTests: []
    };
    
    // Parse each result file
    for (const file of files) {
      try {
        const filePath = path.join(allureDir, file);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        
        if (!data.name || !data.status) continue;
        
        results.totalTests++;
        
        // Count by status
        switch (data.status) {
          case 'passed':
            results.passed++;
            break;
          case 'failed':
            results.failed++;
            
            // Extract risk level from labels
            let riskLevel = 'MEDIUM';
            if (data.labels) {
              const severityLabel = data.labels.find((l: any) => l.name === 'severity');
              if (severityLabel) {
                switch (severityLabel.value) {
                  case 'blocker':
                    results.criticalIssues++;
                    riskLevel = 'CRITICAL';
                    break;
                  case 'critical':
                    results.highRiskIssues++;
                    riskLevel = 'HIGH';
                    break;
                  case 'normal':
                    results.mediumRiskIssues++;
                    riskLevel = 'MEDIUM';
                    break;
                  case 'minor':
                    results.lowRiskIssues++;
                    riskLevel = 'LOW';
                    break;
                }
              }
              
              // Extract OWASP category
              const tagLabel = data.labels.find((l: any) => l.name === 'tag');
              if (tagLabel && tagLabel.value) {
                const owasp = tagLabel.value;
                if (!results.owaspCoverage[owasp]) {
                  results.owaspCoverage[owasp] = { tests: 0, passed: 0, failed: 0 };
                }
                results.owaspCoverage[owasp].tests++;
                results.owaspCoverage[owasp].failed++;
              }
            }
            
            results.failedTests.push({
              name: data.name,
              category: data.fullName || data.name,
              risk: riskLevel,
              issue: data.statusDetails?.message || 'Test failed'
            });
            break;
          case 'skipped':
            results.skipped++;
            break;
        }
        
        // Track OWASP coverage for passed tests too
        if (data.status === 'passed' && data.labels) {
          const tagLabel = data.labels.find((l: any) => l.name === 'tag');
          if (tagLabel && tagLabel.value) {
            const owasp = tagLabel.value;
            if (!results.owaspCoverage[owasp]) {
              results.owaspCoverage[owasp] = { tests: 0, passed: 0, failed: 0 };
            }
            results.owaspCoverage[owasp].tests++;
            results.owaspCoverage[owasp].passed++;
          }
        }
      } catch (e) {
        // Skip invalid files
      }
    }
    
    return results;
  } catch (e) {
    console.warn('Could not read current results:', e);
    return null;
  }
}

/**
 * Test: Compare current results with baseline
 * 
 * Purpose: Detects security test regressions by comparing current
 * test results with historical baseline.
 * 
 * Security Impact: Catching regressions early prevents:
 * - Reintroduction of fixed vulnerabilities
 * - Degradation of security posture over time
 * - Shipping releases with new security issues
 * - Loss of security improvements
 */
test('Audit: no security test regressions', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const current = getCurrentResults();
  
  if (!current || current.totalTests === 0) {
    reporter.reportSkip('No current test results available for audit');
    test.skip(true, 'No test results available');
    return;
  }
  
  const history = loadHistory();
  
  if (history.length === 0) {
    // First run - save baseline
    saveToHistory(current);
    reporter.reportPass(
      `Baseline established: ${current.totalTests} tests (${current.passed} passed, ${current.failed} failed)`,
      'Security Test Audit'
    );
    return;
  }
  
  // Compare with last successful run
  const lastRun = history[history.length - 1];
  
  // Check for regressions
  const regressions: string[] = [];
  const improvements: string[] = [];
  
  // Overall test count changed?
  if (current.totalTests < lastRun.totalTests) {
    regressions.push(`Test count decreased: ${lastRun.totalTests} → ${current.totalTests}`);
  }
  
  // More failures?
  if (current.failed > lastRun.failed) {
    regressions.push(`Failed tests increased: ${lastRun.failed} → ${current.failed}`);
  } else if (current.failed < lastRun.failed) {
    improvements.push(`Failed tests decreased: ${lastRun.failed} → ${current.failed}`);
  }
  
  // More critical issues?
  if (current.criticalIssues > lastRun.criticalIssues) {
    regressions.push(`Critical issues increased: ${lastRun.criticalIssues} → ${current.criticalIssues}`);
  }
  
  if (current.highRiskIssues > lastRun.highRiskIssues) {
    regressions.push(`High risk issues increased: ${lastRun.highRiskIssues} → ${current.highRiskIssues}`);
  }
  
  // Check OWASP category regressions
  for (const category in lastRun.owaspCoverage) {
    const last = lastRun.owaspCoverage[category];
    const curr = current.owaspCoverage[category];
    
    if (!curr) {
      regressions.push(`${category} tests missing (had ${last.tests} tests)`);
    } else if (curr.failed > last.failed) {
      regressions.push(`${category} failures increased: ${last.failed} → ${curr.failed}`);
    } else if (curr.failed < last.failed) {
      improvements.push(`${category} failures decreased: ${last.failed} → ${curr.failed}`);
    }
  }
  
  // Check for new test failures
  const newFailures = current.failedTests.filter(curr => 
    !lastRun.failedTests.some(last => last.name === curr.name)
  );
  
  if (newFailures.length > 0) {
    regressions.push(`${newFailures.length} new test failures detected`);
  }
  
  // Save current results to history
  saveToHistory(current);
  
  // Report findings
  if (regressions.length > 0) {
    reporter.reportVulnerability('API7_MISCONFIGURATION', {
      regressions,
      newFailures: newFailures.map(f => f.name),
      currentStats: {
        total: current.totalTests,
        passed: current.passed,
        failed: current.failed,
        critical: current.criticalIssues,
        high: current.highRiskIssues
      },
      previousStats: {
        total: lastRun.totalTests,
        passed: lastRun.passed,
        failed: lastRun.failed,
        critical: lastRun.criticalIssues,
        high: lastRun.highRiskIssues
      }
    }, [
      'Review recent code changes for security regressions',
      'Fix new test failures before merging',
      'Run security tests in CI before merge',
      'Investigate why tests that previously passed are now failing',
      'Consider reverting changes that introduced regressions'
    ]);
    expect(regressions.length).toBe(0);
  } else {
    let message = `No security regressions detected (${current.passed}/${current.totalTests} passed)`;
    if (improvements.length > 0) {
      message += `. Improvements: ${improvements.join(', ')}`;
    }
    
    reporter.reportPass(message, 'Security Test Audit');
  }
});

/**
 * Test: Security trend analysis
 * 
 * Purpose: Analyzes security test trends over time to identify
 * patterns and overall trajectory.
 */
test('Audit: security posture trending positively', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const history = loadHistory();
  
  if (history.length < 3) {
    reporter.reportSkip('Insufficient history for trend analysis (need at least 3 runs)');
    test.skip(true, 'Insufficient history');
    return;
  }
  
  // Calculate trend over last 10 runs
  const recentRuns = history.slice(-10);
  
  // Calculate average pass rate
  const passRates = recentRuns.map(run => 
    run.totalTests > 0 ? (run.passed / run.totalTests) * 100 : 0
  );
  
  const avgPassRate = passRates.reduce((a, b) => a + b, 0) / passRates.length;
  const latestPassRate = passRates[passRates.length - 1];
  
  // Check if pass rate is improving
  const firstHalfAvg = passRates.slice(0, Math.floor(passRates.length / 2))
    .reduce((a, b) => a + b, 0) / Math.floor(passRates.length / 2);
  const secondHalfAvg = passRates.slice(Math.floor(passRates.length / 2))
    .reduce((a, b) => a + b, 0) / Math.ceil(passRates.length / 2);
  
  const isImproving = secondHalfAvg > firstHalfAvg;
  const isDegrading = secondHalfAvg < firstHalfAvg - 5; // 5% threshold
  
  // Calculate critical issue trend
  const criticalCounts = recentRuns.map(run => run.criticalIssues);
  const avgCritical = criticalCounts.reduce((a, b) => a + b, 0) / criticalCounts.length;
  const latestCritical = criticalCounts[criticalCounts.length - 1];
  
  // Generate trend report
  const trendReport = {
    avgPassRate: avgPassRate.toFixed(1) + '%',
    latestPassRate: latestPassRate.toFixed(1) + '%',
    trend: isImproving ? 'improving' : (isDegrading ? 'degrading' : 'stable'),
    avgCriticalIssues: avgCritical.toFixed(1),
    latestCriticalIssues: latestCritical,
    runsAnalyzed: recentRuns.length
  };
  
  if (isDegrading) {
    reporter.reportWarning(
      `Security posture degrading: pass rate declined from ${firstHalfAvg.toFixed(1)}% to ${secondHalfAvg.toFixed(1)}%`,
      [
        'Review recent code changes affecting security',
        'Allocate resources to fix failing tests',
        'Add security requirements to definition of done',
        'Increase security review rigor',
        'Consider security-focused sprint'
      ],
      'Security Test Audit'
    );
  } else if (isImproving) {
    reporter.reportPass(
      `Security posture improving: pass rate increased from ${firstHalfAvg.toFixed(1)}% to ${secondHalfAvg.toFixed(1)}%`,
      'Security Test Audit'
    );
  } else {
    reporter.reportPass(
      `Security posture stable: ${latestPassRate.toFixed(1)}% pass rate`,
      'Security Test Audit'
    );
  }
  
  // Attach trend report
  try {
    testInfo.attach('security-trend-report', {
      body: JSON.stringify(trendReport, null, 2),
      contentType: 'application/json'
    });
  } catch (e) {
    // Ignore attachment errors
  }
});

/**
 * Test: Critical and high risk issues must be zero
 * 
 * Purpose: Enforces a policy that critical and high risk security
 * issues must be resolved before release.
 */
test('Audit: zero critical/high risk issues for release', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const current = getCurrentResults();
  
  if (!current) {
    reporter.reportSkip('No current test results available');
    test.skip(true, 'No test results available');
    return;
  }
  
  const criticalAndHigh = current.criticalIssues + current.highRiskIssues;
  
  if (criticalAndHigh > 0) {
    const criticalTests = current.failedTests.filter(t => t.risk === 'CRITICAL');
    const highTests = current.failedTests.filter(t => t.risk === 'HIGH');
    
    reporter.reportVulnerability('API7_MISCONFIGURATION', {
      criticalIssues: current.criticalIssues,
      highRiskIssues: current.highRiskIssues,
      totalBlockers: criticalAndHigh,
      criticalTests: criticalTests.map(t => t.name),
      highTests: highTests.map(t => t.name)
    }, [
      '🚨 RELEASE BLOCKER: Critical/High risk issues must be fixed',
      'Review and fix all critical security issues immediately',
      'Address high risk issues before release',
      'Consider emergency security patch if already released',
      'Update security runbook for faster response'
    ]);
    
    expect(criticalAndHigh).toBe(0);
  } else {
    reporter.reportPass(
      `Release quality met: Zero critical/high risk security issues (${current.passed}/${current.totalTests} tests passed)`,
      'Security Test Audit'
    );
  }
});

/**
 * Test: OWASP coverage completeness
 * 
 * Purpose: Ensures all OWASP API Security Top 10 categories are
 * covered by tests.
 */
test('Audit: complete OWASP API Top 10 coverage', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  const current = getCurrentResults();
  
  if (!current) {
    reporter.reportSkip('No current test results available');
    test.skip(true, 'No test results available');
    return;
  }
  
  const expectedOWASP = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10'];
  const covered = Object.keys(current.owaspCoverage);
  const missing = expectedOWASP.filter(cat => !covered.includes(cat));
  
  if (missing.length > 0) {
    reporter.reportWarning(
      `Incomplete OWASP coverage: ${missing.length} categories not tested (${missing.join(', ')})`,
      [
        'Add tests for missing OWASP categories',
        'Review OWASP API Security Top 10 2023',
        'Ensure comprehensive security testing',
        'Document why categories are not applicable (if any)'
      ],
      'Security Test Audit'
    );
  } else {
    const coverageDetails = expectedOWASP.map(cat => {
      const data = current.owaspCoverage[cat];
      return `${cat}: ${data.passed}/${data.tests} passed`;
    }).join(', ');
    
    reporter.reportPass(
      `Complete OWASP API Top 10 coverage: ${coverageDetails}`,
      'Security Test Audit'
    );
  }
});
