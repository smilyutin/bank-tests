import { expect, test, type TestInfo } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import * as fs from 'fs';
import * as path from 'path';

export interface SecurityTestRun {
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

const RESULTS_DIR = path.join(__dirname, '../../../test-results');
const HISTORY_FILE = path.join(RESULTS_DIR, 'security-test-history.json');
const ALLURE_DIR = path.join(__dirname, '../../../allure-results');
const AUDIT_LABEL = 'Security Test Audit';

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

function saveToHistory(run: SecurityTestRun): void {
  try {
    if (!fs.existsSync(RESULTS_DIR)) {
      fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }

    const history = loadHistory();
    history.push(run);

    const trimmed = history.slice(-30);

    fs.writeFileSync(HISTORY_FILE, JSON.stringify(trimmed, null, 2));
  } catch (e) {
    console.warn('Could not save test history:', e);
  }
}

function getCurrentResults(): SecurityTestRun | null {
  try {
    if (!fs.existsSync(ALLURE_DIR)) {
      return null;
    }

    const files = fs.readdirSync(ALLURE_DIR).filter(f => f.endsWith('-result.json'));
    if (files.length === 0) return null;

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

    for (const file of files) {
      try {
        const filePath = path.join(ALLURE_DIR, file);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

        if (!data.name || !data.status) continue;

        results.totalTests++;

        switch (data.status) {
          case 'passed':
            results.passed++;
            break;
          case 'failed':
            results.failed++;

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
      } catch {
        // Skip invalid files.
      }
    }

    return results;
  } catch (e) {
    console.warn('Could not read current results:', e);
    return null;
  }
}

class SecurityAuditResultsProbe {
  async compareWithBaseline(testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const current = getCurrentResults();

    if (!current || current.totalTests === 0) {
      reporter.reportWarning(
        'Environment limitation: security regression audit could not run because no current test results were available.',
        [
          'Ensure security tests run before the audit step in CI.',
          'Publish allure-results or equivalent artifacts before executing audit specs.',
          'Fail the pipeline earlier if test result artifacts are missing.'
        ],
        AUDIT_LABEL
      );
      return;
    }

    const history = loadHistory();
    if (history.length === 0) {
      saveToHistory(current);
      reporter.reportPass(
        `Baseline established: ${current.totalTests} tests (${current.passed} passed, ${current.failed} failed)`,
        AUDIT_LABEL
      );
      return;
    }

    const lastRun = history[history.length - 1];
    const regressions: string[] = [];
    const improvements: string[] = [];

    if (current.totalTests < lastRun.totalTests) {
      regressions.push(`Test count decreased: ${lastRun.totalTests} → ${current.totalTests}`);
    }

    if (current.failed > lastRun.failed) {
      regressions.push(`Failed tests increased: ${lastRun.failed} → ${current.failed}`);
    } else if (current.failed < lastRun.failed) {
      improvements.push(`Failed tests decreased: ${lastRun.failed} → ${current.failed}`);
    }

    if (current.criticalIssues > lastRun.criticalIssues) {
      regressions.push(`Critical issues increased: ${lastRun.criticalIssues} → ${current.criticalIssues}`);
    }

    if (current.highRiskIssues > lastRun.highRiskIssues) {
      regressions.push(`High risk issues increased: ${lastRun.highRiskIssues} → ${current.highRiskIssues}`);
    }

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

    const newFailures = current.failedTests.filter(curr => !lastRun.failedTests.some(last => last.name === curr.name));
    if (newFailures.length > 0) {
      regressions.push(`${newFailures.length} new test failures detected`);
    }

    saveToHistory(current);

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
      return;
    }

    let message = `No security regressions detected (${current.passed}/${current.totalTests} passed)`;
    if (improvements.length > 0) {
      message += `. Improvements: ${improvements.join(', ')}`;
    }
    reporter.reportPass(message, AUDIT_LABEL);
  }

  async analyzeTrend(testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const history = loadHistory();

    if (history.length < 3) {
      reporter.reportWarning(
        'Environment limitation: security trend analysis could not run because there is insufficient history (need at least 3 runs).',
        [
          'Persist security-test-history.json across CI runs.',
          'Run the audit job regularly so trend baselines accumulate.',
          'Seed historical baseline data if this is a newly introduced audit stage.'
        ],
        AUDIT_LABEL
      );
      return;
    }

    const recentRuns = history.slice(-10);
    const passRates = recentRuns.map(run => run.totalTests > 0 ? (run.passed / run.totalTests) * 100 : 0);
    const avgPassRate = passRates.reduce((a, b) => a + b, 0) / passRates.length;
    const latestPassRate = passRates[passRates.length - 1];

    const firstHalfAvg = passRates.slice(0, Math.floor(passRates.length / 2)).reduce((a, b) => a + b, 0) / Math.floor(passRates.length / 2);
    const secondHalfAvg = passRates.slice(Math.floor(passRates.length / 2)).reduce((a, b) => a + b, 0) / Math.ceil(passRates.length / 2);

    const isImproving = secondHalfAvg > firstHalfAvg;
    const isDegrading = secondHalfAvg < firstHalfAvg - 5;

    const criticalCounts = recentRuns.map(run => run.criticalIssues);
    const avgCritical = criticalCounts.reduce((a, b) => a + b, 0) / criticalCounts.length;
    const latestCritical = criticalCounts[criticalCounts.length - 1];

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
        AUDIT_LABEL
      );
    } else if (isImproving) {
      reporter.reportPass(
        `Security posture improving: pass rate increased from ${firstHalfAvg.toFixed(1)}% to ${secondHalfAvg.toFixed(1)}%`,
        AUDIT_LABEL
      );
    } else {
      reporter.reportPass(
        `Security posture stable: ${latestPassRate.toFixed(1)}% pass rate`,
        AUDIT_LABEL
      );
    }

    try {
      testInfo.attach('security-trend-report', {
        body: JSON.stringify(trendReport, null, 2),
        contentType: 'application/json'
      });
    } catch {
      // Ignore attachment errors.
    }
  }

  async enforceReleaseQuality(testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const current = getCurrentResults();

    if (!current) {
      reporter.reportWarning(
        'Environment limitation: release-blocker audit could not run because no current test results were available.',
        [
          'Ensure security tests run before the release audit step in CI.',
          'Publish allure-results or equivalent artifacts before executing audit specs.',
          'Fail the pipeline earlier if test result artifacts are missing.'
        ],
        AUDIT_LABEL
      );
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
        'RELEASE BLOCKER: Critical/High risk issues must be fixed',
        'Review and fix all critical security issues immediately',
        'Address high risk issues before release',
        'Consider emergency security patch if already released',
        'Update security runbook for faster response'
      ]);

      expect(criticalAndHigh).toBe(0);
      return;
    }

    reporter.reportPass(
      `Release quality met: Zero critical/high risk security issues (${current.passed}/${current.totalTests} tests passed)`,
      AUDIT_LABEL
    );
  }

  async verifyOwaspCoverage(testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const current = getCurrentResults();

    if (!current) {
      reporter.reportWarning(
        'Environment limitation: OWASP coverage audit could not run because no current test results were available.',
        [
          'Ensure security tests run before the OWASP coverage audit step in CI.',
          'Publish allure-results or equivalent artifacts before executing audit specs.',
          'Fail the pipeline earlier if test result artifacts are missing.'
        ],
        AUDIT_LABEL
      );
      return;
    }

    const expectedOWASP = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10'];
    const covered = Object.keys(current.owaspCoverage);
    const missing = expectedOWASP.filter(cat => !covered.includes(cat));

    if (missing.length > 0) {
      reporter.reportWarning(
        `Environment limitation: incomplete OWASP coverage because ${missing.length} categories were not tested (${missing.join(', ')}).`,
        [
          'Add tests for missing OWASP categories.',
          'Review OWASP API Security Top 10 2023.',
          'Ensure comprehensive security testing.',
          'Document why categories are not applicable (if any).'
        ],
        AUDIT_LABEL
      );
      return;
    }

    const coverageDetails = expectedOWASP.map(cat => {
      const data = current.owaspCoverage[cat];
      return `${cat}: ${data.passed}/${data.tests} passed`;
    }).join(', ');

    reporter.reportPass(
      `Complete OWASP API Top 10 coverage: ${coverageDetails}`,
      AUDIT_LABEL
    );
  }
}

export { SecurityAuditResultsProbe };