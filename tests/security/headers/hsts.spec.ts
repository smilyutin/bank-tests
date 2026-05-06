import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('HSTS: Strict-Transport-Security header present on HTTPS', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'HSTS presence check could not run because homepage response was not received.',
      [
        'Ensure root endpoint is reachable before running security header tests',
        'Stabilize app startup and health checks in test environment',
        'Fail CI early when baseline app reachability checks fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      `HSTS validation failed because application is served over non-HTTPS URL (${url}).`,
      [
        'Enforce HTTPS in all environments where security tests run',
        'Redirect all HTTP traffic to HTTPS before serving application content',
        'Only emit HSTS header on HTTPS responses after TLS is correctly configured',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const hsts = headers['strict-transport-security'];

  softCheck(
    testInfo,
    !!hsts,
    'Strict-Transport-Security header should be present on HTTPS connections'
  );
});

test('HSTS: max-age is sufficiently long', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'HSTS max-age check could not run because homepage response was not received.',
      [
        'Ensure root endpoint is reachable before running security header tests',
        'Stabilize app startup and health checks in test environment',
        'Fail CI early when baseline app reachability checks fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      `HSTS max-age validation failed because application is served over non-HTTPS URL (${url}).`,
      [
        'Enforce HTTPS in all environments where security tests run',
        'Redirect HTTP to HTTPS and validate TLS certificate chain',
        'Apply HSTS only after HTTPS is consistently enforced',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    reporter.reportWarning(
      'HSTS max-age validation failed because Strict-Transport-Security header is missing.',
      [
        'Add Strict-Transport-Security header to HTTPS responses',
        'Use max-age >= 31536000 (1 year) for strong transport protection',
        'Consider includeSubDomains and preload after validating subdomain HTTPS readiness',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  // Extract max-age value
  const match = hsts.match(/max-age=(\d+)/);
  if (match) {
    const maxAge = parseInt(match[1], 10);
    const oneYear = 31536000; // seconds in a year
    
    softCheck(
      testInfo,
      maxAge >= oneYear,
      `HSTS max-age should be at least 1 year (31536000 seconds), got: ${maxAge}`
    );
  }
});

test('HSTS: includeSubDomains directive present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'HSTS includeSubDomains check could not run because homepage response was not received.',
      [
        'Ensure root endpoint is reachable before running security header tests',
        'Stabilize app startup and health checks in test environment',
        'Fail CI early when baseline app reachability checks fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      `HSTS includeSubDomains validation failed because application is served over non-HTTPS URL (${url}).`,
      [
        'Enforce HTTPS in all environments where security tests run',
        'Redirect HTTP traffic to HTTPS before any authenticated workflow',
        'Apply HSTS and includeSubDomains once HTTPS posture is stable',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    reporter.reportWarning(
      'HSTS includeSubDomains validation failed because Strict-Transport-Security header is missing.',
      [
        'Add Strict-Transport-Security header with includeSubDomains directive',
        'Ensure all subdomains are HTTPS-ready before enabling includeSubDomains',
        'Monitor subdomain TLS health to avoid accidental service lockouts',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasIncludeSubDomains = hsts.toLowerCase().includes('includesubdomains');
  
  softCheck(
    testInfo,
    hasIncludeSubDomains,
    'HSTS should include includeSubDomains directive for comprehensive protection'
  );
});

test('HSTS: preload directive considered', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'HSTS preload assessment could not run because homepage response was not received.',
      [
        'Ensure root endpoint is reachable before running security header tests',
        'Stabilize app startup and health checks in test environment',
        'Fail CI early when baseline app reachability checks fail',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      `HSTS preload assessment failed because application is served over non-HTTPS URL (${url}).`,
      [
        'Enforce HTTPS in all environments where security tests run',
        'Redirect HTTP to HTTPS and validate TLS deployment first',
        'Consider preload only after max-age/includeSubDomains prerequisites are met',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    reporter.reportWarning(
      'HSTS preload assessment failed because Strict-Transport-Security header is missing.',
      [
        'Add Strict-Transport-Security header before evaluating preload readiness',
        'Use long max-age and includeSubDomains to satisfy preload prerequisites',
        'Apply for browser preload list only after full-domain HTTPS readiness is confirmed',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasPreload = hsts.toLowerCase().includes('preload');
  
  // Preload is optional but recommended
  if (!hasPreload) {
    softCheck(
      testInfo,
      true,
      'Consider adding preload directive to HSTS for maximum protection (optional)'
    );
  }
});
