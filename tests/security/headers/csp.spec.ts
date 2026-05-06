import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('CSP: Content-Security-Policy header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP header-presence probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  softCheck(
    testInfo,
    !!csp,
    'Content-Security-Policy header should be present'
  );
});

test('CSP: script-src directive is restrictive', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP script-src probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    reporter.reportWarning(
      'CSP script-src probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses',
        'Define at minimum default-src and script-src directives',
        'Use policy-as-code or gateway config checks to prevent CSP regressions'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasScriptSrc = csp.includes('script-src');
  
  softCheck(
    testInfo,
    hasScriptSrc,
    'CSP should include script-src directive'
  );

  if (hasScriptSrc) {
    // Check for unsafe directives
    const hasUnsafeInline = csp.includes("'unsafe-inline'");
    const hasUnsafeEval = csp.includes("'unsafe-eval'");
    const hasNonce = csp.includes("'nonce-");
    const hasHash = csp.includes("'sha256-") || csp.includes("'sha384-");

    if (hasUnsafeInline) {
      softCheck(
        testInfo,
        hasNonce || hasHash,
        "CSP script-src should avoid 'unsafe-inline' or use nonces/hashes"
      );
    }

    softCheck(
      testInfo,
      !hasUnsafeEval,
      "CSP script-src should not include 'unsafe-eval'"
    );
  }
});

test('CSP: default-src is restrictive', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP default-src probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    reporter.reportWarning(
      'CSP default-src probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses',
        'Define a restrictive default-src directive',
        'Use deployment checks to block releases missing CSP headers'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasDefaultSrc = csp.includes('default-src');
  
  if (hasDefaultSrc) {
    // default-src should not be too permissive
    const isWildcard = csp.includes("default-src *") || csp.includes("default-src 'unsafe-inline'");
    
    softCheck(
      testInfo,
      !isWildcard,
      "CSP default-src should not be wildcard (*) or 'unsafe-inline'"
    );
  }
});

test('CSP: object-src is restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP object-src probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    reporter.reportWarning(
      'CSP object-src probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses',
        "Include object-src 'none' to block plugin object execution",
        'Use deployment checks to block releases missing CSP headers'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasObjectSrc = csp.includes('object-src');
  
  if (hasObjectSrc) {
    const isRestricted = csp.includes("object-src 'none'");
    
    softCheck(
      testInfo,
      isRestricted,
      "CSP should restrict object-src to 'none' to prevent Flash/plugin attacks"
    );
  } else {
    softCheck(
      testInfo,
      false,
      "CSP should include object-src 'none' directive"
    );
  }
});

test('CSP: base-uri is restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP base-uri probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    reporter.reportWarning(
      'CSP base-uri probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses',
        "Include base-uri 'self' or base-uri 'none' to prevent base-tag injection",
        'Use deployment checks to block releases missing CSP headers'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const hasBaseUri = csp.includes('base-uri');
  
  if (hasBaseUri) {
    const isRestricted = 
      csp.includes("base-uri 'none'") || 
      csp.includes("base-uri 'self'");
    
    softCheck(
      testInfo,
      isRestricted,
      "CSP base-uri should be restricted to prevent base tag injection"
    );
  }
});

test('CSP: upgrade-insecure-requests directive present (if HTTPS)', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning(
      'CSP upgrade-insecure-requests probe could not run because no HTTP response was received from the base page.',
      [
        'Ensure BASE_URL points to a reachable web application',
        'Stabilize startup/health checks before running header security tests',
        'Fail CI earlier when homepage reachability checks fail'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      'CSP upgrade-insecure-requests probe could not validate because the target is not using HTTPS.',
      [
        'Run this probe against an HTTPS environment',
        'Enable TLS in test/staging environments to validate transport security controls',
        'Add HTTPS readiness checks before running strict header tests'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (csp) {
    const hasUpgrade = csp.includes('upgrade-insecure-requests');
    
    softCheck(
      testInfo,
      hasUpgrade,
      'CSP should include upgrade-insecure-requests on HTTPS sites'
    );
  }
});
