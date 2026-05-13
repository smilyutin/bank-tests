import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { cspHasDirective, cspHasNonceOrHash, cspHasUnsafeEval, cspHasUnsafeInline, getContentSecurityPolicy } from '../utils/csp';

test('CSP: Content-Security-Policy header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('CSP header-presence probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());
  const cspHeaderPresent = !!csp;

  softCheck(
    testInfo,
    cspHeaderPresent,
    'Content-Security-Policy header should be present'
  );

  if (cspHeaderPresent) {
    reporter.reportPass(
      'Content-Security-Policy header is present.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('CSP: script-src directive is restrictive', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('CSP script-src probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());

  if (!csp) {
    reporter.reportSkip('CSP script-src probe failed because no Content-Security-Policy header was found.');
    test.skip(true, 'No Content-Security-Policy header was found');
    return;
  }

  const hasScriptSrc = cspHasDirective(csp, 'script-src');
  
  softCheck(
    testInfo,
    hasScriptSrc,
    'CSP should include script-src directive'
  );

  if (hasScriptSrc) {
    // Check for unsafe directives
    const hasUnsafeInline = cspHasUnsafeInline(csp);
    const hasUnsafeEval = cspHasUnsafeEval(csp);
    const hasNonceOrHash = cspHasNonceOrHash(csp);

    if (hasUnsafeInline) {
      softCheck(
        testInfo,
        hasNonceOrHash,
        "CSP script-src should avoid 'unsafe-inline' or use nonces/hashes"
      );
    }

    softCheck(
      testInfo,
      !hasUnsafeEval,
      "CSP script-src should not include 'unsafe-eval'"
    );

    if (!hasUnsafeEval && (!hasUnsafeInline || hasNonceOrHash)) {
      reporter.reportPass(
        'CSP script-src is restrictive and avoids unsafe-inline/unsafe-eval.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }
});

test('CSP: default-src is restrictive', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('CSP default-src probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());

  if (!csp) {
    reporter.reportWarning(
      'True vulnerability: CSP default-src probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses.',
        'Define a restrictive default-src directive.',
        'Use deployment checks to block releases missing CSP headers.'
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

    if (!isWildcard) {
      reporter.reportPass(
        'CSP default-src is restrictive.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }
});

test('CSP: object-src is restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('CSP object-src probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());

  if (!csp) {
    reporter.reportWarning(
      'True vulnerability: CSP object-src probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses.',
        "Include object-src 'none' to block plugin object execution.",
        'Use deployment checks to block releases missing CSP headers.'
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

    if (isRestricted) {
      reporter.reportPass(
        "CSP object-src is restricted to 'none'.",
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
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
    reporter.reportSkip('CSP base-uri probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());

  if (!csp) {
    reporter.reportWarning(
      'True vulnerability: CSP base-uri probe failed because no Content-Security-Policy header was found.',
      [
        'Add a Content-Security-Policy header to all HTML responses.',
        "Include base-uri 'self' or base-uri 'none' to prevent base-tag injection.",
        'Use deployment checks to block releases missing CSP headers.'
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

    if (isRestricted) {
      reporter.reportPass(
        'CSP base-uri is restricted to self/none.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }
});

test('CSP: upgrade-insecure-requests directive present (if HTTPS)', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('CSP upgrade-insecure-requests probe could not run because no HTTP response was received from the base page.');
    test.skip(true, 'No HTTP response was received from the base page');
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    reporter.reportWarning(
      'Environment limitation: CSP upgrade-insecure-requests probe could not validate because the target is not using HTTPS.',
      [
        'Run this probe against an HTTPS environment.',
        'Enable TLS in test/staging environments to validate transport security controls.',
        'Add HTTPS readiness checks before running strict header tests.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  const csp = getContentSecurityPolicy(response.headers());

  if (csp) {
    const hasUpgrade = csp.includes('upgrade-insecure-requests');
    
    softCheck(
      testInfo,
      hasUpgrade,
      'CSP should include upgrade-insecure-requests on HTTPS sites'
    );

    if (hasUpgrade) {
      reporter.reportPass(
        'CSP includes upgrade-insecure-requests on HTTPS.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }
});
