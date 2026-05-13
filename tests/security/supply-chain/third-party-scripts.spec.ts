import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { getInlineEventHandlers, pageBodyContainsAnyText, pageHasAnySelector, queryElements } from '../utils/dom';

/**
 * Third-Party Scripts Security Tests
 * 
 * These tests verify that third-party scripts and external resources
 * are properly secured and configured to prevent supply chain attacks
 * and maintain application performance.
 * 
 * Security Risks Addressed:
 * 1. Blocking third-party scripts affecting page load performance
 * 2. Excessive external domains increasing attack surface
 * 3. Insecure CSP policies allowing untrusted scripts
 * 4. Inline event handlers creating XSS vulnerabilities
 * 5. Privacy violations through tracking without consent
 * 6. Deprecated libraries with known vulnerabilities
 * 
 * Expected Behavior:
 * - Analytics scripts should use async/defer attributes
 * - External domains should be limited and trusted
 * - CSP should restrict script sources explicitly
 * - No inline event handlers should be present
 * - Privacy consent should be implemented for tracking
 * - Only maintained libraries should be used
 */

/**
 * Test: Analytics scripts use async/defer attributes
 * 
 * Purpose: Verifies that analytics and tracking scripts use async or defer
 * attributes to prevent blocking page load performance.
 * 
 * Security Impact: Blocking scripts can lead to:
 * - Poor user experience due to slow page loads
 * - Third-party script failures affecting core functionality
 * - Increased attack surface through external dependencies
 * - Performance degradation
 * 
 * Test Strategy:
 * 1. Identify analytics and tracking scripts
 * 2. Check for async/defer attributes
 * 3. Verify non-blocking script loading
 */
test('Third-party scripts: analytics scripts use async/defer', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  // Identify analytics and tracking scripts loaded by the page.
  const blockingAnalytics = (await queryElements(page, 'script[src]'))
    .filter(script => {
      const src = script.src || '';
      return (
        src.includes('google-analytics') ||
        src.includes('googletagmanager') ||
        src.includes('analytics') ||
        src.includes('tracking')
      );
    })
    .filter(script => !script.async && !script.defer)
    .map(script => script.src);

  // Verify that analytics scripts load in a non-blocking way.
  softCheck(
    testInfo,
    blockingAnalytics.length === 0,
    `Analytics scripts should use async/defer: ${blockingAnalytics.join(', ') || 'none'}`
  );

  if (blockingAnalytics.length === 0) {
    reporter.reportPass(
      'Analytics scripts use async/defer and do not block page load.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Limited external domains
 * 
 * Purpose: Verifies that the application doesn't load scripts from
 * excessive external domains, reducing attack surface.
 * 
 * Security Impact: Too many external domains can lead to:
 * - Increased attack surface through multiple dependencies
 * - Supply chain attacks through compromised CDNs
 * - Performance degradation from multiple requests
 * - Privacy concerns through excessive tracking
 * 
 * Test Strategy:
 * 1. Identify all external script domains
 * 2. Count total external domains
 * 3. Verify reasonable limit is maintained
 */
test('Third-party scripts: limited to necessary domains', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const externalDomains = Array.from(new Set(
    (await queryElements(page, 'script[src]'))
      .map(script => script.src)
      .filter((src): src is string => !!src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')))
      .map(src => {
        try {
          const url = new URL(src.startsWith('//') ? 'https:' + src : src);
          return url.hostname;
        } catch (e) {
          return '';
        }
      })
      .filter(Boolean)
  ));

  if (externalDomains.length === 0) {
    reporter.reportPass(
      'No external script domains were detected.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportWarning(
    `Security concern: external script domains were detected (${externalDomains.length}): ${externalDomains.join(', ')}.`,
    [
      'Review whether each external script domain is strictly necessary.',
      'Prefer self-hosted scripts or a small explicit allowlist of trusted domains.',
      'Require CSP script-src allowlists and SRI for any unavoidable third-party resources.'
    ],
    OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
  );
});

test('Third-party scripts: CSP allows only trusted domains', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (csp) {
    // Check if script-src has wildcard
    const hasWildcard = csp.includes("script-src *") || csp.includes("script-src 'unsafe-inline'");
    
    softCheck(
      testInfo,
      !hasWildcard,
      'CSP script-src should not use wildcards - enumerate trusted domains explicitly'
    );

    if (!hasWildcard) {
      reporter.reportPass(
        'CSP script-src allows only trusted domains and avoids wildcards.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
  }
});

test('Third-party scripts: no inline event handlers', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/').catch(() => null);

  if (!response) {
    reporter.reportSkip('Base page is not reachable; unable to inspect DOM for inline event handlers.');
    test.skip(true, 'Base page is not reachable');
    return;
  }
  
  const inlineHandlers = await getInlineEventHandlers(page);

  if (inlineHandlers.length > 0) {
    reporter.reportWarning(
      `True vulnerability: inline event handlers were found: ${inlineHandlers.join(', ')}`,
      [
        'Remove inline event handlers (onclick, onerror, onload, etc.) from HTML markup.',
        'Bind events using external JavaScript modules (addEventListener) after DOM load.',
        'Enforce CSP without unsafe-inline and use nonces/hashes for any required inline code.',
        'Add CI checks to block new on* attributes in templates and rendered views.'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportPass(
    'No inline DOM event handlers detected on the evaluated page.',
    OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
  );
});

test('Third-party scripts: tracking scripts respect privacy', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  // Check for privacy-respecting analytics
  const hasPrivacyConsent = (await pageBodyContainsAnyText(page, ['cookie consent', 'privacy policy', 'gdpr'])) ||
    await pageHasAnySelector(page, ['[data-cookieconsent]']);

  // Check for tracking scripts
  const hasTracking = (await queryElements(page, 'script[src]')).some(script => {
    const src = script.src || '';
    return (
      src.includes('google-analytics') ||
      src.includes('facebook.net') ||
      src.includes('doubleclick') ||
      src.includes('tracking')
    );
  });

  if (hasTracking) {
    softCheck(
      testInfo,
      hasPrivacyConsent,
      'If using tracking scripts, implement cookie consent/privacy notice'
    );

    if (hasPrivacyConsent) {
      reporter.reportPass(
        'Tracking scripts are accompanied by visible privacy consent or notice.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }
  } else {
    reporter.reportPass(
      'No tracking scripts were detected on the evaluated page.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

test('Third-party scripts: no deprecated or unmaintained libraries', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const deprecated = [
    'jquery-1.', // Very old jQuery versions
    'jquery-2.',
    'angular.js/1.2', // Very old Angular
    'moment.js', // Deprecated in favor of modern alternatives
  ];

  const deprecatedLibs = (await queryElements(page, 'script[src]'))
    .map(script => script.src)
    .filter((src): src is string => !!src && deprecated.some(dep => src.includes(dep)));

  softCheck(
    testInfo,
    deprecatedLibs.length === 0,
    `Deprecated libraries detected: ${deprecatedLibs.join(', ') || 'none'}`
  );

  if (deprecatedLibs.length === 0) {
    reporter.reportPass(
      'No deprecated or unmaintained libraries were detected in third-party scripts.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});
