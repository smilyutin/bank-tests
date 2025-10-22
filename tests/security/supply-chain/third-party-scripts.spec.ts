import { test } from '@playwright/test';
import { softCheck } from '../utils';

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
  await page.goto('/');
  
  // Step 1: Identify analytics and tracking scripts
  const blockingAnalytics = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const analytics = scripts.filter(script => {
      const src = script.getAttribute('src') || '';
      return (
        src.includes('google-analytics') ||
        src.includes('googletagmanager') ||
        src.includes('analytics') ||
        src.includes('tracking')
      );
    });
    
    // Step 2: Check for missing async/defer attributes
    return analytics
      .filter(script => !script.hasAttribute('async') && !script.hasAttribute('defer'))
      .map(script => script.getAttribute('src'));
  });

  // Step 3: Verify analytics scripts use non-blocking loading
  softCheck(
    testInfo,
    blockingAnalytics.length === 0,
    `Analytics scripts should use async/defer: ${blockingAnalytics.join(', ') || 'none'}`
  );
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
  await page.goto('/');
  
  const externalDomains = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const domains = new Set<string>();
    
    scripts.forEach(script => {
      const src = script.getAttribute('src');
      if (src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//'))) {
        try {
          const url = new URL(src.startsWith('//') ? 'https:' + src : src);
          domains.add(url.hostname);
        } catch (e) {
          // Invalid URL
        }
      }
    });
    
    return Array.from(domains);
  });

  // More than 5 external domains might indicate excessive third-party scripts
  softCheck(
    testInfo,
    externalDomains.length <= 5,
    `High number of external script domains (${externalDomains.length}): review for necessity`
  );
});

test('Third-party scripts: CSP allows only trusted domains', async ({ page }, testInfo) => {
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
  }
});

test('Third-party scripts: no inline event handlers', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const inlineHandlers = await page.evaluate(() => {
    const elements = Array.from(document.querySelectorAll('*'));
    const handlers: string[] = [];
    
    elements.forEach(el => {
      const attrs = Array.from(el.attributes);
      attrs.forEach(attr => {
        if (attr.name.startsWith('on')) {
          handlers.push(`${el.tagName}.${attr.name}`);
        }
      });
    });
    
    return handlers.slice(0, 10); // Limit output
  });

  softCheck(
    testInfo,
    inlineHandlers.length === 0,
    `Inline event handlers found (security risk): ${inlineHandlers.join(', ') || 'none'}`
  );
});

test('Third-party scripts: tracking scripts respect privacy', async ({ page }, testInfo) => {
  await page.goto('/');
  
  // Check for privacy-respecting analytics
  const hasPrivacyConsent = await page.evaluate(() => {
    const body = document.body.innerHTML;
    return (
      body.includes('cookie consent') ||
      body.includes('privacy policy') ||
      body.includes('gdpr') ||
      document.querySelector('[data-cookieconsent]') !== null
    );
  });

  // Check for tracking scripts
  const hasTracking = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    return scripts.some(script => {
      const src = script.getAttribute('src') || '';
      return (
        src.includes('google-analytics') ||
        src.includes('facebook.net') ||
        src.includes('doubleclick') ||
        src.includes('tracking')
      );
    });
  });

  if (hasTracking) {
    softCheck(
      testInfo,
      hasPrivacyConsent,
      'If using tracking scripts, implement cookie consent/privacy notice'
    );
  }
});

test('Third-party scripts: no deprecated or unmaintained libraries', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const deprecatedLibs = await page.evaluate(() => {
    const deprecated = [
      'jquery-1.', // Very old jQuery versions
      'jquery-2.',
      'angular.js/1.2', // Very old Angular
      'moment.js', // Deprecated in favor of modern alternatives
    ];
    
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    return scripts
      .map(s => s.getAttribute('src'))
      .filter(src => src && deprecated.some(dep => src.includes(dep)));
  });

  softCheck(
    testInfo,
    deprecatedLibs.length === 0,
    `Deprecated libraries detected: ${deprecatedLibs.join(', ') || 'none'}`
  );
});
