import { test } from '@playwright/test';
import { SecurityHeadersProbe } from '../sec-objects/headers/security-headers.logic';

/**
 * Security Headers Tests
 *
 * These tests verify that the application implements proper security headers
 * to protect against various web vulnerabilities and information disclosure.
 *
 * Security Risks Addressed:
 * 1. Missing security headers (CSP, X-Frame-Options, etc.)
 * 2. Information disclosure through server headers
 * 3. Deprecated security headers (X-XSS-Protection)
 * 4. Improper caching of sensitive content
 *
 * Expected Behavior:
 * - Essential security headers should be present
 * - No sensitive server information should be exposed
 * - Deprecated headers should be removed or properly configured
 * - Sensitive content should not be cached
 */

const probe = new SecurityHeadersProbe();

test('Security headers: comprehensive check', async ({ page }, testInfo) => {
  await probe.checkHomepageSecurityHeaders(page, testInfo);
});

test('Security headers: no information disclosure', async ({ page }, testInfo) => {
  await probe.checkInformationDisclosure(page, testInfo);
});

test('Security headers: X-XSS-Protection removed or set to 0', async ({ page }, testInfo) => {
  await probe.checkXssProtection(page, testInfo);
});

test('Security headers: Cache-Control for sensitive pages', async ({ page }, testInfo) => {
  await probe.checkSensitivePageCacheControl(page, testInfo);
});

test('Security headers: no cache for authenticated resources', async ({ baseURL }, testInfo) => {
  if (!baseURL) {
    // Keep the existing environment limitation semantics inside the helper.
  }
  await probe.checkAuthenticatedResourceCacheControl(baseURL?.toString() || '', testInfo);
});

test('Security Headers (OWASP API7): comprehensive security and fingerprinting check', async ({ baseURL }, testInfo) => {
  await probe.checkComprehensiveFingerprinting(baseURL?.toString() || '', testInfo);
});
