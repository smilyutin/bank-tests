import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { queryElements } from '../utils/dom';

/**
 * Content Security Policy (CSP) and Subresource Integrity (SRI) Tests
 * 
 * These tests verify that the application implements proper CSP and SRI
 * protections to prevent supply chain attacks and ensure resource integrity.
 * 
 * Security Risks Addressed:
 * 1. External scripts without integrity verification
 * 2. External stylesheets without integrity verification
 * 3. Weak integrity hash algorithms
 * 4. Missing crossorigin attributes with SRI
 * 5. Insecure CDN resources over HTTP
 * 6. Untrusted CDN sources
 * 
 * Expected Behavior:
 * - External scripts should have SRI integrity attributes
 * - External stylesheets should have SRI integrity attributes
 * - Integrity hashes should use strong algorithms (sha256+)
 * - crossorigin attribute should be present with integrity
 * - CDN resources should use HTTPS
 * - Only trusted CDN sources should be used
 */

/**
 * Test: External scripts have integrity attributes
 * 
 * Purpose: Verifies that all external scripts include Subresource Integrity
 * (SRI) attributes to prevent supply chain attacks through compromised CDNs.
 * 
 * Security Impact: Missing SRI on external scripts can lead to:
 * - Supply chain attacks through compromised CDNs
 * - Malicious script injection
 * - Code tampering attacks
 * - Man-in-the-middle attacks
 * 
 * Test Strategy:
 * 1. Identify all external scripts
 * 2. Check for integrity attributes
 * 3. Verify SRI protection is implemented
 */
test('SRI: external scripts have integrity attributes', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  // Identify external scripts that are missing SRI protection.
  const scriptsWithoutSRI = (await queryElements(page, 'script[src]'))
    .filter(script => script.src && (script.src.startsWith('http://') || script.src.startsWith('https://') || script.src.startsWith('//')))
    .filter(script => !script.integrity)
    .map(script => script.src);

  // Verify that every external script carries an SRI hash.
  softCheck(
    testInfo,
    scriptsWithoutSRI.length === 0,
    `External scripts without SRI integrity: ${scriptsWithoutSRI.join(', ') || 'none'}`
  );

  if (scriptsWithoutSRI.length === 0) {
    reporter.reportPass(
      'All external scripts included Subresource Integrity attributes.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('SRI: external stylesheets have integrity attributes', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const stylesWithoutSRI = (await queryElements(page, 'link[rel="stylesheet"][href]'))
    .filter(link => link.href && (link.href.startsWith('http://') || link.href.startsWith('https://') || link.href.startsWith('//')))
    .filter(link => !link.integrity)
    .map(link => link.href);

  softCheck(
    testInfo,
    stylesWithoutSRI.length === 0,
    `External stylesheets without SRI integrity: ${stylesWithoutSRI.join(', ') || 'none'}`
  );

  if (stylesWithoutSRI.length === 0) {
    reporter.reportPass(
      'All external stylesheets included Subresource Integrity attributes.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('SRI: integrity hashes use strong algorithms', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const weakIntegrity = (await queryElements(page, '[integrity]'))
    .map(item => ({
      src: item.src || item.href,
      integrity: item.integrity || '',
    }))
    .filter(item => {
      const integrity = item.integrity;
      return !integrity.includes('sha256-') && !integrity.includes('sha384-') && !integrity.includes('sha512-');
    });

  softCheck(
    testInfo,
    weakIntegrity.length === 0,
    'SRI integrity attributes should use sha256, sha384, or sha512 algorithms'
  );

  if (weakIntegrity.length === 0) {
    reporter.reportPass(
      'All integrity hashes use strong algorithms (sha256/sha384/sha512).',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('SRI: crossorigin attribute present with integrity', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const missingCrossorigin = (await queryElements(page, '[integrity]'))
    .filter(el => !el.crossorigin)
    .map(el => el.src || el.href);

  softCheck(
    testInfo,
    missingCrossorigin.length === 0,
    'Elements with integrity attribute should also have crossorigin attribute'
  );

  if (missingCrossorigin.length === 0) {
    reporter.reportPass(
      'All SRI-protected elements also included crossorigin attributes.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('Supply chain: CDN resources use HTTPS', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const insecureCDN = (await queryElements(page, 'script[src], link[href]'))
    .map(el => el.src || el.href)
    .filter(url => url && url.startsWith('http://') && !url.includes('localhost'));

  softCheck(
    testInfo,
    insecureCDN.length === 0,
    `Insecure (HTTP) external resources found: ${insecureCDN.join(', ') || 'none'}`
  );

  if (insecureCDN.length === 0) {
    reporter.reportPass(
      'All external CDN resources used HTTPS.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

test('Supply chain: no untrusted CDN sources', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  await page.goto('/');
  
  const trustedCDNs = [
    'cdnjs.cloudflare.com',
    'cdn.jsdelivr.net',
    'unpkg.com',
    'code.jquery.com',
    'stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
  ];

  const externalResources = (await queryElements(page, 'script[src], link[href]'))
    .map(el => el.src || el.href)
    .filter(url => url && (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')));

  const untrusted = externalResources.filter(url => {
    if (!url) return false;
    const hostname = new URL(url.startsWith('//') ? 'https:' + url : url).hostname;
    return !trustedCDNs.some(trusted => hostname.includes(trusted)) && !hostname.includes('localhost');
  });

  if (untrusted.length > 0) {
    reporter.reportWarning(
      `External resources from non-standard CDNs were found: ${untrusted.slice(0, 5).join(', ')}`,
      [
        'Remove unnecessary third-party resources from non-standard CDNs.',
        'Allowlist only trusted CDN hosts for scripts and styles.',
        'Prefer SRI and HTTPS for any external resource that must remain.',
        'Review whether each external resource is necessary for application functionality.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  } else {
    reporter.reportPass(
      'Only trusted CDN sources were used for external resources.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});
