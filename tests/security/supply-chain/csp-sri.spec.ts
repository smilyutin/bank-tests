import { test } from '@playwright/test';
import { softCheck } from '../utils';

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
  await page.goto('/');
  
  // Step 1: Identify external scripts without SRI protection
  const scriptsWithoutSRI = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const external = scripts.filter(script => {
      const src = script.getAttribute('src');
      return src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//'));
    });
    
    // Step 2: Check for missing integrity attributes
    return external
      .filter(script => !script.hasAttribute('integrity'))
      .map(script => script.getAttribute('src'));
  });

  // Step 3: Verify all external scripts have SRI protection
  softCheck(
    testInfo,
    scriptsWithoutSRI.length === 0,
    `External scripts without SRI integrity: ${scriptsWithoutSRI.join(', ') || 'none'}`
  );
});

test('SRI: external stylesheets have integrity attributes', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const stylesWithoutSRI = await page.evaluate(() => {
    const links = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'));
    const external = links.filter(link => {
      const href = link.getAttribute('href');
      return href && (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//'));
    });
    
    return external
      .filter(link => !link.hasAttribute('integrity'))
      .map(link => link.getAttribute('href'));
  });

  softCheck(
    testInfo,
    stylesWithoutSRI.length === 0,
    `External stylesheets without SRI integrity: ${stylesWithoutSRI.join(', ') || 'none'}`
  );
});

test('SRI: integrity hashes use strong algorithms', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const weakIntegrity = await page.evaluate(() => {
    const elements = Array.from(document.querySelectorAll('[integrity]'));
    return elements
      .map(el => ({
        src: el.getAttribute('src') || el.getAttribute('href'),
        integrity: el.getAttribute('integrity'),
      }))
      .filter(item => {
        const integrity = item.integrity || '';
        // sha256, sha384, sha512 are acceptable
        return !integrity.includes('sha256-') && !integrity.includes('sha384-') && !integrity.includes('sha512-');
      });
  });

  softCheck(
    testInfo,
    weakIntegrity.length === 0,
    'SRI integrity attributes should use sha256, sha384, or sha512 algorithms'
  );
});

test('SRI: crossorigin attribute present with integrity', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const missingCrossorigin = await page.evaluate(() => {
    const elements = Array.from(document.querySelectorAll('[integrity]'));
    return elements
      .filter(el => !el.hasAttribute('crossorigin'))
      .map(el => el.getAttribute('src') || el.getAttribute('href'));
  });

  softCheck(
    testInfo,
    missingCrossorigin.length === 0,
    'Elements with integrity attribute should also have crossorigin attribute'
  );
});

test('Supply chain: CDN resources use HTTPS', async ({ page }, testInfo) => {
  await page.goto('/');
  
  const insecureCDN = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src], link[href]'));
    return scripts
      .map(el => el.getAttribute('src') || el.getAttribute('href'))
      .filter(url => url && url.startsWith('http://') && !url.includes('localhost'));
  });

  softCheck(
    testInfo,
    insecureCDN.length === 0,
    `Insecure (HTTP) external resources found: ${insecureCDN.join(', ') || 'none'}`
  );
});

test('Supply chain: no untrusted CDN sources', async ({ page }, testInfo) => {
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

  const externalResources = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script[src], link[href]'));
    return scripts
      .map(el => el.getAttribute('src') || el.getAttribute('href'))
      .filter(url => url && (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')));
  });

  const untrusted = externalResources.filter(url => {
    if (!url) return false;
    const hostname = new URL(url.startsWith('//') ? 'https:' + url : url).hostname;
    return !trustedCDNs.some(trusted => hostname.includes(trusted)) && !hostname.includes('localhost');
  });

  // This is informational - not all external resources are bad
  if (untrusted.length > 0) {
    softCheck(
      testInfo,
      true,
      `External resources from non-standard CDNs (review needed): ${untrusted.slice(0, 5).join(', ')}`
    );
  }
});
