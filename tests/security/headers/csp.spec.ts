import { test } from '@playwright/test';
import { softCheck } from '../utils';

test('CSP: Content-Security-Policy header present', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    test.skip(true, 'No CSP header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    test.skip(true, 'No CSP header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    test.skip(true, 'No CSP header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const csp = headers['content-security-policy'];

  if (!csp) {
    test.skip(true, 'No CSP header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    test.skip(true, 'Not using HTTPS');
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
