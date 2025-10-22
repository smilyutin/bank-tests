import { test } from '@playwright/test';
import { softCheck } from '../utils';

test('HSTS: Strict-Transport-Security header present on HTTPS', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const url = page.url();
  if (!url.startsWith('https://')) {
    test.skip(true, 'Not using HTTPS, HSTS not applicable');
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
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    test.skip(true, 'No HSTS header found');
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
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    test.skip(true, 'No HSTS header found');
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
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    test.skip(true, 'No HSTS header found');
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
