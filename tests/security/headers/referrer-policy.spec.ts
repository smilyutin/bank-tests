import { test } from '@playwright/test';
import { softCheck } from '../utils';

test('Referrer-Policy: header present', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const referrerPolicy = headers['referrer-policy'];

  softCheck(
    testInfo,
    !!referrerPolicy,
    'Referrer-Policy header should be present to control referrer information'
  );
});

test('Referrer-Policy: uses secure value', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const referrerPolicy = headers['referrer-policy'];

  if (!referrerPolicy) {
    test.skip(true, 'No Referrer-Policy header found');
    return;
  }

  // Recommended secure values
  const secureValues = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'same-origin',
  ];

  const isSecure = secureValues.some(value => 
    referrerPolicy.toLowerCase().includes(value.toLowerCase())
  );

  softCheck(
    testInfo,
    isSecure,
    `Referrer-Policy should use a secure value (got: ${referrerPolicy})`
  );

  // Avoid unsafe values
  const isUnsafe = 
    referrerPolicy.toLowerCase() === 'unsafe-url' ||
    referrerPolicy.toLowerCase() === 'origin-when-cross-origin';

  softCheck(
    testInfo,
    !isUnsafe,
    'Referrer-Policy should not use unsafe-url or origin-when-cross-origin'
  );
});

test('Referrer-Policy: meta tag matches header', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const headerPolicy = headers['referrer-policy'];

  const metaPolicy = await page.evaluate(() => {
    const meta = document.querySelector('meta[name="referrer"]');
    return meta?.getAttribute('content') || null;
  });

  if (headerPolicy && metaPolicy) {
    const match = headerPolicy.toLowerCase() === metaPolicy.toLowerCase();
    
    softCheck(
      testInfo,
      match,
      'Referrer-Policy header and meta tag should match for consistency'
    );
  }
});
