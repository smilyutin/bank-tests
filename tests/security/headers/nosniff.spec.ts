import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * MIME-sniffing defense checks.
 *
 * Goal: ensure browsers receive strict content typing instructions
 * (`X-Content-Type-Options: nosniff`) on primary and static resources.
 */

test('X-Content-Type-Options: nosniff header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  // Validate primary document response first before expanding to resource checks.
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name);
    return;
  }

  const headers = response.headers();
  const nosniff = headers['x-content-type-options'];

  softCheck(
    testInfo,
    !!nosniff,
    'X-Content-Type-Options header should be present'
  );

  if (nosniff) {
    const isNosniff = nosniff.toLowerCase() === 'nosniff';
    
    softCheck(
      testInfo,
      isNosniff,
      `X-Content-Type-Options should be 'nosniff' (got: ${nosniff})`
    );
  }
});

test('X-Content-Type-Options: present on all resources', async ({ page }, testInfo) => {
  // Capture response stream to evaluate header consistency for loaded assets.
  await page.goto('/');
  
  // Collect all responses
  const responses: any[] = [];
  
  page.on('response', response => {
    responses.push(response);
  });

  await page.goto('/', { waitUntil: 'networkidle' });
  
  let missingNosniff = 0;
  
  for (const response of responses) {
    const headers = response.headers();
    const contentType = headers['content-type'] || '';
    
    // Check critical content types where MIME confusion can be high impact.
    if (
      contentType.includes('javascript') ||
      contentType.includes('html') ||
      contentType.includes('css')
    ) {
      if (!headers['x-content-type-options']) {
        missingNosniff++;
      }
    }
  }

  softCheck(
    testInfo,
    missingNosniff === 0,
    `${missingNosniff} resources missing X-Content-Type-Options: nosniff header`
  );
});

test('Content-Type: properly set for responses', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name);
    return;
  }

  const headers = response.headers();
  const contentType = headers['content-type'];

  softCheck(
    testInfo,
    !!contentType,
    'Content-Type header should be present on all responses'
  );

  if (contentType) {
    // Should include charset for text content
    const isText = contentType.includes('text/') || contentType.includes('application/json');
    const hasCharset = contentType.includes('charset');
    
    if (isText) {
      softCheck(
        testInfo,
        hasCharset,
        'Text content should specify charset in Content-Type header'
      );
    }
  }
});
