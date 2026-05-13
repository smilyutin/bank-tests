import { test } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { getMetaContent } from '../utils/dom';

test('Referrer-Policy: header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('Referrer-Policy header check could not run because no response was received from the application root endpoint.');
    test.skip(true, 'No response was received from the application root endpoint');
    return;
  }

  const headers = response.headers();
  const referrerPolicy = headers['referrer-policy'];

  if (!referrerPolicy) {
    reporter.reportWarning(
      'True vulnerability: no Referrer-Policy header was found, so referrer information is not explicitly controlled.',
      [
        'Set Referrer-Policy header globally at reverse proxy or application middleware level.',
        'Use a secure policy such as strict-origin-when-cross-origin or no-referrer.',
        'Validate header presence on HTML and API responses in CI security checks.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportPass(
    `Referrer-Policy header is present (${referrerPolicy}).`,
    OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
  );
});

test('Referrer-Policy: uses secure value', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('Referrer-Policy secure-value check could not run because no response was received from the application root endpoint.');
    test.skip(true, 'No response was received from the application root endpoint');
    return;
  }

  const headers = response.headers();
  const referrerPolicy = headers['referrer-policy'];

  if (!referrerPolicy) {
    reporter.reportWarning(
      'True vulnerability: Referrer-Policy secure-value check failed because no Referrer-Policy header was found.',
      [
        'Set Referrer-Policy header globally at reverse proxy or application middleware level',
        'Use strict-origin-when-cross-origin or no-referrer based on privacy requirements',
        'Add CI checks to prevent deployments without Referrer-Policy header'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
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

  if (!isSecure) {
    reporter.reportWarning(
      `Referrer-Policy should use a secure value (got: ${referrerPolicy}).`,
      [
        'Set Referrer-Policy to strict-origin-when-cross-origin for balanced privacy and compatibility.',
        'Use no-referrer for maximum privacy on highly sensitive applications.',
        'Ensure all deployment environments serve the same secure policy value.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  // Avoid unsafe values
  const isUnsafe = 
    referrerPolicy.toLowerCase() === 'unsafe-url' ||
    referrerPolicy.toLowerCase() === 'origin-when-cross-origin';

  if (isUnsafe) {
    reporter.reportWarning(
      `Referrer-Policy uses unsafe value: ${referrerPolicy}.`,
      [
        'Replace unsafe-url/origin-when-cross-origin with strict-origin-when-cross-origin.',
        'Review third-party integrations to avoid requiring over-broad referrer data.',
        'Add regression tests to prevent accidental downgrade to unsafe policy values.'
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportPass(
    `Referrer-Policy uses a secure value (${referrerPolicy}).`,
    OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
  );
});

test('Referrer-Policy: meta tag matches header', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportSkip('Referrer-Policy header/meta consistency check could not run because no response was received from the application root endpoint.');
    test.skip(true, 'No response was received from the application root endpoint');
    return;
  }

  const headers = response.headers();
  const headerPolicy = headers['referrer-policy'];

  const metaPolicy = await getMetaContent(page, 'meta[name="referrer"]');

  if (headerPolicy && metaPolicy) {
    const match = headerPolicy.toLowerCase() === metaPolicy.toLowerCase();

    if (!match) {
      reporter.reportWarning(
        `True vulnerability: Referrer-Policy mismatch between header (${headerPolicy}) and meta tag (${metaPolicy}).`,
        [
          'Use a single canonical Referrer-Policy source, preferably HTTP response headers.',
          'Align meta referrer value with the header policy if both are intentionally present.',
          'Add a CI assertion to keep header and meta policy consistent.'
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    reporter.reportPass(
      `Referrer-Policy header and meta tag are consistent (${headerPolicy}).`,
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportWarning(
    'Environment limitation: Referrer-Policy consistency check could not be fully validated because header or meta referrer value is absent.',
    [
      'Prefer serving Referrer-Policy via HTTP header as the canonical source',
      'If meta referrer is used, keep it consistent with the header value',
      'Add CI assertions for header presence and optional header/meta consistency'
    ],
    OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
  );
});
