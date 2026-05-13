import { test, request as playwrightRequest } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Cross-Origin Resource Sharing (CORS) Security Tests
 * 
 * These tests verify that the application implements proper CORS policies
 * to prevent unauthorized cross-origin requests and protect against
 * cross-origin attacks.
 * 
 * Security Risks Addressed:
 * 1. Overly permissive CORS policies allowing arbitrary origins
 * 2. Credentials allowed with wildcard origins
 * 3. Inadequate preflight request validation
 * 4. Dangerous HTTP methods allowed from untrusted origins
 * 5. Missing Vary headers for proper caching
 * 6. Origin reflection vulnerabilities
 * 
 * Expected Behavior:
 * - Access-Control-Allow-Origin should be restrictive (not *)
 * - Credentials should not be allowed with wildcard origins
 * - Preflight requests should validate origins properly
 * - Dangerous methods should be restricted by origin
 * - Vary header should include Origin for caching
 * - Origin header should not be blindly reflected
 */

/**
 * Probe whether the app returns any CORS headers for a given path + origin.
 * Returns response headers when at least one Access-Control-* header is present,
 * otherwise returns null (CORS not implemented / endpoint not reachable).
 */
// Issue a same-origin-style request with a spoofed Origin header and return CORS headers when present.
async function probeCors(
  baseURL: string,
  path: string,
  origin = 'https://evil.com'
): Promise<Record<string, string> | null> {
  try {
    const ctx = await playwrightRequest.newContext({ baseURL });
    const res = await ctx.get(path, { headers: { Origin: origin } });
    const headers = res.headers();
    const hasCors = Object.keys(headers).some(h => h.toLowerCase().startsWith('access-control-'));
    return hasCors ? headers : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Test 1: Access-Control-Allow-Origin is restrictive
// ---------------------------------------------------------------------------
test('CORS: Access-Control-Allow-Origin is restrictive', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const headers = await probeCors(baseURL, '/');
  if (!headers) {
    reporter.reportSkip('App does not implement CORS headers on the root endpoint – test not applicable');
    test.skip(true, 'CORS not implemented');
    return;
  }

  // Check whether the server reflects the hostile origin or uses a wildcard.
  const allowOrigin = headers['access-control-allow-origin'];
  const isWildcard = allowOrigin === '*';
  const reflectsOrigin = allowOrigin === 'https://evil.com';

  softCheck(
    testInfo,
    !isWildcard && !reflectsOrigin,
    'CORS Access-Control-Allow-Origin should not be * or reflect arbitrary origins'
  );

  if (!isWildcard && !reflectsOrigin) {
    reporter.reportPass(
      'CORS Access-Control-Allow-Origin is restrictive and does not reflect arbitrary origins.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

// ---------------------------------------------------------------------------
// Test 2: Credentials not allowed with wildcard origin
// ---------------------------------------------------------------------------
test('CORS: credentials not allowed with wildcard origin', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const headers = await probeCors(baseURL, '/api/users', 'https://untrusted.com');
  if (!headers) {
    reporter.reportSkip('App does not implement CORS headers on /api/users – test not applicable');
    test.skip(true, 'CORS not implemented');
    return;
  }

  const allowOrigin = headers['access-control-allow-origin'];
  const allowCredentials = headers['access-control-allow-credentials'];

  // Only meaningful if the server actually sends Allow-Credentials: true.
  if (allowCredentials !== 'true') {
    reporter.reportSkip('allow-credentials not present – wildcard-with-credentials check not applicable');
    test.skip(true, 'allow-credentials not set');
    return;
  }

  softCheck(
    testInfo,
    allowOrigin !== '*',
    'CORS: Access-Control-Allow-Credentials should not be used with wildcard origin (*)'
  );

  if (allowCredentials === 'true' && allowOrigin !== '*') {
    reporter.reportPass(
      'CORS credentials are not combined with a wildcard origin.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

// ---------------------------------------------------------------------------
// Test 3: Preflight requests properly validated
// ---------------------------------------------------------------------------
test('CORS: preflight requests properly validated', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  try {
    const ctx = await playwrightRequest.newContext({ baseURL });
    const res = await ctx.fetch('/api/users', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://malicious.com',
        'Access-Control-Request-Method': 'DELETE',
        'Access-Control-Request-Headers': 'X-Custom-Header',
      },
    });

    // Inspect both the status code and returned headers for preflight behavior.
    const status = res.status();
    const headers = res.headers();

    const hasCors = Object.keys(headers).some(h => h.toLowerCase().startsWith('access-control-'));
    if (!hasCors) {
      reporter.reportSkip('App does not respond to OPTIONS preflight with CORS headers – test not applicable');
      test.skip(true, 'Preflight CORS not implemented');
      return;
    }

    const allowOrigin = headers['access-control-allow-origin'];
    // A wildcard or reflected malicious origin means the preflight is too permissive.
    const dangerous =
      allowOrigin === '*' ||
      allowOrigin === 'https://malicious.com';

    softCheck(
      testInfo,
      !dangerous || status >= 400,
      'CORS preflight should validate and restrict origins'
    );

    if (!dangerous || status >= 400) {
      reporter.reportPass(
        'CORS preflight request was validated and did not allow the malicious origin.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  } catch {
    reporter.reportSkip('OPTIONS request to /api/users failed – endpoint or method not supported');
    test.skip(true, 'Preflight endpoint not reachable');
  }
});

// ---------------------------------------------------------------------------
// Test 4: Dangerous methods blocked without proper origin
// ---------------------------------------------------------------------------
test('CORS: dangerous methods blocked without proper origin', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const probe = await probeCors(baseURL, '/api/users', 'https://evil.com');
  if (!probe) {
    reporter.reportSkip('App does not implement CORS headers – dangerous-methods check not applicable');
    test.skip(true, 'CORS not implemented');
    return;
  }

  // Probe methods that should be tightly controlled by origin policy.
  const dangerousMethods = ['DELETE', 'PUT', 'PATCH'];
  const ctx = await playwrightRequest.newContext({ baseURL });

  for (const method of dangerousMethods) {
    try {
      const res = await ctx.fetch('/api/users/1', {
        method,
        headers: { Origin: 'https://evil.com' },
      });

      // A reflected untrusted origin with a 2xx response is the risky combination.
      const allowOrigin = res.headers()['access-control-allow-origin'];
      const vulnerable = allowOrigin === 'https://evil.com' && res.status() < 400;

      if (vulnerable) {
        softCheck(
          testInfo,
          false,
          `CORS allows dangerous ${method} requests from arbitrary origins`
        );
        break;
      } else if (res.status() >= 400 || allowOrigin !== 'https://evil.com') {
        reporter.reportPass(
          `CORS blocked dangerous ${method} requests from the untrusted origin.`,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      }
    } catch {
      // Method not supported / endpoint not found – not a CORS vulnerability
    }
  }
});

// ---------------------------------------------------------------------------
// Test 5: Vary header includes Origin
// ---------------------------------------------------------------------------
test('CORS: Vary header includes Origin', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const headers = await probeCors(baseURL, '/');
  if (!headers) {
    reporter.reportSkip('App does not implement CORS headers – Vary: Origin check not applicable');
    test.skip(true, 'CORS not implemented');
    return;
  }

  // Ensure caches separate responses by Origin when CORS is enabled.
  const vary = headers['vary'];
  const hasOriginInVary = vary?.toLowerCase().includes('origin') ?? false;

  softCheck(
    testInfo,
    hasOriginInVary,
    'CORS responses should include "Vary: Origin" header for proper caching'
  );

  if (hasOriginInVary) {
    reporter.reportPass(
      'CORS responses include Vary: Origin for proper caching.',
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }
});

// ---------------------------------------------------------------------------
// Test 6: No origin reflection vulnerability
// ---------------------------------------------------------------------------
test('CORS: no origin reflection vulnerability', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  // Skip cleanly when the CI environment does not provide a target URL.
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const probe = await probeCors(baseURL, '/api/users', 'https://attacker.com');
  if (!probe) {
    reporter.reportSkip('App does not implement CORS headers on /api/users – origin reflection check not applicable');
    test.skip(true, 'CORS not implemented');
    return;
  }

  // Try a few hostile origins to see whether the server blindly mirrors them.
  const testOrigins = [
    'https://attacker.com',
    'http://localhost:9999',
    'null',
  ];

  const ctx = await playwrightRequest.newContext({ baseURL });
  let vulnerable = false;
  let reflectedOrigin: string | null = null;

  for (const origin of testOrigins) {
    try {
      const res = await ctx.get('/api/users', {
        headers: { Origin: origin },
      });

      // Reflection is only a problem when the server echoes a hostile Origin value.
      const allowOrigin = res.headers()['access-control-allow-origin'];

      if (allowOrigin === origin && origin !== 'null') {
        vulnerable = true;
        reflectedOrigin = origin;
        break;
      }
    } catch {
      // Continue to next origin
    }
  }

  if (vulnerable) {
    reporter.reportWarning(
      `True vulnerability: CORS origin reflection detected; server reflected untrusted Origin (${reflectedOrigin ?? 'unknown'}).`,
      [
        'Use an explicit allowlist of trusted origins; do not mirror arbitrary Origin values.',
        'Return no Access-Control-Allow-Origin header for untrusted origins.',
        'If credentials are enabled, ensure exact trusted-origin matching and avoid wildcard behavior.',
        'Add automated negative tests for attacker-controlled origins in CI.',
      ],
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
    return;
  }

  reporter.reportPass(
    'CORS policy did not reflect tested untrusted origins.',
    OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
  );
});
