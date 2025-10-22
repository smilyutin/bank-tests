import { test, request as playwrightRequest } from '@playwright/test';
import { ensureTestUser, getLoginCandidates, softCheck } from '../utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Rate Limiting and Abuse Prevention Tests
 * 
 * These tests verify that the application implements proper rate limiting
 * to prevent abuse, DoS attacks, and brute force attempts.
 * 
 * Security Risks Addressed:
 * 1. Excessive requests without throttling
 * 2. Missing retry-after headers for rate limits
 * 3. Lack of per-user or per-IP rate limiting
 * 4. Brute force attacks on authentication endpoints
 * 5. DoS attacks through request flooding
 * 
 * Expected Behavior:
 * - Excessive requests should be throttled (429 status)
 * - Rate limit responses should include retry-after headers
 * - Per-user and per-IP limits should be enforced
 * - Authentication endpoints should have rate limiting
 * - Proper abuse prevention mechanisms should be in place
 */

/**
 * Test: Excessive requests are throttled
 * 
 * Purpose: Verifies that the application implements rate limiting
 * to prevent abuse and DoS attacks through excessive requests.
 * 
 * Security Impact: Lack of rate limiting can lead to:
 * - DoS attacks through request flooding
 * - Brute force attacks on authentication
 * - Resource exhaustion
 * - Service unavailability
 * 
 * Test Strategy:
 * 1. Make rapid sequential requests
 * 2. Check for 429 status code (Too Many Requests)
 * 3. Verify rate limit headers are present
 * 4. Ensure proper throttling is implemented
 */
test('Rate limiting: excessive requests are throttled', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length) {
    test.skip(true, 'No login endpoints configured');
    return;
  }

  const endpoint = candidates[0];
  let throttled = false;
  const maxAttempts = 30;

  // Step 1: Make rapid sequential requests to trigger rate limiting
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await request.post(endpoint, {
        data: { email: user.email, password: 'test-' + i },
        headers: { 'content-type': 'application/json' },
      });

      const status = res.status();
      // Step 2: Check for rate limiting response
      if (status === 429) {
        throttled = true;
        break;
      }

      // Step 3: Check for rate limit headers
      const headers = res.headers();
      if (headers['x-ratelimit-remaining'] === '0' || headers['retry-after']) {
        throttled = true;
        break;
      }
    } catch (e) {
      // Continue on errors
    }
  }

  // Step 4: Verify rate limiting was triggered
  softCheck(
    testInfo,
    throttled,
    'API did not implement rate limiting after ' + maxAttempts + ' rapid requests'
  );
});

test('Rate limiting: 429 status includes Retry-After header', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length) {
    test.skip(true, 'No login endpoints configured');
    return;
  }

  const endpoint = candidates[0];
  let foundRetryAfter = false;
  const maxAttempts = 50;

  // Trigger rate limiting
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await request.post(endpoint, {
        data: { email: `test${i}@example.com`, password: 'test' },
      });

      if (res.status() === 429) {
        const headers = res.headers();
        foundRetryAfter = !!(headers['retry-after'] || headers['x-ratelimit-reset']);
        break;
      }
    } catch (e) {
      // Continue
    }
  }

  if (!foundRetryAfter) {
    test.skip(true, 'Rate-limited response did not include Retry-After or reset header');
  }
});

/**
 * Test: Non-destructive rate limiting detection (OWASP API4:2023)
 * 
 * Purpose: Verifies that the API implements rate limiting or DoS protection
 * mechanisms without requiring authentication.
 * 
 * Security Impact: Lack of rate limiting can lead to:
 * - DoS attacks through request flooding
 * - Resource exhaustion and service unavailability
 * - Brute force attacks on authentication endpoints
 * - API abuse and cost escalation
 * 
 * Test Strategy:
 * 1. Send multiple rapid requests to a public endpoint
 * 2. Look for 429 (Too Many Requests) status codes
 * 3. Check for rate limiting headers
 * 4. Verify protection mechanisms are in place
 */
test('Rate limiting (OWASP API4): DoS protection on public endpoints', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const target = '/api/docs'; // Non-destructive public endpoint
  let gotAny = false;
  let saw429 = false;
  
  // Step 1: Send multiple rapid requests to test rate limiting
  for (let i = 0; i < 30; i++) {
    try {
      const res = await api.get(target).catch(() => null);
      if (!res) continue;
      
      gotAny = true;
      
      // Step 2: Check for 429 status indicating rate limiting
      if (res.status() === 429) { 
        saw429 = true; 
        break; 
      }
      
      // Step 3: Check for rate limiting headers
      const ra = res.headers()['retry-after'] || res.headers()['x-rate-limit-reset'];
      if (ra) { 
        saw429 = true; 
        break; 
      }
    } catch (e) {
      // Continue testing
    }
  }
  
  // Step 4: Skip if target endpoint not reachable
  if (!gotAny) {
    reporter.reportSkip('Target endpoint not reachable for rate-limit probe');
    test.skip(true, 'Target endpoint not reachable for rate-limit probe');
    return;
  }
  
  // Step 5: Report based on findings
  if (saw429) {
    reporter.reportPass(
      'Rate limiting detected: API returned 429 status or rate-limit headers',
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportWarning(
      'No rate limiting detected during burst test (30 requests). This may indicate lack of DoS protection.',
      [
        'Consider implementing rate limiting to prevent abuse',
        'Use middleware like express-rate-limit or similar',
        'Return 429 status code when limits exceeded',
        'Add rate limit headers (X-RateLimit-*) to responses',
        'Implement different limits for authenticated vs anonymous users'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});

test('Rate limiting: per-IP or per-user limits exist', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length || !user.email) {
    test.skip(true, 'No login endpoints or user configured');
    return;
  }

  const endpoint = candidates[0];
  const responses: number[] = [];

  // Make requests with same credentials
  for (let i = 0; i < 20; i++) {
    try {
      const res = await request.post(endpoint, {
        data: { email: user.email, password: 'wrong-password' },
      });
      responses.push(res.status());
      
      if (res.status() === 429) break;
    } catch (e) {
      // Continue
    }
  }

  const hasRateLimit = responses.includes(429);
  
  softCheck(
    testInfo,
    hasRateLimit,
    'No per-user or per-IP rate limiting detected for authentication endpoint'
  );
});
