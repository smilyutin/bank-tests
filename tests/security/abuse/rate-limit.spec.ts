import { test, request as playwrightRequest } from '@playwright/test';
import { ensureTestUser, getLoginCandidates } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Stabilize authentication endpoint behavior (fix 5xx errors, ensure DB migrations/tables exist)',
  '2) Normalize login request contract (accept and validate expected credential fields consistently)',
  '3) Add rate-limiter middleware on auth/public endpoints and return HTTP 429 when threshold is exceeded',
  '4) Include Retry-After and X-RateLimit-* headers in throttled responses',
];

// These probes measure whether auth and public endpoints slow down abusive traffic.

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
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length) {
    reporter.reportSkip('No login endpoints configured');
    test.skip(true, 'No login endpoints configured');
    return;
  }

  const endpoint = candidates[0];
  let throttled = false;
  let throttleReason = '';
  let throttleAtAttempt = -1;
  const statuses: number[] = [];
  const maxAttempts = 30;

  // Step 1: Make rapid sequential requests to trigger rate limiting
  for (let i = 0; i < maxAttempts; i++) {
    try {
      // Drive repeated login attempts through the same endpoint to provoke throttling.
      const res = await request.post(endpoint, {
        data: { email: user.email, username: user.email, password: 'test-' + i },
        headers: { 'content-type': 'application/json' },
      });

      const status = res.status();
      statuses.push(status);
      // Step 2: Check for rate limiting response
      if (status === 429) {
        throttled = true;
        throttleReason = `Server returned HTTP 429 Too Many Requests on attempt ${i + 1}`;
        throttleAtAttempt = i + 1;
        break;
      }

      // Step 3: Check for rate limit headers
      const headers = res.headers();
      if (headers['x-ratelimit-remaining'] === '0') {
        throttled = true;
        throttleReason = `Header X-RateLimit-Remaining reached 0 on attempt ${i + 1}`;
        throttleAtAttempt = i + 1;
        break;
      }
      if (headers['retry-after']) {
        throttled = true;
        throttleReason = `Server sent Retry-After: ${headers['retry-after']} on attempt ${i + 1}`;
        throttleAtAttempt = i + 1;
        break;
      }
    } catch (e) {
      // Continue on errors
    }
  }

  // Step 4: Report findings
  const statusSummary = `[${statuses.join(', ')}]`;
  const has5xx = statuses.some((s) => s >= 500);
  const all5xx = statuses.length > 0 && statuses.every((s) => s >= 500);
  if (throttled) {
    reporter.reportPass(
      `System is protected: rate limiting triggered after ${throttleAtAttempt} rapid POST requests to ${endpoint}. ` +
      `Reason: ${throttleReason}. ` +
      `Observed status progression: ${statusSummary}. ` +
      `This prevents brute-force and DoS attacks by blocking excessive login attempts before an attacker can make meaningful progress.`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    if (all5xx) {
      reporter.reportWarning(
        `Environment limitation: rate-limit verification is blocked by endpoint instability. ${maxAttempts} rapid POST requests to ${endpoint} all returned 5xx responses. ` +
        `Observed status progression: ${statusSummary}. ` +
        `No 429 / Retry-After / rate-limit headers were observed, so throttling could not be confirmed. ` +
        `Risk: broken auth availability under load and potential brute-force exposure once endpoint is stable.`,
        [
          ...TARGET_APP_FIX_FIRST,
          'Treat repeated 5xx on auth as a production-severity reliability/security incident.',
          `After stabilizing ${endpoint}, rerun abuse tests and enforce explicit 429 throttling behavior.`,
          'Instrument auth failures and 5xx spikes with alerts to detect active abuse or regressions.',
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    reporter.reportWarning(
      `True vulnerability: no rate limiting was detected. ${maxAttempts} rapid POST requests to ${endpoint} did not trigger throttling signals (429/Retry-After/rate-limit headers). ` +
      `Observed status progression: ${statusSummary}. ` +
      `${has5xx ? 'Some 5xx responses were observed, indicating endpoint instability during the probe. ' : ''}` +
      `Risk: account takeover via credential stuffing and service degradation under load.`,
      [
        ...TARGET_APP_FIX_FIRST,
        `Add rate limiting middleware on ${endpoint} (e.g. express-rate-limit, nginx limit_req).`,
        'Return HTTP 429 with a Retry-After header when the threshold is exceeded.',
        'Set a low threshold (e.g. 5–10 requests/min) specifically for authentication endpoints.',
        'Combine with account lockout after N consecutive failures for the same username.',
        'Add X-RateLimit-Limit / X-RateLimit-Remaining / X-RateLimit-Reset headers so clients can self-throttle.',
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});

test('Rate limiting: 429 status includes Retry-After header', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length) {
    reporter.reportSkip('No login endpoints configured');
    test.skip(true, 'No login endpoints configured');
    return;
  }

  const endpoint = candidates[0];
  let foundRetryAfter = false;
  let retryAfterValue = '';
  let saw429 = false;
  const statuses: number[] = [];
  const maxAttempts = 150;

  // Trigger rate limiting
  for (let i = 0; i < maxAttempts; i++) {
    try {
      // Continue until the server either throttles or exhausts the probe window.
      const res = await request.post(endpoint, {
        data: { email: `test${i}@example.com`, username: `test${i}@example.com`, password: 'test' },
      });
      statuses.push(res.status());

      if (res.status() === 429) {
        saw429 = true;
        const headers = res.headers();
        retryAfterValue = headers['retry-after'] || headers['x-ratelimit-reset'] || '';
        foundRetryAfter = !!retryAfterValue;
        break;
      }
    } catch (e) {
      // Continue
    }
  }

  if (!saw429) {
    const statusSummary = `[${statuses.join(', ')}]`;
    const all5xx = statuses.length > 0 && statuses.every((s) => s >= 500);
    reporter.reportWarning(
      all5xx
        ? `Environment limitation: Retry-After validation could not confirm throttling because ${endpoint} returned only 5xx responses during the ${maxAttempts}-request probe (${statusSummary}). ` +
          `No 429 response was observed, so compliant throttling behavior could not be confirmed. ` +
          `Risk: unstable auth endpoint under load and missing abuse controls.`
        : `True vulnerability: Retry-After validation failed because no HTTP 429 response was received after ${maxAttempts} requests to ${endpoint} (statuses: ${statusSummary}). ` +
          `Without a 429 response, clients never receive explicit retry guidance and abuse controls are likely missing or ineffective.`,
      [
        ...TARGET_APP_FIX_FIRST,
        `Ensure ${endpoint} enforces deterministic rate-limit thresholds and returns HTTP 429 on excess requests.`,
        'Include Retry-After (or X-RateLimit-Reset) on every throttled response so clients can back off correctly.',
        'Stabilize auth endpoint behavior first if 5xx responses occur during rate-limit probes.',
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
    return;
  }

  if (foundRetryAfter) {
    reporter.reportPass(
      `System is protected: HTTP 429 response from ${endpoint} includes a Retry-After / X-RateLimit-Reset header (value: "${retryAfterValue}"). ` +
      `Clients receive clear guidance on when to retry, preventing retry storms and enabling compliant API clients to back off gracefully.`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportWarning(
      `True vulnerability: rate limiting is active on ${endpoint} (returned 429) but the response is missing a Retry-After or X-RateLimit-Reset header. ` +
      `Without this header, clients have no signal for when to retry, leading to immediate retry storms that amplify load.`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Add a Retry-After header (seconds until reset) to every 429 response.',
        'Alternatively expose X-RateLimit-Reset (Unix epoch) so clients can schedule retries precisely.',
        'Document the rate-limit policy in your API spec so integrators can design compliant clients.',
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
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
  const statuses: number[] = [];
  const maxAttempts = 150;
  
  // Step 1: Send multiple rapid requests to test rate limiting
  for (let i = 0; i < maxAttempts; i++) {
    try {
      // Use a low-risk public route so the probe stays non-destructive.
      const res = await api.get(target).catch(() => null);
      if (!res) continue;
      
      gotAny = true;
      statuses.push(res.status());
      
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
      `System is protected: public endpoint ${target} returned HTTP 429 or rate-limit headers during a ${maxAttempts}-request burst. ` +
      `Observed status progression: [${statuses.join(', ')}]. ` +
      `This limits the blast radius of DoS attempts and prevents API abuse by anonymous clients. ` +
      `Rate limiting on public endpoints is a first line of defence before authentication is even reached.`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  } else {
    reporter.reportWarning(
      `True vulnerability: no rate limiting was detected on public endpoint ${target} during a ${maxAttempts}-request burst — all requests returned non-429 responses. ` +
      `Observed status progression: [${statuses.join(', ')}]. ` +
      `Risk: an unauthenticated attacker can flood this endpoint without restriction, potentially causing service degradation or exhausting server resources.`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Consider implementing rate limiting to prevent abuse.',
        'Use middleware like express-rate-limit or similar.',
        'Return 429 status code when limits exceeded.',
        'Add rate limit headers (X-RateLimit-*) to responses.',
        'Implement different limits for authenticated vs anonymous users.'
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});

test('Rate limiting: per-IP or per-user limits exist', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  const candidates = getLoginCandidates();
  
  if (!candidates.length || !user.email) {
    reporter.reportSkip('No login endpoints or user configured');
    test.skip(true, 'No login endpoints or user configured');
    return;
  }

  const endpoint = candidates[0];
  const responses: number[] = [];
  let throttleAtAttempt = -1;

  // Make requests with same credentials
  for (let i = 0; i < 100; i++) {
    try {
      // Reuse the same username so per-user throttling has a chance to trigger.
      const res = await request.post(endpoint, {
        data: { email: user.email, username: user.email, password: 'wrong-password' },
      });
      responses.push(res.status());
      
      if (res.status() === 429) {
        throttleAtAttempt = i + 1;
        break;
      }
    } catch (e) {
      // Continue
    }
  }

  const hasRateLimit = responses.includes(429);
  const statusSummary = `[${responses.join(', ')}]`;

  if (hasRateLimit) {
    reporter.reportPass(
      `System is protected: per-user rate limiting triggered after ${throttleAtAttempt} consecutive failed login attempts for "${user.email}" on ${endpoint}. ` +
      `Response codes observed: ${statusSummary}. ` +
      `This directly prevents credential-stuffing and password-spray attacks targeting a single account.`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
    
  } else {
    reporter.reportWarning(
      `True vulnerability: no per-user rate limiting was detected. ${responses.length} consecutive failed login attempts for "${user.email}" on ${endpoint} all completed without a 429. ` +
      `Response codes observed: ${statusSummary}. ` +
      `Risk: an attacker can perform unlimited password-guessing against any account with no server-side enforcement.`,
      [
        ...TARGET_APP_FIX_FIRST,
        `Implement per-username (or per-IP) rate limiting on ${endpoint}.`,
        'Consider account lockout or CAPTCHA after 5–10 failed attempts for the same username.',
        'Use progressive delays (exponential back-off on the server) as an alternative to hard lockout.',
        'Emit security events / alerts on repeated failures so your SIEM can detect spraying campaigns.',
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
    // console.log(`Rate limit triggered at attempt ${throttleAtAttempt} with response codes: ${statusSummary}`);
    //console.log(responses.includes(429) ? `Received 429 at attempt ${throttleAtAttempt}` : 'No 429 received, the app appears to have no rate-limiter middleware active.');
});
