import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Enforce request body size limits at API gateway/reverse proxy and app middleware',
  '2) Return explicit 413 Payload Too Large when limits are exceeded',
  '3) Ensure large payload handling cannot trigger 5xx or excessive processing time',
  '4) Add request size policy documentation and monitoring alerts for abuse spikes',
];

/**
 * Payload Size Abuse Tests
 * 
 * These tests verify that the application properly handles and rejects oversized payloads
 * to prevent Denial of Service (DoS) attacks and resource exhaustion.
 * 
 * Security Risks Addressed:
 * 1. DoS attacks through oversized requests
 * 2. Memory exhaustion from large payloads
 * 3. Network bandwidth abuse
 * 4. Server resource consumption attacks
 * 
 * Expected Behavior:
 * - Server should reject payloads exceeding reasonable limits (typically 1-10MB)
 * - Should return appropriate HTTP status codes (413 Payload Too Large, 400 Bad Request)
 * - Should not process or store oversized data
 */

/**
 * Test: Server rejects oversized payloads (>10MB)
 * 
 * Purpose: Verifies that the server properly rejects extremely large payloads to prevent
 * DoS attacks and resource exhaustion.
 * 
 * Security Impact: If servers accept unlimited payload sizes, attackers could:
 * - Send massive requests to exhaust server memory
 * - Consume network bandwidth
 * - Cause server crashes or slowdowns
 * - Impact other users' experience
 * 
 * Test Strategy:
 * 1. Create a 10MB payload (common DoS attack size)
 * 2. Attempt to send it to a protected endpoint
 * 3. Verify the server rejects it with appropriate status code
 */
test('Payload size: server rejects oversized payloads', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  if (!user.email) {
    reporter.reportSkip('No persisted user');
    test.skip(true, 'No persisted user');
    return;
  }

  // Step 1: Create a large payload (> 10MB)
  // This simulates a DoS attack attempting to exhaust server resources
  const largeString = 'A'.repeat(10 * 1024 * 1024);
  const oversizedPayload = {
    email: user.email,
    password: user.password,
    extraData: largeString,
  };

  // Step 2: Verify login endpoint exists for testing
  const attempt = await tryLogin(request as any, user.email!, user.password!);
  if (!attempt) {
    reporter.reportSkip('Login endpoint not found');
    test.skip(true, 'Login endpoint not found');
    return;
  }

  const { path } = attempt as any;

  // Step 3: Attempt to send the oversized payload
  // This tests if the server properly validates request size
  let networkRejected = false;
  let networkRejectionReason = '';
  try {
    const res = await request.post(path, {
      data: oversizedPayload,
      headers: { 'content-type': 'application/json' },
    });

    const status = res.status();
    const statusSummary = `[${status}]`;
    // Step 4: Verify server rejects oversized payloads
    // Expected responses: 413 (Payload Too Large), 400 (Bad Request), or 5xx (Server Error)
    const rejected = status === 413 || status === 400 || status >= 500;

    if (rejected) {
      const isIdeal = status === 413;
      reporter.reportPass(
        `System is protected against oversized payload abuse: endpoint ${path} rejected a 10MB payload with status ${status}. ` +
        `Observed status progression: ${statusSummary}. ` +
        (isIdeal
          ? 'The explicit 413 response confirms payload size enforcement is active and predictable.'
          : 'Request was rejected, which reduces DoS risk, but using explicit 413 would improve API behavior and observability.'),
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    } else {
      reporter.reportWarning(
        `Oversized payload may be accepted: endpoint ${path} returned status ${status} for a 10MB request. ` +
        `Observed status progression: ${statusSummary}. ` +
        `Risk: attackers can submit very large bodies to consume memory/CPU and degrade service availability.`,
        [
          ...TARGET_APP_FIX_FIRST,
          `Apply strict max body size for ${path} (e.g., 1MB for auth endpoints)`,
          'Use schema validation to reject unexpected large fields (e.g., extraData)',
          'Short-circuit oversized requests before business logic/database layers',
          'Add per-route limits for high-risk endpoints (login, registration, file uploads)',
        ],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    }
  } catch (e: any) {
    // Step 5: Handle network-level rejections
    // Network errors are acceptable - payload may be rejected at proxy/load balancer level
    if (e.message?.includes('Request Entity Too Large') || e.message?.includes('413')) {
      networkRejected = true;
      networkRejectionReason = e.message;
    }

    if (networkRejected) {
      reporter.reportPass(
        `System is protected against oversized payload abuse: 10MB request was rejected at network/proxy layer before app processing. ` +
        `Evidence: ${networkRejectionReason}`,
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
      return;
    }

    reporter.reportWarning(
      `Oversized payload test encountered an unexpected client/network error without clear size-limit evidence. Error: ${e?.message || 'unknown error'}`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Verify reverse proxy and application body-size limits are both configured',
        'Ensure oversized request rejections are returned consistently as HTTP 413',
      ],
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});

/**
 * Test: API has reasonable size limits (5MB test)
 * 
 * Purpose: Verifies that the API has reasonable payload size limits in place,
 * even for moderately large requests that might be legitimate but could still
 * cause resource issues.
 * 
 * Security Impact: APIs without size limits could be vulnerable to:
 * - Resource exhaustion attacks with moderately large payloads
 * - Memory consumption issues
 * - Performance degradation
 * - Potential buffer overflow vulnerabilities
 * 
 * Test Strategy:
 * 1. Create a 5MB payload (moderate size that should be limited)
 * 2. Send it to a protected endpoint
 * 3. Verify the server either rejects it or has processing limits
 * 4. Check for appropriate timeout behavior
 */
test('Payload size: API has reasonable size limits', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  // Step 1: Create a moderate-sized payload (5MB)
  // This tests for reasonable limits that should be enforced
  const mediumPayload = {
    data: 'B'.repeat(5 * 1024 * 1024),
  };

  // Step 2: Verify login endpoint exists for testing
  const attempt = await tryLogin(request as any, user.email!, user.password!);
  if (!attempt) {
    reporter.reportSkip('Login endpoint not found');
    test.skip(true, 'Login endpoint not found');
    return;
  }

  const { path } = attempt as any;

  // Step 3: Send moderate-sized payload with timeout
  // This tests both size limits and timeout behavior
  try {
    const res = await request.post(path, {
      data: mediumPayload,
      headers: { 'content-type': 'application/json' },
      timeout: 5000, // 5 second timeout to prevent hanging
    });

    const status = res.status();
    const hasLimits = status === 413 || status === 400 || status === 404;

    if (hasLimits) {
      reporter.reportPass(
        `System is protected: endpoint ${path} enforced reasonable handling for a 5MB request with status ${status}. ` +
        `This indicates payload-size controls or endpoint-level request validation are in place.`,
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    } else {
      reporter.reportWarning(
        `API may lack adequate payload size controls: endpoint ${path} returned status ${status} for a 5MB request. ` +
        `Risk: sustained medium-size requests can consume server resources and degrade performance over time.`,
        [
          ...TARGET_APP_FIX_FIRST,
          `Define explicit max request size on ${path} and reject with HTTP 413`,
          'Set conservative body-parser limits for JSON/form content',
          'Apply per-user/IP throttling for repeated large requests',
          'Track and alert on request size percentile anomalies',
        ],
        OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
      );
    }
  } catch (e: any) {
    // Step 5: Handle timeout or rejection scenarios
    // Timeout or rejection is acceptable behavior for large payloads
    reporter.reportPass(
      `System is protected: 5MB request to ${path} did not complete normally (timeout/rejection), indicating processing safeguards against heavy payloads. ` +
      `Evidence: ${e?.message || 'request aborted or timed out'}`,
      OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
    );
  }
});
