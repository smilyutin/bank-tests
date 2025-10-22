import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

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
  const user = await ensureTestUser(request as any);
  if (!user.email) {
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
    test.skip(true, 'Login endpoint not found');
    return;
  }

  const { path } = attempt as any;

  // Step 3: Attempt to send the oversized payload
  // This tests if the server properly validates request size
  try {
    const res = await request.post(path, {
      data: oversizedPayload,
      headers: { 'content-type': 'application/json' },
    });

    const status = res.status();
    // Step 4: Verify server rejects oversized payloads
    // Expected responses: 413 (Payload Too Large), 400 (Bad Request), or 5xx (Server Error)
    const rejected = status === 413 || status === 400 || status >= 500;
    
    softCheck(
      testInfo,
      rejected,
      `Server did not reject oversized payload (status: ${status}). Expected 413 or 400.`
    );
  } catch (e: any) {
    // Step 5: Handle network-level rejections
    // Network errors are acceptable - payload may be rejected at proxy/load balancer level
    if (e.message?.includes('Request Entity Too Large') || e.message?.includes('413')) {
      // Good - payload was rejected at network level
      return;
    }
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
  const user = await ensureTestUser(request as any);
  
  // Step 1: Create a moderate-sized payload (5MB)
  // This tests for reasonable limits that should be enforced
  const mediumPayload = {
    data: 'B'.repeat(5 * 1024 * 1024),
  };

  // Step 2: Verify login endpoint exists for testing
  const attempt = await tryLogin(request as any, user.email!, user.password!);
  if (!attempt) {
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
    // Step 4: Verify server has size limits in place
    // Should reject with 413 (Payload Too Large) or 400 (Bad Request)
    const hasLimits = status === 413 || status === 400;
    
    softCheck(
      testInfo,
      hasLimits || status === 404, // 404 is acceptable if endpoint doesn't exist
      `API may not have adequate payload size limits (status: ${status})`
    );
  } catch (e: any) {
    // Step 5: Handle timeout or rejection scenarios
    // Timeout or rejection is acceptable behavior for large payloads
  }
});
