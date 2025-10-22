import { test } from '@playwright/test';
import { softCheck } from '../utils';

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
 * Test: Access-Control-Allow-Origin is restrictive
 * 
 * Purpose: Verifies that the CORS Access-Control-Allow-Origin header
 * is properly configured and not overly permissive.
 * 
 * Security Impact: Permissive CORS policies can lead to:
 * - Cross-origin attacks from malicious websites
 * - Unauthorized data access from other domains
 * - CSRF attacks through cross-origin requests
 * - Data exfiltration to attacker-controlled domains
 * 
 * Test Strategy:
 * 1. Send request with malicious origin header
 * 2. Check Access-Control-Allow-Origin response
 * 3. Verify origin is not wildcard or reflected
 * 4. Ensure proper origin validation
 */
test('CORS: Access-Control-Allow-Origin is restrictive', async ({ request }, testInfo) => {
  try {
    // Step 1: Send request with malicious origin header
    const res = await request.get('/', {
      headers: { 'Origin': 'https://evil.com' },
    });

    const headers = res.headers();
    const allowOrigin = headers['access-control-allow-origin'];

    // Step 2: Check for overly permissive CORS policies
    const isWildcard = allowOrigin === '*';
    const reflectsOrigin = allowOrigin === 'https://evil.com';

    // Step 3: Verify CORS policy is restrictive
    softCheck(
      testInfo,
      !isWildcard && !reflectsOrigin,
      'CORS Access-Control-Allow-Origin should not be * or reflect arbitrary origins'
    );
  } catch (e) {
    // Request might fail - this is acceptable
  }
});

test('CORS: credentials not allowed with wildcard origin', async ({ request }, testInfo) => {
  try {
    const res = await request.get('/api/users', {
      headers: { 'Origin': 'https://untrusted.com' },
    });

    const headers = res.headers();
    const allowOrigin = headers['access-control-allow-origin'];
    const allowCredentials = headers['access-control-allow-credentials'];

    // If credentials are allowed, origin should NOT be *
    if (allowCredentials === 'true') {
      const secure = allowOrigin !== '*';
      
      softCheck(
        testInfo,
        secure,
        'CORS: Access-Control-Allow-Credentials should not be used with wildcard origin (*)'
      );
    }
  } catch (e) {
    // Expected
  }
});

test('CORS: preflight requests properly validated', async ({ request }, testInfo) => {
  try {
    // Send OPTIONS preflight request
    const res = await request.fetch('/api/users', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://malicious.com',
        'Access-Control-Request-Method': 'DELETE',
        'Access-Control-Request-Headers': 'X-Custom-Header',
      },
    });

    const status = res.status();
    const headers = res.headers();
    
    // Preflight should validate origin
    const allowOrigin = headers['access-control-allow-origin'];
    const dangerous = 
      allowOrigin === '*' || 
      allowOrigin === 'https://malicious.com';

    softCheck(
      testInfo,
      !dangerous || status >= 400,
      'CORS preflight should validate and restrict origins'
    );
  } catch (e) {
    // Expected
  }
});

test('CORS: dangerous methods blocked without proper origin', async ({ request }, testInfo) => {
  const dangerousMethods = ['DELETE', 'PUT', 'PATCH'];
  
  for (const method of dangerousMethods) {
    try {
      const res = await request.fetch('/api/users/1', {
        method,
        headers: { 'Origin': 'https://evil.com' },
      });

      const allowOrigin = res.headers()['access-control-allow-origin'];
      
      // Should not allow dangerous methods from arbitrary origins
      const vulnerable = allowOrigin === 'https://evil.com' && res.status() < 400;
      
      if (vulnerable) {
        softCheck(
          testInfo,
          false,
          `CORS allows dangerous ${method} requests from arbitrary origins`
        );
        break;
      }
    } catch (e) {
      // Expected
    }
  }
});

test('CORS: Vary header includes Origin', async ({ request }, testInfo) => {
  try {
    const res = await request.get('/', {
      headers: { 'Origin': 'https://example.com' },
    });

    const headers = res.headers();
    const vary = headers['vary'];
    const allowOrigin = headers['access-control-allow-origin'];

    // If CORS is used, Vary should include Origin for caching
    if (allowOrigin) {
      const hasOriginInVary = vary?.toLowerCase().includes('origin');
      
      softCheck(
        testInfo,
        hasOriginInVary || false,
        'CORS responses should include "Vary: Origin" header for proper caching'
      );
    }
  } catch (e) {
    // Request might fail
  }
});

test('CORS: no origin reflection vulnerability', async ({ request }, testInfo) => {
  const testOrigins = [
    'https://attacker.com',
    'http://localhost:9999',
    'null',
  ];

  let vulnerable = false;

  for (const origin of testOrigins) {
    try {
      const res = await request.get('/api/users', {
        headers: { 'Origin': origin },
      });

      const allowOrigin = res.headers()['access-control-allow-origin'];
      
      // Origin should not be blindly reflected
      if (allowOrigin === origin && origin !== 'null') {
        vulnerable = true;
        break;
      }
    } catch (e) {
      // Continue
    }
  }

  softCheck(
    testInfo,
    !vulnerable,
    'CORS should not blindly reflect Origin header (origin reflection vulnerability)'
  );
});
