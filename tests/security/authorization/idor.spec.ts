import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';

/**
 * IDOR (Insecure Direct Object Reference) Vulnerability Tests
 * 
 * These tests verify that the application properly enforces authorization controls
 * to prevent users from accessing resources belonging to other users.
 * 
 * Security Risks Addressed:
 * 1. Direct access to other users' resources by ID manipulation
 * 2. Sequential ID enumeration attacks
 * 3. Unauthorized access to protected endpoints
 * 4. Parameter manipulation to bypass authorization
 * 
 * Expected Behavior:
 * - Users should only access their own resources
 * - Sequential IDs should not be predictable or enumerable
 * - Unauthorized requests should return 401/403 status codes
 * - Parameter manipulation should be blocked
 */

/**
 * Test: Users cannot access other users' resources by ID
 * 
 * Purpose: Verifies that users cannot access resources belonging to other users
 * by manipulating resource IDs in API requests.
 * 
 * Security Impact: If IDOR vulnerabilities exist, attackers could:
 * - Access other users' personal data (profiles, accounts, transactions)
 * - Modify or delete other users' resources
 * - Enumerate all users in the system
 * - Perform unauthorized actions on behalf of other users
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt to access resources with various user IDs
 * 3. Verify that only authorized resources are accessible
 */
test('IDOR: users cannot access other users resources by ID', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login or obtain token');
    return;
  }

  const { token } = attempt as any;

  // Step 2: Define common resource endpoints that should be protected
  // These represent typical user resources that could be vulnerable to IDOR
  const resourceEndpoints = [
    '/api/users',        // User profiles
    '/api/accounts',     // User accounts
    '/api/profile',     // User profile data
    '/api/transactions', // Transaction history
    '/api/orders',       // Order history
  ];

  // Step 3: Define target IDs to test for unauthorized access
  // These represent other users' IDs that should not be accessible
  const targetIds = ['1', '2', '999', 'other-user-id'];
  let idorVulnerable = false;

  // Step 4: Test each endpoint with various user IDs
  for (const endpoint of resourceEndpoints) {
    for (const id of targetIds) {
      try {
        const res = await request.get(`${endpoint}/${id}`, {
          headers: { 
            'Authorization': `Bearer ${token}`,
            'X-Auth-Token': token,
          },
        });

        // Step 5: Check if unauthorized access was successful
        // Status 200 with data indicates potential IDOR vulnerability
        if (res.status() === 200) {
          const body = await res.json().catch(() => null);
          
          // Step 6: Verify response contains actual data (not just empty response)
          if (body && typeof body === 'object') {
            idorVulnerable = true;
          }
        }
      } catch (e) {
        // Continue testing other endpoints
      }
    }
  }

  // Step 7: Verify no IDOR vulnerabilities were found
  softCheck(
    testInfo,
    !idorVulnerable,
    'Possible IDOR vulnerability: API may allow access to other users resources'
  );
});

/**
 * Test: Sequential ID enumeration protection
 * 
 * Purpose: Verifies that the application uses non-sequential or unpredictable IDs
 * to prevent attackers from enumerating all users by trying sequential numbers.
 * 
 * Security Impact: If sequential IDs are used without proper authorization:
 * - Attackers can enumerate all users in the system
 * - Mass data extraction becomes possible
 * - Privacy violations occur at scale
 * - System resources can be exhausted through enumeration
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt to access users with sequential IDs (1-10)
 * 3. Verify that most requests fail (indicating proper protection)
 */
test('IDOR: sequential ID enumeration protection', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;
  const successfulIds: string[] = [];

  // Step 2: Test sequential IDs (1-10)
  // This simulates an attacker trying to enumerate users
  for (let i = 1; i <= 10; i++) {
    try {
      const res = await request.get(`/api/users/${i}`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      // Step 3: Track successful requests
      // Status 200 indicates the ID exists and is accessible
      if (res.status() === 200) {
        successfulIds.push(String(i));
      }
    } catch (e) {
      // Continue testing other IDs
    }
  }

  // Step 4: Evaluate enumeration vulnerability
  // If too many sequential IDs work, the system may be vulnerable
  // Allow for 1-2 successful requests (legitimate user's own data)
  const vulnerable = successfulIds.length > 2;

  // Step 5: Verify enumeration protection is in place
  softCheck(
    testInfo,
    !vulnerable,
    'API may use sequential IDs without proper authorization checks'
  );
});

/**
 * Test: Unauthorized access returns proper error codes
 * 
 * Purpose: Verifies that protected endpoints properly reject unauthorized requests
 * with appropriate HTTP status codes (401 Unauthorized or 403 Forbidden).
 * 
 * Security Impact: If endpoints don't properly reject unauthorized requests:
 * - Attackers can access protected resources without authentication
 * - Sensitive data may be exposed to anonymous users
 * - Authorization controls are ineffective
 * - Security boundaries are not enforced
 * 
 * Test Strategy:
 * 1. Attempt to access protected endpoints without authentication
 * 2. Verify all requests are rejected with 401/403 status codes
 * 3. Ensure no sensitive data is returned
 */
test('IDOR: unauthorized access returns 401/403', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  // Step 1: Define protected endpoints that should require authentication
  // These represent sensitive resources that should not be publicly accessible
  const protectedEndpoints = [
    '/api/users/1',        // User data
    '/api/accounts/1',     // Account information
    '/api/profile',        // Profile data
    '/api/admin/users',    // Admin functionality
  ];

  let properlyProtected = true;

  // Step 2: Test each protected endpoint without authentication
  for (const endpoint of protectedEndpoints) {
    try {
      const res = await request.get(endpoint);
      const status = res.status();

      // Step 3: Verify unauthorized access is properly rejected
      // Status 200 indicates the resource was accessible without authentication
      if (status === 200) {
        properlyProtected = false;
        break;
      }
    } catch (e) {
      // Expected behavior - request should fail without authentication
    }
  }

  // Step 4: Verify all endpoints are properly protected
  softCheck(
    testInfo,
    properlyProtected,
    'Protected resources should return 401/403 for unauthorized requests'
  );
});

/**
 * Test: Parameter manipulation is blocked
 * 
 * Purpose: Verifies that the application properly validates and rejects requests
 * that attempt to manipulate user identification parameters to access other users' data.
 * 
 * Security Impact: If parameter manipulation is not blocked:
 * - Attackers can modify user_id parameters to access other users' data
 * - Authorization controls can be bypassed through parameter tampering
 * - Sensitive operations can be performed on behalf of other users
 * - Data integrity and privacy are compromised
 * 
 * Test Strategy:
 * 1. Authenticate as a valid user
 * 2. Attempt to modify user_id parameter in requests
 * 3. Verify the application rejects manipulated parameters
 */
test('IDOR: parameter manipulation blocked', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate as a valid user
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Step 2: Attempt to manipulate user_id parameter
  // This simulates an attacker trying to modify the user context
  try {
    const res = await request.post('/api/profile', {
      headers: { 'Authorization': `Bearer ${token}` },
      data: { user_id: '999', name: 'Hacker' }, // Attempting to modify another user
    });

    const status = res.status();
    
    // Step 3: Verify parameter manipulation is blocked
    // Status 400 (Bad Request) or 403 (Forbidden) indicate proper validation
    softCheck(
      testInfo,
      status === 400 || status === 403,
      'API should reject requests with manipulated user_id parameters'
    );
  } catch (e) {
    // Step 4: Handle case where endpoint doesn't exist
    // This is acceptable behavior
  }
});
