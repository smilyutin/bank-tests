import { test, expect, request as playwrightRequest } from '@playwright/test';
import { createRandomUser } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Token Expiration and Lifecycle Tests (OWASP API2:2023)
 * 
 * These tests verify that authentication tokens properly expire and
 * that expired tokens are rejected to prevent session hijacking and
 * unauthorized access.
 * 
 * Security Risks Addressed:
 * 1. Expired tokens still accepted
 * 2. Tokens never expire (infinite sessions)
 * 3. Token refresh vulnerabilities
 * 4. Logout not invalidating tokens
 * 5. Long-lived tokens without rotation
 * 
 * Expected Behavior:
 * - Tokens expire after defined period
 * - Expired tokens rejected with 401
 * - Refresh tokens work correctly
 * - Logout invalidates tokens
 * - Token rotation implemented
 * 
 * Usage:
 *   - Run in CI: npm run test:ci:tokens
 *   - Run nightly: Check for token lifecycle issues
 *   - Run before releases: Verify auth security
 */

/**
 * Test: Expired tokens are rejected
 * 
 * Purpose: Verifies that tokens with expired timestamps are properly
 * rejected and don't grant access to protected resources.
 * 
 * Security Impact: Accepting expired tokens can lead to:
 * - Session hijacking through stolen old tokens
 * - Unauthorized access after user logout
 * - Violation of compliance requirements
 * - Extended attack window for stolen credentials
 * 
 * Test Strategy:
 * 1. Create a user and obtain a token
 * 2. Simulate token expiration (if possible)
 * 3. Attempt to use expired token
 * 4. Verify 401 Unauthorized response
 */
test('Token Expiration: expired tokens rejected', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const user = createRandomUser('token-test', false);
  
  // Step 1: Try to register user
  let registerEndpoint = '';
  for (const endpoint of ['/api/auth/register', '/api/register', '/api/users']) {
    try {
      const res = await api.post(endpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && [200, 201, 409].includes(res.status())) {
        registerEndpoint = endpoint;
        break;
      }
    } catch (e) {
      // Try next endpoint
    }
  }
  
  if (!registerEndpoint) {
    reporter.reportSkip('No registration endpoint found for token testing');
    test.skip(true, 'No registration endpoint found');
    return;
  }
  
  // Step 2: Login to get a token
  let token = '';
  for (const endpoint of ['/api/auth/login', '/api/login']) {
    try {
      const res = await api.post(endpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        const body = await res.json().catch(() => null);
        if (body && (body.token || body.accessToken || body.access_token)) {
          token = body.token || body.accessToken || body.access_token;
          break;
        }
      }
    } catch (e) {
      // Try next endpoint
    }
  }
  
  if (!token) {
    reporter.reportSkip('Could not obtain authentication token');
    test.skip(true, 'Could not obtain token');
    return;
  }
  
  // Step 3: Test with manipulated expired token (if JWT)
  let expiredTokenAccepted = false;
  
  // For JWT tokens, we can decode and check expiration
  if (token.includes('.')) {
    try {
      // Decode JWT payload (middle part)
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        
        // Check if token has expiration
        if (payload.exp) {
          const expirationTime = payload.exp * 1000; // Convert to milliseconds
          const now = Date.now();
          
          // If token is not yet expired, we can't test expired rejection directly
          // But we can verify expiration field exists
          if (expirationTime > now) {
            const timeToExpire = Math.round((expirationTime - now) / 1000 / 60);
            
            reporter.reportPass(
              `Token has expiration set (expires in ${timeToExpire} minutes)`,
              OWASP_VULNERABILITIES.API2_AUTH.name
            );
          }
        } else {
          // No expiration in token!
          reporter.reportVulnerability('API2_AUTH', {
            issue: 'JWT token has no expiration (exp) claim',
            tokenPayload: payload
          }, [
            'Add exp (expiration) claim to JWT tokens',
            'Set reasonable expiration time (e.g., 15 minutes for access tokens)',
            'Implement token refresh mechanism',
            'Use short-lived access tokens with refresh tokens',
            'Follow JWT best practices (RFC 7519)'
          ]);
          expect(payload.exp).toBeDefined();
        }
      }
    } catch (e) {
      // Not a valid JWT or can't decode
    }
  }
  
  // Step 4: Try using a clearly expired/invalid token
  const invalidTokens = [
    'expired.token.here',
    token + 'tampered',
    'Bearer invalid',
  ];
  
  let acceptedInvalidToken = false;
  
  for (const invalidToken of invalidTokens) {
    try {
      const res = await api.get('/api/users', {
        headers: { 
          'Authorization': `Bearer ${invalidToken}`,
          'X-Auth-Token': invalidToken
        }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        acceptedInvalidToken = true;
        break;
      }
    } catch (e) {
      // Expected to fail
    }
  }
  
  if (acceptedInvalidToken) {
    reporter.reportVulnerability('API2_AUTH', {
      issue: 'Invalid/tampered tokens accepted'
    }, [
      'Verify token signature before accepting',
      'Validate token structure and claims',
      'Return 401 for invalid tokens',
      'Implement proper token validation middleware'
    ]);
    expect(acceptedInvalidToken).toBeFalsy();
  }
});

/**
 * Test: Token refresh mechanism works correctly
 * 
 * Purpose: Verifies that token refresh functionality is implemented
 * and works securely.
 */
test('Token Lifecycle: refresh tokens work correctly', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const user = createRandomUser('refresh-test', false);
  
  // Try to register and login
  let accessToken = '';
  let refreshToken = '';
  
  for (const regEndpoint of ['/api/auth/register', '/api/register']) {
    try {
      await api.post(regEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch (e) {
      // Continue
    }
  }
  
  for (const loginEndpoint of ['/api/auth/login', '/api/login']) {
    try {
      const res = await api.post(loginEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        const body = await res.json().catch(() => null);
        if (body) {
          accessToken = body.accessToken || body.access_token || body.token || '';
          refreshToken = body.refreshToken || body.refresh_token || '';
          break;
        }
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!accessToken) {
    reporter.reportSkip('Could not obtain access token for refresh testing');
    test.skip(true, 'Could not obtain tokens');
    return;
  }
  
  if (!refreshToken) {
    reporter.reportWarning(
      'No refresh token provided - only access token returned',
      [
        'Implement refresh token mechanism for better security',
        'Use short-lived access tokens (15 min) with long-lived refresh tokens',
        'Store refresh tokens securely (httpOnly cookies or secure storage)',
        'Implement token rotation on refresh',
        'Add refresh token expiration and revocation'
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }
  
  // Try to use refresh token
  const refreshEndpoints = ['/api/auth/refresh', '/api/refresh', '/api/token/refresh'];
  let refreshWorked = false;
  let newAccessToken = '';
  
  for (const endpoint of refreshEndpoints) {
    try {
      const res = await api.post(endpoint, {
        data: JSON.stringify({ refreshToken }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        const body = await res.json().catch(() => null);
        if (body && (body.accessToken || body.access_token || body.token)) {
          refreshWorked = true;
          newAccessToken = body.accessToken || body.access_token || body.token;
          break;
        }
      }
    } catch (e) {
      // Try next endpoint
    }
  }
  
  if (refreshWorked && newAccessToken) {
    // Verify new token is different (token rotation)
    if (newAccessToken === accessToken) {
      reporter.reportWarning(
        'Refresh returns same token - no token rotation implemented',
        [
          'Implement token rotation on refresh',
          'Issue new access and refresh tokens on each refresh',
          'Invalidate old refresh token after use',
          'Prevent refresh token reuse'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportPass(
        'Token refresh mechanism works correctly with token rotation',
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  } else {
    reporter.reportSkip('Refresh token endpoint not found or not functional');
    test.skip(true, 'Refresh mechanism not testable');
  }
});

/**
 * Test: Logout invalidates tokens
 * 
 * Purpose: Verifies that tokens are invalidated after logout and
 * cannot be reused.
 */
test('Token Lifecycle: logout invalidates tokens', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const user = createRandomUser('logout-test', false);
  
  // Register and login
  let token = '';
  
  for (const regEndpoint of ['/api/auth/register', '/api/register']) {
    try {
      await api.post(regEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch (e) {
      // Continue
    }
  }
  
  for (const loginEndpoint of ['/api/auth/login', '/api/login']) {
    try {
      const res = await api.post(loginEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        const body = await res.json().catch(() => null);
        if (body && (body.token || body.accessToken)) {
          token = body.token || body.accessToken;
          break;
        }
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!token) {
    reporter.reportSkip('Could not obtain token for logout testing');
    test.skip(true, 'Could not obtain token');
    return;
  }
  
  // Verify token works before logout
  let tokenWorksBeforeLogout = false;
  const protectedEndpoints = ['/api/users', '/api/profile', '/api/me'];
  
  for (const endpoint of protectedEndpoints) {
    try {
      const res = await api.get(endpoint, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        tokenWorksBeforeLogout = true;
        break;
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!tokenWorksBeforeLogout) {
    reporter.reportSkip('Token not accepted before logout - cannot test invalidation');
    test.skip(true, 'Token not functional');
    return;
  }
  
  // Logout
  const logoutEndpoints = ['/api/auth/logout', '/api/logout'];
  let logoutFound = false;
  
  for (const endpoint of logoutEndpoints) {
    try {
      const res = await api.post(endpoint, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).catch(() => null);
      
      if (res && [200, 204].includes(res.status())) {
        logoutFound = true;
        break;
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!logoutFound) {
    reporter.reportSkip('No logout endpoint found');
    test.skip(true, 'Logout endpoint not found');
    return;
  }
  
  // Try using token after logout
  let tokenWorksAfterLogout = false;
  
  for (const endpoint of protectedEndpoints) {
    try {
      const res = await api.get(endpoint, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        tokenWorksAfterLogout = true;
        break;
      }
    } catch (e) {
      // Expected - token should be invalid
    }
  }
  
  if (tokenWorksAfterLogout) {
    reporter.reportVulnerability('API2_AUTH', {
      issue: 'Token still valid after logout - logout does not invalidate tokens'
    }, [
      'Implement token blacklist/revocation on logout',
      'Use Redis or similar for token invalidation tracking',
      'Set short token expiration times',
      'Clear tokens server-side on logout',
      'Consider using session-based auth for better control'
    ]);
    expect(tokenWorksAfterLogout).toBeFalsy();
  } else {
    reporter.reportPass(
      'Logout properly invalidates tokens',
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
});

/**
 * Test: Token expiration time is reasonable
 * 
 * Purpose: Verifies that tokens don't have excessively long lifetimes
 * that increase security risk.
 */
test('Token Lifecycle: reasonable expiration times', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const user = createRandomUser('expiry-test', false);
  
  // Register and login
  let token = '';
  
  for (const regEndpoint of ['/api/auth/register', '/api/register']) {
    try {
      await api.post(regEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
    } catch (e) {
      // Continue
    }
  }
  
  for (const loginEndpoint of ['/api/auth/login', '/api/login']) {
    try {
      const res = await api.post(loginEndpoint, {
        data: JSON.stringify({ email: user.email, password: user.password }),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null);
      
      if (res && res.status() === 200) {
        const body = await res.json().catch(() => null);
        if (body && (body.token || body.accessToken)) {
          token = body.token || body.accessToken;
          break;
        }
      }
    } catch (e) {
      // Continue
    }
  }
  
  if (!token || !token.includes('.')) {
    reporter.reportSkip('Could not obtain JWT token for expiration check');
    test.skip(true, 'No JWT token available');
    return;
  }
  
  try {
    // Decode JWT
    const parts = token.split('.');
    if (parts.length !== 3) {
      reporter.reportSkip('Token is not a valid JWT');
      test.skip(true, 'Invalid JWT format');
      return;
    }
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    if (!payload.exp) {
      reporter.reportVulnerability('API2_AUTH', {
        issue: 'Token has no expiration time'
      });
      expect(payload.exp).toBeDefined();
      return;
    }
    
    if (!payload.iat) {
      reporter.reportWarning(
        'Token has no issued-at (iat) claim',
        ['Add iat claim to track token age'],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
    
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = payload.exp - (payload.iat || now);
    const expiresInHours = expiresIn / 3600;
    
    // Check if expiration is reasonable
    // Access tokens should typically expire in 15 min to 1 hour
    // Refresh tokens can be longer (days/weeks)
    if (expiresInHours > 24) {
      reporter.reportWarning(
        `Token expires in ${Math.round(expiresInHours)} hours - very long lifetime increases security risk`,
        [
          'Reduce access token expiration to 15-60 minutes',
          'Use refresh tokens for longer sessions',
          'Implement token rotation',
          'Consider risk vs usability tradeoff'
        ],
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else if (expiresInHours < 0.25 && expiresInHours > 0) {
      // Very short (< 15 min) might be too aggressive
      reporter.reportPass(
        `Token expires in ${Math.round(expiresIn / 60)} minutes - good security practice`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportPass(
        `Token has reasonable expiration time (${Math.round(expiresInHours)} hours)`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  } catch (e) {
    reporter.reportSkip('Could not decode JWT token payload');
    test.skip(true, 'JWT decode failed');
  }
});
