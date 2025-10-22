import { test, expect, request } from '@playwright/test';
import { loadUsers } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Excessive Data Exposure Tests (OWASP API3:2023)
 * 
 * These tests verify that API endpoints do not expose sensitive fields
 * like passwords, tokens, or other confidential information in responses.
 * 
 * Security Risks Addressed:
 * 1. Password hash exposure enabling offline cracking
 * 2. Sensitive personal information leakage
 * 3. Privacy violations and compliance issues
 * 4. Credential theft and account compromise
 * 5. API key or token exposure
 * 
 * Expected Behavior:
 * - Passwords and password hashes should never be in responses
 * - API responses should use DTOs to control exposed fields
 * - Only necessary data should be returned
 * - Sensitive fields should be filtered based on user permissions
 */

// Common user endpoint patterns
const candidateUserGet = [
  '/api/users',
  '/users',
  '/api/v1/users'
];

/**
 * Test: User endpoints should not expose password fields
 * 
 * Purpose: Verifies that user data endpoints do not expose sensitive fields
 * like passwords or password hashes in API responses.
 * 
 * Security Impact: Excessive data exposure can lead to:
 * - Password hash exposure enabling offline cracking
 * - Sensitive personal information leakage
 * - Privacy violations and compliance issues
 * - Credential theft and account compromise
 * 
 * Test Strategy:
 * 1. Attempt to retrieve user data from various endpoints
 * 2. Check response for sensitive fields (password, passwordHash)
 * 3. Verify sensitive data is not included in responses
 */
test('Excessive Data Exposure: GET user should not return sensitive fields (password)', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await request.newContext({ baseURL: baseURL.toString() });
  
  // Step 1: Load persisted users for testing
  const users = loadUsers();
  if (users.length === 0) {
    reporter.reportSkip('No persisted users available to check'); 
    test.skip(true, 'No persisted users available to check'); 
    return; 
  }
  const u = users[0];
  let tried = false;
  
  // Step 2: Test individual user endpoint
  for (const base of candidateUserGet) {
    try {
      // Step 3: Try to get specific user by ID
      if ('id' in (u as any) && (u as any).id) {
        const res = await api.get(`${base}/${(u as any).id}`);
        if (res.status() === 200) {
          tried = true;
          const body = await res.json().catch(() => null);
          if (body) {
            // Step 4: Verify password fields are not exposed
            if (body.password !== undefined || body.passwordHash !== undefined) {
              reporter.reportVulnerability('API3_DATA_EXPOSURE', {
                endpoint: `${base}/${(u as any).id}`,
                exposedFields: {
                  password: body.password !== undefined,
                  passwordHash: body.passwordHash !== undefined
                },
                issue: 'Sensitive password fields exposed in API response'
              });
            } else {
              reporter.reportPass(
                'No sensitive password fields exposed in user endpoint response',
                OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
              );
            }
            expect(body.password === undefined && body.passwordHash === undefined).toBeTruthy();
          }
          break;
        }
      }
      
      // Step 5: Try list endpoint and check for sensitive fields
      const res = await api.get(base);
      if (res.status() === 200) {
        tried = true;
        const arr = await res.json().catch(() => null);
        if (Array.isArray(arr) && arr.length > 0) {
          const sample = arr[0];
          // Step 6: Verify no password fields in list response
          if (sample.password !== undefined || sample.passwordHash !== undefined) {
            reporter.reportVulnerability('API3_DATA_EXPOSURE', {
              endpoint: base,
              exposedFields: {
                password: sample.password !== undefined,
                passwordHash: sample.passwordHash !== undefined
              },
              issue: 'Sensitive password fields exposed in user list API response'
            });
          } else {
            reporter.reportPass(
              'No sensitive password fields exposed in user list endpoint response',
              OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
            );
          }
          expect(sample.password === undefined && sample.passwordHash === undefined).toBeTruthy();
        }
        break;
      }
    } catch (e) {
      // Continue testing other endpoints
    }
  }
  
  // Step 7: Skip if no user endpoint found
  if (!tried) {
    reporter.reportSkip('No user listing endpoint found to check for excessive data exposure'); 
    test.skip(true, 'No user listing endpoint found to check for excessive data exposure'); 
    return; 
  }
});

/**
 * Test: API should not expose tokens or API keys
 * 
 * Purpose: Verifies that API endpoints do not accidentally expose tokens,
 * API keys, secrets, or other sensitive credentials in responses.
 */
test('Excessive Data Exposure: API should not expose tokens or secrets', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await request.newContext({ baseURL: baseURL.toString() });
  const users = loadUsers();
  
  if (users.length === 0) {
    reporter.reportSkip('No persisted users available to check');
    test.skip(true, 'No persisted users available to check');
    return;
  }
  
  let tried = false;
  const sensitiveFields = ['token', 'apiKey', 'secret', 'privateKey', 'accessToken', 'refreshToken'];
  
  for (const base of candidateUserGet) {
    try {
      const res = await api.get(base);
      if (res.status() === 200) {
        tried = true;
        const arr = await res.json().catch(() => null);
        
        if (Array.isArray(arr) && arr.length > 0) {
          const sample = arr[0];
          const exposedSensitiveFields = sensitiveFields.filter(field => sample[field] !== undefined);
          
          if (exposedSensitiveFields.length > 0) {
            reporter.reportVulnerability('API3_DATA_EXPOSURE', {
              endpoint: base,
              exposedFields: Object.fromEntries(exposedSensitiveFields.map(f => [f, true])),
              issue: `Sensitive credential fields exposed: ${exposedSensitiveFields.join(', ')}`
            });
            expect(exposedSensitiveFields.length).toBe(0);
          } else {
            reporter.reportPass(
              'No sensitive token/secret fields exposed in API response',
              OWASP_VULNERABILITIES.API3_DATA_EXPOSURE.name
            );
            expect(true).toBeTruthy();
          }
        }
        break;
      }
    } catch (e) {
      // Continue testing
    }
  }
  
  if (!tried) {
    reporter.reportSkip('No user listing endpoint found to check for token exposure');
    test.skip(true, 'No user listing endpoint found');
  }
});
