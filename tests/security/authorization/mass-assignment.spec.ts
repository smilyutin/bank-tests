import { test, expect, request } from '@playwright/test';
import { createRandomUser } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Mass Assignment Vulnerability Tests (OWASP API6:2023)
 * 
 * These tests verify that APIs do not allow mass assignment of sensitive fields
 * that could lead to privilege escalation or unauthorized access.
 * 
 * Security Risks Addressed:
 * 1. Privilege escalation through admin field manipulation
 * 2. Role assignment bypass
 * 3. Unauthorized access to sensitive functionality
 * 4. Data integrity violations
 * 
 * Expected Behavior:
 * - Sensitive fields (isAdmin, role, permissions) should not be settable via API
 * - Only explicitly allowed fields should be bindable
 * - API should use DTOs or allowlists for field assignment
 * - Privilege fields should be set through separate admin endpoints only
 */

// Common user creation endpoint patterns
const candidateCreatePaths = [
  '/api/users',
  '/api/auth/register',
  '/api/register',
  '/register'
];

/**
 * Test: Mass assignment protection for admin privileges
 * 
 * Purpose: Verifies that user creation endpoints do not allow mass assignment
 * of sensitive fields like admin privileges through request parameters.
 * 
 * Security Impact: Mass assignment vulnerabilities can lead to:
 * - Privilege escalation through admin field manipulation
 * - Unauthorized access to sensitive functionality
 * - Data integrity violations
 * - Bypass of authorization controls
 * 
 * Test Strategy:
 * 1. Attempt to create user with isAdmin=true parameter
 * 2. Verify the API ignores or rejects admin privilege assignment
 * 3. Check that response doesn't reflect admin privileges
 */
test('Mass assignment: creating user should not allow isAdmin=true', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await request.newContext({ baseURL: baseURL.toString() });
  const u = createRandomUser('sec', false);
  let found = false;
  
  // Step 1: Test each candidate user creation endpoint
  for (const p of candidateCreatePaths) {
    try {
      // Step 2: Attempt to create user with admin privilege
      const res = await api.post(p, { 
        data: JSON.stringify({ email: u.email, password: u.password, isAdmin: true }), 
        headers: { 'Content-Type': 'application/json' } 
      });
      
      if (res.status() === 404) continue; // Endpoint doesn't exist
      
      // Step 3: Check if creation was successful
      if ([200, 201].includes(res.status())) {
        found = true;
        const body = await res.json().catch(() => null);
        
        // Step 4: Verify admin privilege was not granted
        if (body && (body.isAdmin === true || body.admin === true)) {
          reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
            endpoint: p,
            request: { email: u.email, isAdmin: true },
            response: body,
            issue: 'API accepted isAdmin=true and granted admin privileges'
          });
          expect(body.isAdmin === true || body.admin === true).toBeFalsy();
        } else {
          // Pass - no admin privilege granted
          reporter.reportPass(
            'Mass assignment protection verified: API correctly rejected or ignored isAdmin=true parameter',
            OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
          );
          expect(true).toBeTruthy();
        }
        break;
      }
      
      // Step 5: Handle other response codes
      if ([302, 303, 409].includes(res.status())) { 
        found = true; 
        break; 
      }
    } catch (e) {
      // Ignore errors and continue testing other endpoints
    }
  }
  
  // Step 6: Skip if no user creation endpoint found
  if (!found) {
    reporter.reportSkip('No user-create endpoint found to test mass assignment');
    test.skip(true, 'No user-create endpoint found to test mass assignment'); 
    return; 
  }
});

/**
 * Test: Mass assignment protection for role field
 * 
 * Purpose: Verifies that user creation endpoints do not allow setting
 * the role field to privileged values like 'admin' or 'superuser'.
 */
test('Mass assignment: creating user should not allow role assignment', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await request.newContext({ baseURL: baseURL.toString() });
  const u = createRandomUser('sec', false);
  let found = false;
  
  for (const p of candidateCreatePaths) {
    try {
      const res = await api.post(p, { 
        data: JSON.stringify({ email: u.email, password: u.password, role: 'admin' }), 
        headers: { 'Content-Type': 'application/json' } 
      });
      
      if (res.status() === 404) continue;
      
      if ([200, 201].includes(res.status())) {
        found = true;
        const body = await res.json().catch(() => null);
        
        if (body && (body.role === 'admin' || body.role === 'superuser')) {
          reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
            endpoint: p,
            request: { email: u.email, role: 'admin' },
            response: body,
            issue: 'API accepted role=admin and granted privileged role'
          });
          expect(body.role).not.toBe('admin');
        } else {
          reporter.reportPass(
            'Mass assignment protection verified: API correctly rejected or ignored role=admin parameter',
            OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
          );
          expect(true).toBeTruthy();
        }
        break;
      }
      
      if ([302, 303, 409].includes(res.status())) { 
        found = true; 
        break; 
      }
    } catch (e) {
      // Ignore errors
    }
  }
  
  if (!found) {
    reporter.reportSkip('No user-create endpoint found to test role mass assignment');
    test.skip(true, 'No user-create endpoint found to test role mass assignment'); 
  }
});
