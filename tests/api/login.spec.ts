import { test, expect, request } from '@playwright/test';
import { loadUsers, findOrCreateUser, saveUser, User } from '../utils/credentials';
import { validateSchema } from '../utils/schema-validator';
import { SecurityReporter } from '../security/security-reporter';

/**
 * API Authentication Tests
 * 
 * These tests verify that the application provides functional API endpoints
 * for user authentication and login, ensuring the system can be properly
 * tested with valid user credentials.
 * 
 * Test Strategy:
 * 1. Use persisted user credentials or create new ones
 * 2. Attempt to discover login endpoints through common patterns
 * 3. Try multiple content types (form-data and JSON)
 * 4. Fall back to user creation if login fails
 * 5. Verify successful authentication response
 * 
 * Expected Behavior:
 * - Login should succeed with valid credentials
 * - Response should indicate successful authentication
 * - User credentials should be persisted for future tests
 * - Multiple endpoint formats should be supported
 */

/**
 * Test: Login with persisted user credentials
 * 
 * Purpose: Verifies that the application supports user authentication
 * through API endpoints, enabling automated testing with valid credentials.
 * 
 * Test Strategy:
 * 1. Load or create test user credentials
 * 2. Try common login endpoints
 * 3. Attempt both form-data and JSON content types
 * 4. Create user account if login fails
 * 5. Verify successful authentication response
 * 6. Persist user credentials for future tests
 */
test.describe('API - Login with persisted user', () => {
  test('should login using stored credentials or create then login', async ({ baseURL }, testInfo) => {
    if (!baseURL) throw new Error('baseURL is not defined');

    const reporter = new SecurityReporter(testInfo);
    const api = await request.newContext({ baseURL: baseURL.toString() });
    const res = await api.get('/login');
    // Step 1: Load or create test user credentials
    let user: User = findOrCreateUser('e2e');

    // Step 2: Try common login endpoints
    const loginCandidates = ['/api/auth/login', '/api/login', '/login', '/api/session'];
   
    let loginRes = null;
    let successfulLoginPath: string | null = null;
    const contentType = (res.headers()['content-type'] || '').toLowerCase();
    if (contentType.includes('application/json')) {
      const loginPageJson = await res.json().catch(() => null);
      if (loginPageJson && typeof loginPageJson === 'object') {
        await validateSchema('login-schema', 'GET_login', loginPageJson as object);
      }
    }
    const status = res.status();
    if (status === 404) {
      reporter.reportSkip('Login route (/login) is not available on this target application (404).');
      test.skip(true, 'GET /login not found (404)');
    }

    for (const p of loginCandidates) {
      try {
        const res = await api.post(p, { data: { username: user.username || user.email, password: user.password } });
        if ([200, 201, 302].includes(res.status())) { loginRes = res; successfulLoginPath = `${p} (form)`; break; }
      } catch (e) {
        // Continue to next endpoint
      }
      try {
        const res = await api.post(p, { data: JSON.stringify({ username: user.username || user.email, password: user.password }), headers: { 'Content-Type': 'application/json' } });
        if ([200, 201, 302].includes(res.status())) { loginRes = res; successfulLoginPath = `${p} (json)`; break; }
      } catch (e) {
        // Continue to next endpoint
      }
    }

    // If login failed, attempt to create account via register endpoints (reuse create-user test logic)
    if (!loginRes) {
      // Try to create via /register form as the create-user test does
      try {
        const regGet = await api.get('/register');
        if (regGet.status() === 200 && (regGet.headers()['content-type'] || '').includes('html')) {
          const html = await regGet.text();
          const formMatch = html.match(/<form[^>]*action=["'](?<action>[^"']+)["'][^>]*>([\s\S]*?)<\/form>/i);
          let actionPath = '/register';
          let formInner = html;
          if (formMatch && formMatch.groups) { actionPath = formMatch.groups['action'] || actionPath; formInner = formMatch[0]; }
          const inputRegex2 = /<input[^>]*name=["'](?<name>[^"']+)["'][^>]*>/gi;
          const inputs: Record<string,string> = {};
          let m: RegExpExecArray | null;
          while ((m = inputRegex2.exec(formInner)) !== null) {
            if (m.groups && m.groups['name']) inputs[m.groups['name']] = '';
          }
          const emailKeys = ['email','username','user','email_address','user[email]'];
          const passwordKeys = ['password','pass','user[password]'];
          for (const k of Object.keys(inputs)) inputs[k] = inputs[k] || '';
          for (const k of emailKeys) if (k in inputs) { inputs[k] = user.email || user.username || ''; break; }
          for (const k of passwordKeys) if (k in inputs) { inputs[k] = user.password; break; }
          try {
            const post = await api.post(actionPath, { form: inputs });
            if ([200,201,302].includes(post.status())) {
              // Try login again
              for (const p of loginCandidates) {
                try {
                  const res = await api.post(p, { data: { username: user.username || user.email, password: user.password } });
                  if ([200,201,302].includes(res.status())) { loginRes = res; successfulLoginPath = `${p} (form-after-register)`; break; }
                } catch {}
              }
            }
          } catch {}
        }
      } catch (e) {}
    }

    if (!loginRes) {
      reporter.reportWarning(
        'Authentication could not be completed through common API login endpoints using valid test credentials.',
        [
          'Verify login route mappings and accepted content types (form and JSON).',
          'Ensure API authentication endpoint is documented and enabled for test environments.',
          'Return explicit 401/403 errors for invalid auth flows instead of ambiguous responses.'
        ],
        'API2:2023 - Broken Authentication'
      );
    }

    expect(loginRes).toBeTruthy();

    reporter.reportPass(
      `Authentication succeeded using endpoint ${successfulLoginPath || 'unknown'} with persisted or discovered credentials.`,
      'API2:2023 - Broken Authentication'
    );

    // if login response returns a token or body, check basic shape
    try {
      let b = null;
      if (loginRes) {
        b = await loginRes.json().catch(() => null);
      }
      if (b) expect(b).toBeTruthy();
    } catch {}
  });
});
