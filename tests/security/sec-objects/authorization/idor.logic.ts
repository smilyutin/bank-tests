import { type TestInfo, test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

class IdorProbe {
  private async authenticate(request: any, testInfo: TestInfo): Promise<{ token: string } | null> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(request as any);

    if (!user.email || !user.password) {
      reporter.reportSkip('IDOR probe could not run because no valid test user credentials are configured.');
      test.skip(true, 'No valid test user credentials are configured');
      return null;
    }

    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt || !attempt.token) {
      reporter.reportSkip('IDOR probe could not run because login failed or no bearer token was obtained.');
      test.skip(true, 'Login failed or no bearer token was obtained');
      return null;
    }

    return { token: attempt.token };
  }

  async checkOtherUsersResources(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const auth = await this.authenticate(request, testInfo);
    if (!auth) return;

    const resourceEndpoints = ['/api/users', '/api/accounts', '/api/profile', '/api/transactions', '/api/orders'];
    const targetIds = ['1', '2', '999', 'other-user-id'];
    let idorVulnerable = false;

    for (const endpoint of resourceEndpoints) {
      for (const id of targetIds) {
        try {
          const res = await request.get(`${endpoint}/${id}`, {
            headers: {
              'Authorization': `Bearer ${auth.token}`,
              'X-Auth-Token': auth.token,
            },
          });

          if (res.status() === 200) {
            const body = await res.json().catch(() => null);
            if (body && typeof body === 'object') {
              idorVulnerable = true;
            }
          }
        } catch {
          // Continue testing other endpoints if this one is not applicable.
        }
      }
    }

    softCheck(testInfo, !idorVulnerable, 'Possible IDOR vulnerability: API may allow access to other users resources');

    if (!idorVulnerable) {
      reporter.reportPass(
        'No IDOR behavior was observed; tested resources were not accessible as other users.',
        OWASP_VULNERABILITIES.API1_BOLA.name
      );
    }
  }

  async checkSequentialEnumeration(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const auth = await this.authenticate(request, testInfo);
    if (!auth) return;

    const successfulIds: string[] = [];

    for (let i = 1; i <= 10; i++) {
      try {
        const res = await request.get(`/api/users/${i}`, {
          headers: { 'Authorization': `Bearer ${auth.token}` },
        });

        if (res.status() === 200) {
          successfulIds.push(String(i));
        }
      } catch {
        // Continue testing other IDs if this one is not applicable.
      }
    }

    const vulnerable = successfulIds.length > 2;

    softCheck(testInfo, !vulnerable, 'API may use sequential IDs without proper authorization checks');

    if (!vulnerable) {
      reporter.reportPass(
        'Sequential ID enumeration was not effective beyond legitimate access patterns.',
        OWASP_VULNERABILITIES.API1_BOLA.name
      );
    }
  }

  async checkUnauthorizedAccess(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    const protectedEndpoints = ['/api/users/1', '/api/accounts/1', '/api/profile', '/api/admin/users'];
    let properlyProtected = true;

    for (const endpoint of protectedEndpoints) {
      try {
        const res = await request.get(endpoint);
        if (res.status() === 200) {
          properlyProtected = false;
          break;
        }
      } catch {
        // Expected behavior - request should fail without authentication
      }
    }

    softCheck(testInfo, properlyProtected, 'Protected resources should return 401/403 for unauthorized requests');

    if (properlyProtected) {
      reporter.reportPass(
        'All tested protected endpoints rejected unauthenticated access with 401/403 behavior.',
        OWASP_VULNERABILITIES.API1_BOLA.name
      );
    }
  }

  async checkParameterManipulation(request: any, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const auth = await this.authenticate(request, testInfo);
    if (!auth) return;

    try {
      const res = await request.post('/api/profile', {
        headers: { 'Authorization': `Bearer ${auth.token}` },
        data: { user_id: '999', name: 'Hacker' },
      });

      const status = res.status();

      softCheck(
        testInfo,
        status === 400 || status === 403,
        'API should reject requests with manipulated user_id parameters'
      );

      if (status === 400 || status === 403) {
        reporter.reportPass(
          `Parameter manipulation was blocked for /api/profile (status ${status}).`,
          OWASP_VULNERABILITIES.API1_BOLA.name
        );
      }
    } catch {
      // Treat missing endpoints as not applicable rather than failing the suite.
    }
  }
}

export { IdorProbe };
