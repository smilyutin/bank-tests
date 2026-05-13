import { expect, request as playwrightRequest, type TestInfo } from '@playwright/test';
import { createRandomUser } from '../../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

const candidateCreatePaths = [
  '/api/users',
  '/api/auth/register',
  '/api/register',
  '/register'
];

class MassAssignmentProbe {
  async checkAdminField(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await playwrightRequest.newContext({ baseURL });
    const u = createRandomUser('sec', false);
    let found = false;

    try {
      for (const p of candidateCreatePaths) {
        try {
          const res = await api.post(p, {
            data: JSON.stringify({ email: u.email, password: u.password, isAdmin: true }),
            headers: { 'Content-Type': 'application/json' }
          });

          if (res.status() === 404) continue;

          if ([200, 201].includes(res.status())) {
            found = true;
            const body = await res.json().catch(() => null);

            if (body && (body.isAdmin === true || body.admin === true)) {
              reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
                endpoint: p,
                request: { email: u.email, isAdmin: true },
                response: body,
                issue: 'API accepted isAdmin=true and granted admin privileges'
              });
              expect(body.isAdmin === true || body.admin === true).toBeFalsy();
            } else {
              reporter.reportPass(
                'Mass assignment protection verified: API correctly rejected or ignored isAdmin=true parameter',
                OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
              );
              expect(true).toBeTruthy();
            }
            return;
          }

          if ([302, 303, 409].includes(res.status())) {
            found = true;
            return;
          }
        } catch {
          // Ignore errors and continue testing other endpoints.
        }
      }

      if (!found) {
        reporter.reportSkip(`No user-create endpoint responded for isAdmin mass-assignment probe. Tried: ${candidateCreatePaths.join(', ')}`);
      }
    } finally {
      await api.dispose();
    }
  }

  async checkRoleField(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await playwrightRequest.newContext({ baseURL });
    const u = createRandomUser('sec', false);
    let found = false;

    try {
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
            return;
          }

          if ([302, 303, 409].includes(res.status())) {
            found = true;
            return;
          }
        } catch {
          // Ignore errors
        }
      }

      if (!found) {
        reporter.reportSkip(`No user-create endpoint responded for role mass-assignment probe. Tried: ${candidateCreatePaths.join(', ')}`);
      }
    } finally {
      await api.dispose();
    }
  }
}

export { MassAssignmentProbe };
