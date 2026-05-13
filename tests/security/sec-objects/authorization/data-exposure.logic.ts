import { expect, request as playwrightRequest, type TestInfo } from '@playwright/test';
import { loadUsers } from '../../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

const candidateUserGet = [
  '/api/users',
  '/users',
  '/api/v1/users'
];

class DataExposureProbe {
  async checkUserPasswordFields(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await playwrightRequest.newContext({ baseURL });

    try {
      const users = loadUsers();
      if (users.length === 0) {
        reporter.reportSkip('No persisted users available for data-exposure validation.');
        return;
      }
      const u = users[0];
      let tried = false;

      for (const base of candidateUserGet) {
        try {
          if ('id' in (u as any) && (u as any).id) {
            const res = await api.get(`${base}/${(u as any).id}`);
            if (res.status() === 200) {
              tried = true;
              const body = await res.json().catch(() => null);
              if (body) {
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
              return;
            }
          }

          const res = await api.get(base);
          if (res.status() === 200) {
            tried = true;
            const arr = await res.json().catch(() => null);
            if (Array.isArray(arr) && arr.length > 0) {
              const sample = arr[0];
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
            return;
          }
        } catch {
          // Continue testing other endpoints if this one responds unexpectedly.
        }
      }

      if (!tried) {
        reporter.reportSkip(`No user endpoint responded for excessive data exposure checks. Tried: ${candidateUserGet.join(', ')}`);
        return;
      }
    } finally {
      await api.dispose();
    }
  }

  async checkSecretsExposure(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await playwrightRequest.newContext({ baseURL });

    try {
      const users = loadUsers();
      if (users.length === 0) {
        reporter.reportSkip('No persisted users available for token/secret exposure validation.');
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
            return;
          }
        } catch {
          // Continue testing other endpoints if this one responds unexpectedly.
        }
      }

      if (!tried) {
        reporter.reportSkip(`No user listing endpoint responded for token/secret exposure checks. Tried: ${candidateUserGet.join(', ')}`);
      }
    } finally {
      await api.dispose();
    }
  }
}

export { DataExposureProbe };
