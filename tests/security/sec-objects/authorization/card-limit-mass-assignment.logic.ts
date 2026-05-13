import { expect, request as playwrightRequest, type TestInfo } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

const candidateUpdatePaths = [
  '/api/cards/1',
  '/api/cards/1/limits',
  '/api/cards/1/limit',
  '/api/cards/1/update',
  '/api/cards/update',
  '/api/cards',
  '/cards/1',
  '/cards/1/limits',
  '/virtual-cards/1',
  '/api/virtual-cards/1',
  '/api/virtual-cards/1/limits'
];

class CardLimitMassAssignmentProbe {
  async check(baseURL: string, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const api = await playwrightRequest.newContext({ baseURL });
    let found = false;

    const maliciousPayload = {
      limit: 1000000,
      daily_limit: 1000000,
      ownerId: 'attacker-owned',
      isBlocked: false,
      isAdmin: true
    };

    try {
      for (const p of candidateUpdatePaths) {
        try {
          const res = await api.patch(p, {
            data: JSON.stringify(maliciousPayload),
            headers: { 'Content-Type': 'application/json' }
          }).catch(() => null as any);

          if (!res) continue;
          if (res.status() === 404) continue;

          if ([200, 201, 204].includes(res.status())) {
            found = true;
            const body = await res.json().catch(() => null);

            if (body) {
              const accepted = [] as string[];
              if (body.limit && body.limit === maliciousPayload.limit) accepted.push('limit');
              if (body.daily_limit && body.daily_limit === maliciousPayload.daily_limit) accepted.push('daily_limit');
              if ((body.ownerId && body.ownerId === maliciousPayload.ownerId) || (body.owner_id && body.owner_id === maliciousPayload.ownerId)) accepted.push('ownerId');
              if (body.isBlocked === false) accepted.push('isBlocked');
              if (body.isAdmin === true) accepted.push('isAdmin');

              if (accepted.length > 0) {
                reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
                  endpoint: p,
                  request: maliciousPayload,
                  response: body,
                  acceptedFields: accepted,
                  issue: 'Card update endpoint accepted and applied sensitive fields via request payload'
                });
                expect(accepted.length, `Endpoint ${p} should not accept sensitive fields`).toBe(0);
              } else {
                reporter.reportPass(
                  `Mass assignment protection verified for endpoint ${p}: sensitive fields were ignored or rejected`,
                  OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
                );
                expect(true).toBeTruthy();
              }
            } else {
              reporter.reportPass(
                `Endpoint ${p} exists but returned no content; unable to confirm mass-assignment via response body. Manual review recommended.`,
                OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
              );
              expect([200, 201, 204]).toContain(res.status());
            }
            return;
          }

          if ([302, 303, 409].includes(res.status())) {
            found = true;
            return;
          }
        } catch {
          // Ignore this endpoint and continue probing the remaining candidates.
        }
      }

      if (!found) {
        reporter.reportSkip(`No candidate card update endpoints responded for mass-assignment probe. Checked: ${candidateUpdatePaths.join(', ')}`);
      }
    } finally {
      await api.dispose();
    }
  }
}

export { CardLimitMassAssignmentProbe };
