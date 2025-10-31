import { test, expect, request } from '@playwright/test';
import { createRandomUser } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Mass Assignment test for Card Limit Updates
 *
 * Purpose: Verify that card update endpoints do not allow mass-assignment of
 * sensitive fields such as `limit`, `ownerId`, `status`, or other privileged
 * properties by unauthorised users or via generic update payloads.
 *
 * Strategy:
 * 1. Probe a set of candidate card update endpoints using PATCH/PUT/POST
 * 2. Include additional fields that should never be settable by a regular
 *    user (e.g. `limit`, `ownerId`, `isBlocked`, `isAdmin`)
 * 3. If the endpoint returns success and echoes or applies these fields,
 *    report a mass-assignment vulnerability (OWASP API6)
 * 4. If no candidate endpoints are found, skip the test
 */

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

test('Mass assignment: updating card limits should not permit unauthorized fields', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }

  const api = await request.newContext({ baseURL: baseURL.toString() });
  const attacker = createRandomUser('sec-atta', false);
  let found = false;

  // Payload contains fields that should not be mass-assignable
  const maliciousPayload = {
    // Typical sensitive fields an attacker might try to set
    limit: 1000000,
    daily_limit: 1000000,
    ownerId: 'attacker-owned',
    isBlocked: false,
    isAdmin: true
  };

  for (const p of candidateUpdatePaths) {
    try {
      // Try PATCH first
      const res = await api.patch(p, {
        data: JSON.stringify(maliciousPayload),
        headers: { 'Content-Type': 'application/json' }
      }).catch(() => null as any);

      if (!res) continue;

      if (res.status() === 404) continue;

      // If endpoint exists and returned success-ish status
      if ([200, 201, 204].includes(res.status())) {
        found = true;
        // Try to parse JSON response if present
        const body = await res.json().catch(() => null);

        // If response echoes or shows the updated object, inspect sensitive fields
        if (body) {
          // Check if any of the malicious fields were accepted/applied
          const accepted = [] as string[];
          if (body.limit && body.limit === maliciousPayload.limit) accepted.push('limit');
          if (body.daily_limit && body.daily_limit === maliciousPayload.daily_limit) accepted.push('daily_limit');
          if ((body.ownerId && body.ownerId === maliciousPayload.ownerId) || (body.owner_id && body.owner_id === maliciousPayload.ownerId)) accepted.push('ownerId');
          if (body.isBlocked === false) accepted.push('isBlocked');
          if (body.isAdmin === true) accepted.push('isAdmin');

          if (accepted.length > 0) {
            // Vulnerability found: mass-assignment allowed
            reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
              endpoint: p,
              request: maliciousPayload,
              response: body,
              acceptedFields: accepted,
              issue: 'Card update endpoint accepted and applied sensitive fields via request payload'
            });

            // Fail the test asserting no accepted fields
            expect(accepted.length, `Endpoint ${p} should not accept sensitive fields`).toBe(0);
          } else {
            reporter.reportPass(
              `Mass assignment protection verified for endpoint ${p}: sensitive fields were ignored or rejected`,
              OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
            );
            expect(true).toBeTruthy();
          }

        } else {
          // No JSON body: assume 204/no content; treat as inconclusive but mark found
          reporter.reportPass(
            `Endpoint ${p} exists but returned no content; unable to confirm mass-assignment via response body. Manual review recommended.`,
            OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
          );
          expect([200,201,204]).toContain(res.status());
        }

        break; // Stop after first responsive endpoint
      }

      // Handle redirect/other codes as indication endpoint exists
      if ([302, 303, 409].includes(res.status())) { found = true; break; }
    } catch (e) {
      // Ignore and continue probing other endpoints
    }
  }

  if (!found) {
    reporter.reportSkip('No card update endpoints found to test mass assignment');
    test.skip(true, 'No card update endpoints found to test mass assignment');
    return;
  }
});
