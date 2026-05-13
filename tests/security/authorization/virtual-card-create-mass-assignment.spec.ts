import { test } from '@playwright/test';
import { VirtualCardCreateMassAssignmentProbe } from '../sec-objects/authorization/virtual-card-create-mass-assignment.logic';

/**
 * Mass Assignment: Virtual Card Creation
 *
 * Targets the documented endpoint: POST /api/virtual-cards (see API docs)
 * Attempts to set sensitive fields during card creation that should be
 * controlled by the server (limit, ownerId, isBlocked, isAdmin, etc.).
 */

test('Mass assignment: creating virtual card should not allow sensitive fields', async ({ baseURL, page }, testInfo) => {
  if (!baseURL) {
    test.skip(true, 'baseURL not provided');
    return;
  }

  await new VirtualCardCreateMassAssignmentProbe().verify(baseURL.toString(), page, testInfo);
});
