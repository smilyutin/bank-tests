import { test } from '@playwright/test';
import { MassAssignmentProbe } from '../sec-objects/authorization/mass-assignment.logic';

test.describe('Mass Assignment Vulnerability Tests', () => {
  test('Mass assignment: creating user should not allow isAdmin=true', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    await new MassAssignmentProbe().checkAdminField(baseURL.toString(), testInfo);
  });

  test('Mass assignment: creating user should not allow role assignment', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    await new MassAssignmentProbe().checkRoleField(baseURL.toString(), testInfo);
  });
});
