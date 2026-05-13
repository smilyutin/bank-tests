import { test } from '@playwright/test';
import { CardLimitMassAssignmentProbe } from '../sec-objects/authorization/card-limit-mass-assignment.logic';

test('Mass assignment: updating card limits should not permit unauthorized fields', async ({ baseURL }, testInfo) => {
  if (!baseURL) {
    test.skip(true, 'baseURL is not provided');
    return;
  }

  await new CardLimitMassAssignmentProbe().check(baseURL.toString(), testInfo);
});
