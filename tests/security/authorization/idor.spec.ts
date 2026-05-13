import { test } from '@playwright/test';
import { IdorProbe } from '../sec-objects/authorization/idor.logic';

test('IDOR: users cannot access other users resources by ID', async ({ request }, testInfo) => {
  await new IdorProbe().checkOtherUsersResources(request, testInfo);
});

test('IDOR: sequential ID enumeration protection', async ({ request }, testInfo) => {
  await new IdorProbe().checkSequentialEnumeration(request, testInfo);
});

test('IDOR: unauthorized access returns 401/403', async ({ request }, testInfo) => {
  await new IdorProbe().checkUnauthorizedAccess(request, testInfo);
});

test('IDOR: parameter manipulation blocked', async ({ request }, testInfo) => {
  await new IdorProbe().checkParameterManipulation(request, testInfo);
});
