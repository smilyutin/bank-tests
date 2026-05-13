import { test } from '@playwright/test';
import { DataExposureProbe } from '../sec-objects/authorization/data-exposure.logic';

test.describe('Excessive Data Exposure Tests', () => {
  test('Excessive Data Exposure: GET user should not return sensitive fields (password)', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    await new DataExposureProbe().checkUserPasswordFields(baseURL.toString(), testInfo);
  });

  test('Excessive Data Exposure: API should not expose tokens or secrets', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    await new DataExposureProbe().checkSecretsExposure(baseURL.toString(), testInfo);
  });
});
