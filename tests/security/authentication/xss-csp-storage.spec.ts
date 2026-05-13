import { test } from '@playwright/test';
import { StorageHardeningProbe } from '../sec-objects/authentication/storage-hardening.logic';

/**
 * XSS and browser storage hardening checks.
 *
 * Design note:
 * - Preconditions (user config, login reachability, base page reachability)
 *   are reported via reportWarning with remediation instead of skip.
 * - This keeps CI output explicit about why a check could not fully execute.
 */

test('XSS/Storage: sensitive tokens not in localStorage', async ({ page }, testInfo) => {
  await new StorageHardeningProbe().verifyLocalStorageDoesNotContainSensitiveTokens(page, testInfo);
});

test('XSS: sessionStorage does not contain sensitive data', async ({ page }, testInfo) => {
  await new StorageHardeningProbe().verifySessionStorageDoesNotContainSensitiveData(page, testInfo);
});
