import { test } from '@playwright/test';
import { LogoutClearsSessionProbe } from '../sec-objects/authentication/logout-clears-session.logic';

// Verify that logout removes both browser state and any stored session tokens.
test('UI logout clears browser session state', async ({ browser }, testInfo) => {
  await new LogoutClearsSessionProbe().verify(browser, testInfo);
});
