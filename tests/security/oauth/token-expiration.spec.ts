import { test } from '@playwright/test';
import { OAuthTokenLifecycleProbe } from '../sec-objects/oauth/token-expiration.logic';

test.describe('OAuth token lifecycle checks', () => {
  test('OAuth: expired tokens rejected', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    const probe = new OAuthTokenLifecycleProbe();
    await probe.verifyExpiredTokensRejected(baseURL.toString(), testInfo);
  });

  test('OAuth: refresh tokens work correctly', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    const probe = new OAuthTokenLifecycleProbe();
    await probe.verifyRefreshTokensWorkCorrectly(baseURL.toString(), testInfo);
  });

  test('OAuth: logout invalidates bearer tokens', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    const probe = new OAuthTokenLifecycleProbe();
    await probe.verifyLogoutInvalidatesTokens(baseURL.toString(), testInfo);
  });

  test('OAuth: reasonable expiration times', async ({ baseURL }, testInfo) => {
    if (!baseURL) {
      test.skip(true, 'baseURL is not provided');
      return;
    }

    const probe = new OAuthTokenLifecycleProbe();
    await probe.verifyReasonableExpirationTimes(baseURL.toString(), testInfo);
  });
});
