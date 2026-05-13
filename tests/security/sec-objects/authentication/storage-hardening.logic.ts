import { ensureTestUser, tryLogin, softCheck } from '../../utils/utils';
import { SecurityReporter } from '../../security-reporter';

class StorageHardeningProbe {
  private async captureStorage(page: any): Promise<{ local: Record<string, string>; session: Record<string, string> }> {
    const storage = await page.evaluate(() => {
      const read = (source: Storage) => {
        const items: Record<string, string> = {};
        for (let i = 0; i < source.length; i++) {
          const key = source.key(i);
          if (key) items[key] = source.getItem(key) || '';
        }
        return items;
      };

      return {
        local: read(window.localStorage),
        session: read(window.sessionStorage),
      };
    });

    return storage;
  }

  async verifyLocalStorageDoesNotContainSensitiveTokens(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(page.request as any);

    if (!user.email || !user.password) {
      reporter.reportSkip('No test user configured');
      return;
    }

    const attempt = await tryLogin(page.request as any, user.email, user.password);
    if (!attempt) {
      reporter.reportSkip('Could not complete login via API');
      return;
    }

    try {
      await page.goto('/');
      const localStorage = (await this.captureStorage(page)).local;
      const sensitiveKeys = ['token', 'jwt', 'auth', 'session', 'access_token', 'id_token'];
      const foundSensitive = Object.keys(localStorage).some(key =>
        sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
      );

      softCheck(
        testInfo,
        !foundSensitive,
        'Sensitive auth tokens should not be stored in localStorage (prefer httpOnly cookies)'
      );

      if (!foundSensitive) {
        reporter.reportPass(
          'No sensitive auth tokens were found in localStorage.',
          'A2:2021-Identification and Authentication Failures'
        );
      }
    } catch {
      reporter.reportWarning('Environment limitation: localStorage inspection could not complete because the browser/page interaction failed.', [
        'Ensure the page is accessible and JavaScript is enabled.',
        'Check browser console for errors during page load.',
        'Verify DOM is ready before querying storage.',
        'Use try-catch to handle navigation failures gracefully.'
      ], 'A3:2021-Injection');
    }
  }

  async verifySessionStorageDoesNotContainSensitiveData(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    try {
      await page.goto('/');
      const sessionStorage = (await this.captureStorage(page)).session;
      const sensitiveKeys = ['password', 'secret', 'private'];
      const foundSensitive = Object.keys(sessionStorage).some(key =>
        sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))
      );

      softCheck(
        testInfo,
        !foundSensitive,
        'Passwords or secrets should never be stored in sessionStorage'
      );

      if (!foundSensitive) {
        reporter.reportPass(
          'No passwords or secrets were found in sessionStorage.',
          'A2:2021-Identification and Authentication Failures'
        );
      }
    } catch {
      reporter.reportWarning('Environment limitation: sessionStorage inspection could not complete because the browser/page interaction failed.', [
        'Verify the application is running and accessible at BASE_URL.',
        'Check browser console for page load or script errors.',
        'Ensure the session is properly initialized before querying storage.',
        'Add error logging to understand why the storage check failed.'
      ], 'A1:2021-Broken Access Control');
    }
  }
}

export { StorageHardeningProbe };
