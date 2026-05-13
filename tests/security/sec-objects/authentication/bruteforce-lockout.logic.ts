import { test } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Add brute-force protection on login endpoints (per-IP and per-user limits)',
  '2) Return HTTP 429 with Retry-After when thresholds are exceeded',
  '3) Implement account lockout or progressive backoff after repeated failures',
  '4) Monitor and alert on repeated failed authentication attempts',
];

class BruteForceLockoutProbe {
  async verify(request: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const user = await ensureTestUser(request as any);
    if (!user.email) {
      reporter.reportSkip('Brute-force probe could not run because no test user is configured.');
      test.skip(true, 'No test user configured for brute-force test');
      return;
    }

    const attempts = 6;
    let throttled = false;
    let throttleReason = '';
    let throttleAtAttempt = -1;
    const statuses: number[] = [];
    let loginPath = 'unknown';

    for (let i = 0; i < attempts; i++) {
      const attempt = await tryLogin(request as any, user.email, 'bad-password-' + i);
      if (!attempt) {
        reporter.reportSkip('Environment limitation: brute-force probe could not run because the login endpoint was not found or was unreachable.');
        test.skip(true, 'Login endpoint not found or unreachable for brute-force test');
        return;
      }

      const { res, path } = attempt as any;
      loginPath = path || loginPath;
      const status = res.status();
      statuses.push(status);

      if (status === 429) {
        throttled = true;
        throttleReason = `Server returned HTTP 429 on attempt ${i + 1}`;
        throttleAtAttempt = i + 1;
        break;
      }

      const headers = res.headers();
      if (headers['retry-after'] || headers['x-ratelimit-remaining'] === '0') {
        throttled = true;
        throttleReason = headers['retry-after']
          ? `Server returned Retry-After header on attempt ${i + 1}`
          : `X-RateLimit-Remaining reached 0 on attempt ${i + 1}`;
        throttleAtAttempt = i + 1;
        break;
      }
    }

    const statusSummary = `[${statuses.join(', ')}]`;

    if (throttled) {
      reporter.reportPass(
        `System is protected: brute-force throttling/lockout signal detected on ${loginPath} after ${throttleAtAttempt} failed attempts. ` +
        `Reason: ${throttleReason}. Observed status progression: ${statusSummary}. ` +
        `This helps prevent credential stuffing and password-guessing attacks.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
      return;
    }

    reporter.reportWarning(
      `True vulnerability: no brute-force throttling was detected. ${attempts} failed login attempts to ${loginPath} did not trigger 429 or lockout headers. ` +
      `Observed status progression: ${statusSummary}. ` +
      `Risk: an attacker can perform repeated password guessing with limited friction.`,
      [
        ...TARGET_APP_FIX_FIRST,
        `Apply strict auth throttling policy on ${loginPath} (e.g., 5-10 failed attempts per minute).`,
        'Use combined controls: per-user, per-IP, and global rate limits.',
        'Add temporary lockout/CAPTCHA challenge after the threshold is exceeded.',
        'Record auth-failure telemetry and feed SIEM detection rules.',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
  }
}

export { BruteForceLockoutProbe };
