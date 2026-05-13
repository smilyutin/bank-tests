import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, parseSetCookieFlags } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'What to fix in the target app first (priority order):',
  '1) Ensure authentication always sets a session/auth cookie on successful login flow',
  '2) Set HttpOnly and Secure flags on all auth/session cookies',
  '3) Set SameSite=Lax or SameSite=Strict for auth/session cookies',
  '4) Standardize cookie policy across environments and gateways (app, proxy, CDN)',
];

// Review the login response cookie directly so the cookie flags can be validated at the source.

test('Auth cookie flags from login response (Secure, HttpOnly, SameSite)', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  if (!user.email || !user.password) {
    reporter.reportSkip('No test user configured for cookie test');
    test.skip(true, 'No test user configured for cookie test');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    reporter.reportSkip('Login endpoint not found or unreachable for cookie test');
    test.skip(true, 'Login endpoint not found or unreachable for cookie test');
    return;
  }

  const { res, path } = attempt as any;
  const setCookie = res.headers()['set-cookie'];

  if (!setCookie) {
    reporter.reportSkip(
      `Authentication response from ${path} did not include a Set-Cookie header; cookie-based auth hardening is not applicable to this flow.`
    );
    test.skip(true, `No Set-Cookie header from ${path}`);
    return;
  }

  const flags = parseSetCookieFlags(setCookie as string);
  const secureRequired = process.env.SKIP_SECURE_CHECK !== '1';
  const sameSiteStrong = !!(flags.sameSite && /lax|strict/i.test(String(flags.sameSite)));

  const missingFlags: string[] = [];
  if (!flags.httpOnly) missingFlags.push('HttpOnly');
  if (secureRequired && !flags.secure) missingFlags.push('Secure');
  if (!sameSiteStrong) missingFlags.push('SameSite=Lax/Strict');

  if (missingFlags.length === 0) {
    reporter.reportPass(
      `System is protected: authentication cookie from ${path} includes secure attributes. ` +
      `Outcome: HttpOnly=${flags.httpOnly}, Secure=${flags.secure}, SameSite=${flags.sameSite || 'unset'}. ` +
      `These settings reduce XSS token theft and cross-site request abuse risk.`,
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
    return;
  }

  reporter.reportWarning(
    `True vulnerability: authentication cookie from ${path} is missing recommended security flags: ${missingFlags.join(', ')}. ` +
    `Observed flags: HttpOnly=${flags.httpOnly}, Secure=${flags.secure}, SameSite=${flags.sameSite || 'unset'}. ` +
    `Risk: missing cookie protections increase exposure to session hijacking, XSS-driven token theft, and CSRF-like attacks.`,
    [
      ...TARGET_APP_FIX_FIRST,
      `Set missing cookie attributes: ${missingFlags.join(', ')}.`,
      'Prefer SameSite=Strict for highly sensitive workflows; use Lax where UX requires top-level cross-site navigation.',
      'Keep SKIP_SECURE_CHECK disabled in production and enforce HTTPS end-to-end.',
      'Add regression tests in CI to block deployments if auth cookies lose security flags.',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});
