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

test('Auth cookie flags (Secure, HttpOnly, SameSite)', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  if (!user.email || !user.password) {
    reporter.reportWarning('No test user configured for cookie test', [
      'Ensure test credentials exist in tests/fixtures/users.json',
      'Run user fixture initialization scripts',
      'Verify ensureTestUser() implementation and test user setup',
      'Check FIXTURE_USERS_INTEGRATION.md for user configuration'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt) {
    reporter.reportWarning('Login endpoint not found or unreachable for cookie test', [
      'Verify /login or /api/auth endpoints exist and respond',
      'Ensure application server is running and accessible',
      'Check server configuration for auth endpoint availability',
      'Review tryLogin() implementation for endpoint discovery'
    ], OWASP_VULNERABILITIES.API2_AUTH.name);
    return;
  }

  const { res, path } = attempt as any;
  const setCookie = res.headers()['set-cookie'];

  if (!setCookie) {
    reporter.reportWarning(
      `Authentication response from ${path} did not include a Set-Cookie header. ` +
      `Outcome: cookie-based session hardening flags (HttpOnly/Secure/SameSite) cannot be validated. ` +
      `Risk: session handling may be inconsistent or token storage may shift to less secure client-side mechanisms.`,
      [
        ...TARGET_APP_FIX_FIRST,
        'Verify successful login flow issues a session/auth cookie when cookie-based auth is expected',
        'If token-based auth is intended, document it and test token transport/storage protections separately',
      ],
      OWASP_VULNERABILITIES.API2_AUTH.name
    );
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
    `Authentication cookie from ${path} is missing recommended security flags: ${missingFlags.join(', ')}. ` +
    `Observed flags: HttpOnly=${flags.httpOnly}, Secure=${flags.secure}, SameSite=${flags.sameSite || 'unset'}. ` +
    `Risk: missing cookie protections increase exposure to session hijacking, XSS-driven token theft, and CSRF-like attacks.`,
    [
      ...TARGET_APP_FIX_FIRST,
      `Set missing cookie attributes: ${missingFlags.join(', ')}`,
      'Prefer SameSite=Strict for highly sensitive workflows; use Lax where UX requires top-level cross-site navigation',
      'Keep SKIP_SECURE_CHECK disabled in production and enforce HTTPS end-to-end',
      'Add regression tests in CI to block deployments if auth cookies lose security flags',
    ],
    OWASP_VULNERABILITIES.API2_AUTH.name
  );
});
