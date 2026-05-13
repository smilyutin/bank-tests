import { expect, request as playwrightRequest, test } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { softCheck } from '../../utils/utils';

const SENSITIVE_ROUTE_CANDIDATES = ['/profile', '/account', '/settings'];
const AUTH_RESOURCE_CANDIDATES = ['/api/users/me', '/api/me', '/api/user/me', '/me'];

class SecurityHeadersProbe {
  async checkHomepageSecurityHeaders(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const response = await page.goto('/');

    if (!response) {
      reporter.reportSkip('Comprehensive security-header check could not run because homepage response was not received.');
      test.skip(true, 'Homepage response was not received');
      return;
    }

    const headers = response.headers();
    const securityHeaders = {
      'X-Content-Type-Options': !!headers['x-content-type-options'],
      'X-Frame-Options': !!headers['x-frame-options'],
      'Content-Security-Policy': !!headers['content-security-policy'],
      'Strict-Transport-Security': !!headers['strict-transport-security'] || !page.url().startsWith('https://'),
      'Referrer-Policy': !!headers['referrer-policy'],
      'Permissions-Policy': !!headers['permissions-policy'] || !!headers['feature-policy'],
    };

    const missing = Object.entries(securityHeaders)
      .filter(([_, present]) => !present)
      .map(([header]) => header);

    softCheck(testInfo, missing.length === 0, `Missing security headers: ${missing.join(', ') || 'none'}`);

    if (missing.length === 0) {
      reporter.reportPass(
        'All essential security headers are present and the homepage response is properly hardened.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }

  async checkInformationDisclosure(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const response = await page.goto('/');

    if (!response) {
      reporter.reportSkip('Information-disclosure header check could not run because homepage response was not received.');
      test.skip(true, 'Homepage response was not received');
      return;
    }

    const headers = response.headers();
    const sensitiveHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
    const found: string[] = [];

    for (const header of sensitiveHeaders) {
      if (headers[header]) {
        found.push(`${header}: ${headers[header]}`);
      }
    }

    softCheck(testInfo, found.length === 0, `Information disclosure headers found: ${found.join(', ') || 'none'}`);

    if (found.length === 0) {
      reporter.reportPass(
        'No sensitive server or framework headers were exposed in the homepage response.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }

  async checkXssProtection(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    const response = await page.goto('/');

    if (!response) {
      reporter.reportSkip('X-XSS-Protection deprecation check could not run because homepage response was not received.');
      test.skip(true, 'Homepage response was not received');
      return;
    }

    const headers = response.headers();
    const xssProtection = headers['x-xss-protection'];

    if (xssProtection) {
      const isDeprecatedValue = xssProtection === '1' || xssProtection.includes('mode=block');

      softCheck(
        testInfo,
        !isDeprecatedValue,
        'X-XSS-Protection header should be removed or set to 0 (deprecated, can cause vulnerabilities)'
      );

      if (!isDeprecatedValue) {
        reporter.reportPass(
          `X-XSS-Protection is present but safely configured (${xssProtection}).`,
          OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
        );
      }
    } else {
      reporter.reportPass(
        'X-XSS-Protection header is absent, which is expected because the header is deprecated in modern browsers.',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }

  async checkSensitivePageCacheControl(page: any, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);
    await page.goto('/');

    const response = await page.goto('/profile').catch(() => null) ||
                     await page.goto('/account').catch(() => null) ||
                     await page.goto('/settings').catch(() => null);

    if (!response) {
      reporter.reportWarning(
        'Environment limitation: sensitive-page cache-control probe could not run because no candidate sensitive routes were reachable (/profile, /account, /settings).',
        [
          'Expose/document at least one authenticated sensitive route for cache-control validation',
          'Ensure test environment routes mirror production protected pages',
          'Add OpenAPI/UI route metadata so security probes can discover sensitive endpoints',
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    const headers = response.headers();
    const cacheControl = headers['cache-control'];

    if (cacheControl) {
      const hasNoStore = cacheControl.includes('no-store');
      const hasPrivate = cacheControl.includes('private');

      softCheck(testInfo, hasNoStore || hasPrivate, 'Sensitive pages should have Cache-Control: no-store or private');
    }
  }

  async checkAuthenticatedResourceCacheControl(baseURL: string, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    if (!baseURL) {
      reporter.reportWarning(
        'Environment limitation: authenticated-resource cache-control check could not run because baseURL is not provided.',
        [
          'Set BASE_URL in .env or CI configuration before security tests run',
          'Ensure Playwright baseURL points to reachable target application',
          'Fail pipeline early when baseURL is missing',
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
    let response: Awaited<ReturnType<typeof api.get>> | null = null;
    let endpointUsed: string | null = null;

    for (const path of AUTH_RESOURCE_CANDIDATES) {
      const res = await api.get(path).catch(() => null);
      if (!res) continue;
      if (res.status() !== 404) {
        response = res;
        endpointUsed = path;
        break;
      }
    }

    if (!response) {
      reporter.reportWarning(
        'Environment limitation: no authenticated-resource endpoint responded for cache-control probe (/api/users/me, /api/me, /api/user/me, /me).',
        [
          'Expose/document a stable authenticated profile endpoint for security testing',
          'Ensure non-production environments include representative authenticated APIs',
          'Add endpoint discovery metadata (OpenAPI) for authenticated resource checks',
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    const headers = response.headers();
    const cacheControl = (headers['cache-control'] || '').toLowerCase();
    const pragma = (headers['pragma'] || '').toLowerCase();
    const status = response.status();

    const properlyConfigured =
      cacheControl.includes('no-store') ||
      (cacheControl.includes('no-cache') && cacheControl.includes('private')) ||
      pragma === 'no-cache';

    if (!properlyConfigured) {
      reporter.reportWarning(
        `True vulnerability: authenticated API resource ${endpointUsed} (status ${status}) does not include safe anti-cache directives. Observed Cache-Control="${cacheControl || 'missing'}", Pragma="${pragma || 'missing'}".`,
        [
          'Add Cache-Control: no-store for authenticated and sensitive responses.',
          'At minimum, use Cache-Control: private, no-cache, must-revalidate for user-specific resources.',
          'Add Pragma: no-cache for legacy proxy compatibility.',
          'Review all /me, /profile, /account endpoints to ensure consistent no-cache behavior.'
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    reporter.reportPass(
      `Authenticated API resource ${endpointUsed} correctly disables caching (Cache-Control="${cacheControl || 'n/a'}", Pragma="${pragma || 'n/a'}").`,
      OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
    );
  }

  async checkComprehensiveFingerprinting(baseURL: string, testInfo: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    if (!baseURL) {
      reporter.reportWarning(
        'Environment limitation: OWASP API7 comprehensive header/fingerprinting check could not run because baseURL is not provided.',
        [
          'Set BASE_URL in .env or CI configuration before security tests run',
          'Ensure Playwright baseURL points to reachable target application',
          'Fail pipeline early when baseURL is missing',
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
    const res = await api.get('/').catch(() => null);

    if (!res) {
      reporter.reportWarning(
        'Environment limitation: OWASP API7 comprehensive header/fingerprinting check failed because base URL was not reachable.',
        [
          'Ensure app is running and accessible from test environment network',
          'Stabilize startup/health checks before launching security suite',
          'Fail CI earlier on base URL reachability failure to avoid partial security coverage',
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
      return;
    }

    const headers = res.headers();
    const server = headers['server'] || headers['x-powered-by'] || '';

    if (server) {
      try {
        testInfo.attach('server-header', {
          body: server.toString(),
          contentType: 'text/plain'
        });
      } catch {}
    }

    const haveCT = !!(headers['content-security-policy']);
    const haveXfo = !!(headers['x-frame-options']);
    const haveXss = !!(headers['x-xss-protection'] || headers['x-content-type-options']);
    const haveHSTS = !!(headers['strict-transport-security']);

    const missingHeaders: string[] = [];
    if (!haveCT) missingHeaders.push('Content-Security-Policy');
    if (!haveXfo) missingHeaders.push('X-Frame-Options');
    if (!haveXss) missingHeaders.push('X-Content-Type-Options');
    if (!haveHSTS) missingHeaders.push('Strict-Transport-Security');

    if (missingHeaders.length > 0) {
      reporter.reportWarning(
        `True vulnerability: missing ${missingHeaders.length} security headers: ${missingHeaders.join(', ')}. ${server ? `Server fingerprinting detected: ${server}` : ''}`,
        [
          'Add Content-Security-Policy header to prevent XSS attacks',
          'Add X-Frame-Options header to prevent clickjacking',
          'Add X-Content-Type-Options: nosniff to prevent MIME sniffing',
          'Add Strict-Transport-Security header to enforce HTTPS',
          'Remove or obscure Server and X-Powered-By headers to prevent fingerprinting'
        ],
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    } else {
      reporter.reportPass(
        'All recommended security headers are present',
        OWASP_VULNERABILITIES.API7_MISCONFIGURATION.name
      );
    }
  }
}

export { SecurityHeadersProbe };
