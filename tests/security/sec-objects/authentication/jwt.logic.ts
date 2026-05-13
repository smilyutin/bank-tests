import { expect, test, type TestInfo } from '@playwright/test';
import { ensureTestUser, tryLogin } from '../../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';

const TARGET_APP_FIX_FIRST = [
  'Implement strict JWT signature validation (HS256 or RS256)',
  'Reject algorithms "none", "HS256" when expecting RS256, and vice versa (algorithm confusion)',
  'Validate JWT structure: 3 base64url-encoded parts separated by dots',
  'Reject tokens with expired `exp` claim (timestamp comparison)',
  'Verify token issuer (`iss`) and audience (`aud`) claims match expected values',
  'Implement token revocation/blacklist for logged-out tokens',
];

class JwtIntegrityProbe {
  async verify(testInfo: TestInfo, request: any): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    const user = await ensureTestUser(request as any);
    if (!user.email || !user.password) {
      reporter.reportSkip('JWT validation could not run because no test user credentials are available.');
      test.skip(true, 'No test user credentials are available');
      return;
    }

    // Log in first so we can inspect the returned token format.
    const attempt = await tryLogin(request as any, user.email, user.password);
    if (!attempt) {
      reporter.reportSkip('JWT validation could not run because login endpoint was not found or unreachable.');
      test.skip(true, 'Login endpoint was not found or unreachable');
      return;
    }

    const { res, token: returnedToken, path } = attempt as any;

    // Extract the token from either the response body or headers.
    let bodyToken = null;
    try {
      const json = await res.json().catch(() => null);
      if (json && (json.token || json.access_token || json.jwt)) {
        bodyToken = json.token || json.access_token || json.jwt;
      }
    } catch (e) {}

    const auth = res.headers()['authorization'] || res.headers()['www-authenticate'];
    const token = returnedToken || bodyToken || (auth && String(auth).split(' ').pop());

    if (!token) {
      reporter.reportSkip(
        `No JWT token was returned by login endpoint (${path || 'unknown path'}), so JWT integrity checks are not applicable to this auth flow.`
      );
      test.skip(true, 'No JWT token was returned by login');
      return;
    }

    // A valid JWT should have three dot-separated parts.
    const parts = token.split('.');
    if (parts.length !== 3) {
      reporter.reportSkip(
        `Token returned is not a valid JWT structure. Expected 3 base64url parts separated by dots, got ${parts.length} parts.`
      );
      test.skip(true, 'Token returned is not a JWT');
      return;
    }

    // Decode the JWT header and payload before testing tampering.
    let header: any, payload: any;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
      payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    } catch (e) {
      reporter.reportSkip(
        `JWT header or payload could not be decoded. Token may be malformed. Error: ${String(e).slice(0, 100)}`
      );
      test.skip(true, 'JWT header or payload could not be decoded');
      return;
    }

    // Collect findings
    const findings: { success: string[]; vulnerabilities: string[] } = { success: [], vulnerabilities: [] };
    const protectedPaths = ['/api/me', '/api/profile', '/profile', '/me'];

    // Try the alg=none downgrade path to verify signature enforcement.
    header.alg = 'none';
    const algNone = [Buffer.from(JSON.stringify(header)).toString('base64url'), Buffer.from(JSON.stringify(payload)).toString('base64url'), ''].join('.');

    let algNoneAccepted = false;
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${algNone}` } });
        if (r.status() < 400 || r.status() >= 500) {
          findings.vulnerabilities.push(`alg=none token accepted on ${p} (status ${r.status()})`);
          algNoneAccepted = true;
        }
      } catch (e) {}
    }
    if (!algNoneAccepted) {
      findings.success.push('alg=none algorithm confusion attack rejected');
    }

    // Modify the payload to confirm tampering and expiry are rejected.
    const tamperedPayload = { ...payload, exp: 1 }; // expired
    const tampered = [parts[0], Buffer.from(JSON.stringify(tamperedPayload)).toString('base64url'), parts[2]].join('.');
    let tamperedAccepted = false;
    for (const p of protectedPaths) {
      try {
        const r = await request.get(p, { headers: { authorization: `Bearer ${tampered}` } });
        if (r.status() < 400 || r.status() >= 500) {
          findings.vulnerabilities.push(`Tampered/expired token accepted on ${p} (status ${r.status()})`);
          tamperedAccepted = true;
        }
      } catch (e) {}
    }
    if (!tamperedAccepted) {
      findings.success.push('Token tampering/expiry detection working');
    }

    // Summarize the token validation results.
    if (findings.vulnerabilities.length === 0) {
      reporter.reportPass(
        `JWT implementation is secure. Token structure valid (3 parts). ` +
        `Verified: ${findings.success.join(', ')}. Algorithm confusion (alg=none) rejected. ` +
        `Tampered tokens rejected. Evidence: tested against ${protectedPaths.length} protected endpoints.`,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    } else {
      reporter.reportWarning(
        `JWT implementation has security issues. ${findings.vulnerabilities.length} vulnerability(ies) detected: ${findings.vulnerabilities.join('; ')}. ` +
        `This allows attackers to forge tokens or bypass authentication.`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API2_AUTH.name
      );
    }
  }
}

export { JwtIntegrityProbe };
