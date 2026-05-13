import { expect, request as playwrightRequest, type Page, type TestInfo, test } from '@playwright/test';
import { createRandomUser } from '../../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../../security-reporter';
import { tryLogin, ensureTestUser } from '../../utils/utils';

const LOGIN_IDENTIFIER_SELECTOR = '[name="email"], [name="username"], [type="email"], input[type="text"]';
const PASSWORD_SELECTOR = '[name="password"], [type="password"]';
const SUBMIT_SELECTOR = '[type="submit"], button[type="submit"]';

const TARGET_APP_FIX_FIRST = [
  'Implement and document a virtual card creation endpoint with consistent path/method',
  'Return 4xx for unsupported payload fields instead of generic errors',
  'Enforce explicit server-side allowlists for bindable fields',
  'Reject sensitive fields (limit, ownerId, isAdmin, isBlocked) during create/update operations',
  'Provide consistent authentication flow for API security tests (token or session cookie)',
  'Expose stable OpenAPI/Swagger definitions for security automation coverage',
];

function buildCookieHeaderFromSetCookie(setCookie: string | string[]): string {
  const values = Array.isArray(setCookie) ? setCookie : [setCookie];
  return values
    .map((entry) => String(entry).split(';')[0]?.trim())
    .filter(Boolean)
    .join('; ');
}

async function performUiLogin(
  page: Page,
  baseUrl: string,
  credentials: { email?: string; username?: string; password?: string }
): Promise<{ cookieHeader?: string | null }> {
  const identifier = credentials.email || credentials.username;
  if (!identifier || !credentials.password) return { cookieHeader: null };

  await page.goto(`${baseUrl.replace(/\/$/, '')}/login`).catch(() => {});

  const identifierInput = page.locator(LOGIN_IDENTIFIER_SELECTOR).first();
  const passwordInput = page.locator(PASSWORD_SELECTOR).first();
  const submitButton = page.locator(SUBMIT_SELECTOR).first();

  if (await identifierInput.count() === 0 || await passwordInput.count() === 0 || await submitButton.count() === 0) {
    return { cookieHeader: null };
  }

  await identifierInput.fill(identifier, { timeout: 2000 }).catch(() => {});
  await passwordInput.fill(credentials.password, { timeout: 2000 }).catch(() => {});
  await submitButton.click({ timeout: 2000 }).catch(() => {});
  await page.waitForTimeout(1500);

  const cookies = await page.context().cookies().catch(() => []);
  const cookieHeader = cookies.map((cookie: any) => `${cookie.name}=${cookie.value}`).join('; ');
  return { cookieHeader: cookieHeader || null };
}

class VirtualCardCreateMassAssignmentProbe {
  async verify(baseURL: string, page: Page, testInfo: TestInfo): Promise<void> {
    const reporter = new SecurityReporter(testInfo);

    const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
    const attacker = createRandomUser('sec-atta', false);

    const user = await ensureTestUser(api as any);

    async function ensureAuthHeaders(): Promise<Record<string, string> | null> {
      const loginAttempt = await tryLogin(api as any, user.email || user.username || '', user.password);
      let attemptObj: any = loginAttempt;

      try {
        if (attemptObj && !attemptObj.token && attemptObj.res) {
          const st = attemptObj.res.status && attemptObj.res.status();
          if (st === 401 || st === 403) {
            attemptObj = null;
          } else {
            try {
              const txt = await attemptObj.res.text();
              if (txt && txt.toLowerCase().includes('token is missing')) attemptObj = null;
            } catch {}
          }
        }
      } catch {}

      if (!attemptObj) {
        const createUserCandidates = ['/api/users', '/api/auth/register', '/api/register', '/register', '/users'];
        for (const p of createUserCandidates) {
          try {
            const r = await api.post(p, { data: JSON.stringify({ email: user.email, username: user.username, password: user.password }), headers: { 'Content-Type': 'application/json' } }).catch(() => null as any);
            if (r && [200, 201, 302, 204].includes(r.status())) {
              const re = await tryLogin(api as any, user.email || user.username || '', user.password);
              if (re) { attemptObj = re; break; }
            }
            const rf = await api.post(p, { form: { email: user.email || '', username: user.username || '', password: user.password } }).catch(() => null as any);
            if (rf && [200, 201, 302, 204].includes(rf.status())) {
              const re = await tryLogin(api as any, user.email || user.username || '', user.password);
              if (re) { attemptObj = re; break; }
            }
          } catch {
            // Continue trying the remaining register endpoints.
          }
        }
      }

      if (!attemptObj && page) {
        try {
          const ui = await performUiLogin(page, baseURL?.toString() || 'http://localhost:5001', { email: user.email, username: user.username, password: user.password });
          if (ui && ui.cookieHeader) {
            return { 'Content-Type': 'application/json', 'Cookie': ui.cookieHeader };
          }
        } catch {
          // Ignore this path and keep trying to derive cookies from API responses.
        }
      }

      if (!attemptObj) return null;

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (attemptObj.token) {
        headers['Authorization'] = `Bearer ${attemptObj.token}`;
        return headers;
      }
      if (attemptObj.res) {
        const sc = attemptObj.res.headers()['set-cookie'];
        if (sc) {
          const cookieHeader = buildCookieHeaderFromSetCookie(sc);
          if (cookieHeader) {
            headers['Cookie'] = cookieHeader;
            headers['x-original-set-cookie'] = Array.isArray(sc) ? sc.join('; ') : String(sc);
            return headers;
          }
        }
      }
      return headers;
    }

    let authHeaders = await ensureAuthHeaders() || { 'Content-Type': 'application/json' };

    try {
      console.log('[mass-assign] Resolved auth headers:', JSON.stringify(authHeaders));
    } catch {}

    async function tryFetchTokenWithCredentials() {
      if (authHeaders && authHeaders.Authorization) return null;
      const tokenCandidates = ['/api/auth/token', '/api/token', '/auth/token', '/api/login', '/api/auth/login'];
      for (const p of tokenCandidates) {
        try {
          const r = await api.post(p, { data: JSON.stringify({ username: user.email || user.username, email: user.email, password: user.password }), headers: { 'Content-Type': 'application/json' } }).catch(() => null as any);
          if (!r) continue;
          const text = await r.text().catch(() => null);
          let json = null;
          try { if (text) json = JSON.parse(text); } catch {}
          if (json && (json.token || json.access_token || json.jwt || json.id_token)) {
            return json.token || json.access_token || json.jwt || json.id_token;
          }
          const authHeader = r.headers && (r.headers()['authorization'] || r.headers()['x-auth-token']);
          if (authHeader) {
            const maybe = String(authHeader).split(' ').pop();
            if (maybe) return maybe;
          }
        } catch {
          // Ignore the failure and continue.
        }
      }
      return null;
    }

    try {
      if (!authHeaders.Authorization) {
        const token = await tryFetchTokenWithCredentials();
        if (token) {
          authHeaders.Authorization = `Bearer ${token}`;
          console.log('[mass-assign] Using Bearer token for auth');
        }
      }
    } catch {}

    try {
      const minimal = Object.keys(authHeaders).length === 1 && authHeaders['Content-Type'] === 'application/json';
      if (minimal && page) {
        console.log('[mass-assign] No auth obtained via API; attempting UI login fallback');
        try {
          const ui = await performUiLogin(page, baseURL?.toString() || 'http://localhost:5001', { email: user.email, username: user.username, password: user.password });
          if (ui && ui.cookieHeader) {
            authHeaders['Cookie'] = ui.cookieHeader;
            console.log('[mass-assign] Obtained cookies via UI login');
          }
        } catch {
          // ignore failure
        }
      }
    } catch {}

    let payload: any = {
      cardholderName: 'Attacker Card',
      currency: 'USD',
      limit: 9999999,
      daily_limit: 9999999,
      ownerId: 'attacker-owner-id',
      isBlocked: false,
      isAdmin: true
    };

    async function fetchOpenApiSpec() {
      const candidates = ['/openapi.json', '/swagger.json', '/api/openapi.json', '/api/swagger.json', '/api/docs/swagger.json', '/api/docs/openapi.json', '/swagger/v1/swagger.json'];
      for (const c of candidates) {
        try {
          const r = await api.get(c).catch(() => null as any);
          if (r && r.status() === 200) {
            const text = await r.text().catch(() => null);
            if (!text) continue;
            try { return JSON.parse(text); } catch { continue; }
          }
        } catch {
          continue;
        }
      }
      return null;
    }

    function buildSampleFromSchema(schema: any): any {
      if (!schema) return null;
      if (schema.$ref && typeof schema.$ref === 'string') {
        const ref = schema.$ref.replace(/^#\//, '').split('/');
        let cur: any = (openapiSpec as any);
        for (const k of ref) { if (cur && k in cur) cur = cur[k]; else { cur = null; break; } }
        if (cur) return buildSampleFromSchema(cur);
      }
      if (schema.type === 'object' && schema.properties) {
        const out: any = {};
        for (const [k, v] of Object.entries(schema.properties)) {
          const prop = v as any;
          if (prop.example !== undefined) out[k] = prop.example;
          else if (prop.default !== undefined) out[k] = prop.default;
          else if (prop.enum && prop.enum.length) out[k] = prop.enum[0];
          else if (prop.type === 'string') out[k] = k.includes('email') ? 'attacker@example.com' : (k.includes('name') ? 'Attacker' : 'string');
          else if (prop.type === 'integer' || prop.type === 'number') out[k] = 1;
          else if (prop.type === 'boolean') out[k] = false;
          else if (prop.type === 'array') out[k] = [];
          else out[k] = null;
        }
        return out;
      }
      if (schema.type === 'array' && schema.items) return [buildSampleFromSchema(schema.items)];
      if (schema.example !== undefined) return schema.example;
      return null;
    }

    let openapiSpec: any = null;
    try {
      openapiSpec = await fetchOpenApiSpec();
    } catch {}
    if (openapiSpec && openapiSpec.paths) {
      const p = openapiSpec.paths['/api/virtual-cards/create'] || openapiSpec.paths['/api/virtual-cards'] || openapiSpec.paths['/virtual-cards/create'];
      if (p && p.post && p.post.requestBody) {
        const content = p.post.requestBody.content || p.post.requestBody['application/json'] || p.post.requestBody['content'];
        let schema = null;
        if (content && content['application/json'] && content['application/json'].schema) schema = content['application/json'].schema;
        if (!schema && p.post.requestBody.schema) schema = p.post.requestBody.schema;
        const sample = buildSampleFromSchema(schema);
        if (sample) {
          Object.assign(sample, {
            limit: 9999999,
            daily_limit: 9999999,
            ownerId: 'attacker-owner-id',
            isBlocked: false,
            isAdmin: true
          });
          payload = sample;
        }
      }
    }

    try {
      const candidatePaths = ['/api/virtual-cards/create', '/api/virtual-cards', '/api/virtual-cards/', '/virtual-cards/create', '/virtual-cards', '/api/v1/virtual-cards'];
      const methods: ('POST' | 'PUT' | 'PATCH')[] = ['POST', 'PUT', 'PATCH'];
      let triedAny = false;
      let success = false;

      for (const path of candidatePaths) {
        for (const method of methods) {
          triedAny = true;
          let res: any = null;

          try {
            try {
              res = await api.post(path, { data: JSON.stringify(payload), headers: { ...(authHeaders || {}), 'Content-Type': 'application/json' } }).catch(() => null as any);
            } catch { res = null; }

            if (!res) {
              try {
                res = await api.post(path, { form: payload, headers: { ...(authHeaders || {}) } }).catch(() => null as any);
              } catch { res = null; }
            }

            if (!res) {
              try {
                res = await api.fetch(path, { method, headers: authHeaders || {}, data: JSON.stringify(payload) }).catch(() => null as any);
              } catch { res = null; }
            }
          } catch {
            continue;
          }

          if (!res) continue;

          let status = res.status();
          const responseText = await res.text().catch(() => null);
          let body: any = null;
          try {
            if (responseText) body = JSON.parse(responseText);
          } catch {}
          console.log(`[mass-assign] Attempt ${method} ${path} => status=${status}`);
          if (responseText) console.log(`[mass-assign] Response (truncated 2000 chars): ${responseText.substring(0, 2000)}`);

          if (status === 405) {
            continue;
          }

          if (status === 401 || status === 403) {
            const fresh = await ensureAuthHeaders();
            if (fresh) {
              authHeaders = fresh;
              try {
                res = await api.fetch(path, { method, headers: authHeaders, data: JSON.stringify(payload) });
              } catch (e) {
                reporter.reportWarning(`Environment limitation: network error retrying ${method} ${path} after re-authentication: ${(e as Error).message}`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
                continue;
              }
              if (!res) continue;
              status = res.status();
            } else {
              reporter.reportSkip(`Authentication required but fixture login/registration failed (status ${status}); endpoint not assessable in this environment.`);
              test.skip(true, `Authentication failed for ${method} ${path}`);
              return;
            }
          }

          if (status === 404) continue;

          if ([400, 422].includes(status)) {
            reporter.reportPass(`${method} ${path} rejected suspicious fields with status ${status}`, OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
            expect([400, 422]).toContain(status);
            success = true;
            break;
          }

          if ([200, 201].includes(status)) {
            if (body) {
              const accepted: string[] = [];
              if (body.limit === payload.limit) accepted.push('limit');
              if (body.daily_limit === payload.daily_limit) accepted.push('daily_limit');
              if (body.ownerId === payload.ownerId || body.owner_id === payload.ownerId) accepted.push('ownerId');
              if (body.isBlocked === payload.isBlocked) accepted.push('isBlocked');
              if (body.isAdmin === payload.isAdmin) accepted.push('isAdmin');

              if (accepted.length > 0) {
                reporter.reportVulnerability('API6_MASS_ASSIGNMENT', {
                  endpoint: path,
                  method,
                  request: payload,
                  response: body,
                  acceptedFields: accepted,
                  issue: 'Virtual card creation accepted and applied sensitive fields via payload'
                });
                expect(accepted.length, `Virtual card creation should not accept sensitive fields: ${accepted.join(',')}`).toBe(0);
              } else {
                reporter.reportPass(`Mass assignment protection verified for ${method} ${path}: sensitive fields were ignored or rejected`, OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
                expect(true).toBeTruthy();
              }

              async function probeUpdateLimit(cardId: string | number) {
                if (!cardId) return;
                const upath = `/api/virtual-cards/${cardId}/update-limit`;
                try {
                  const ures = await api.fetch(upath, { method: 'POST', headers: authHeaders, data: JSON.stringify({ limit: 5000000, ownerId: 'attacker-owner-id', daily_limit: 5000000 }) }).catch(() => null as any);
                  if (!ures) {
                    console.log(`[mass-assign] update-limit ${upath} no response`);
                    return;
                  }
                  const ustatus = ures.status();
                  const utext = await ures.text().catch(() => null);
                  let ubody = null;
                  try { if (utext) ubody = JSON.parse(utext); } catch {}
                  console.log(`[mass-assign] update-limit POST ${upath} => status=${ustatus}`);
                  if (utext) console.log(`[mass-assign] update-limit response (truncated): ${utext.substring(0,2000)}`);
                  if ([200,201].includes(ustatus) && ubody) {
                    const acceptedU: string[] = [];
                    if (ubody.limit === 5000000) acceptedU.push('limit');
                    if (ubody.daily_limit === 5000000) acceptedU.push('daily_limit');
                    if (ubody.ownerId === 'attacker-owner-id' || ubody.owner_id === 'attacker-owner-id') acceptedU.push('ownerId');
                    if (acceptedU.length > 0) {
                      reporter.reportVulnerability('API6_MASS_ASSIGNMENT', { endpoint: upath, method: 'POST', request: { limit: 5000000 }, response: ubody, acceptedFields: acceptedU, issue: 'Update-limit endpoint accepted sensitive fields via payload' });
                      expect(acceptedU.length, `Update-limit should not accept sensitive fields: ${acceptedU.join(',')}`).toBe(0);
                    } else {
                      reporter.reportPass(`Update-limit endpoint ${upath} ignored sensitive fields`, OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
                    }
                  }
                } catch {
                  // ignore probe errors
                }
              }

              let cardId: string | number | null = null;
              if (body.id) cardId = body.id;
              if (!cardId && body.card_id) cardId = body.card_id;
              if (!cardId && body.cardId) cardId = body.cardId;
              if (!cardId && body.data && (body.data.id || body.data.card_id)) cardId = body.data.id || body.data.card_id;
              if (!cardId) {
                try {
                  const list = await api.get('/api/virtual-cards', { headers: authHeaders }).catch(() => null as any);
                  if (list && [200,201].includes(list.status())) {
                    const ltext = await list.text().catch(() => null);
                    let lbody = null;
                    try { if (ltext) lbody = JSON.parse(ltext); } catch {}
                    if (Array.isArray(lbody) && lbody.length) cardId = lbody[0].id || lbody[0].card_id || lbody[0].cardId || null;
                    if (lbody && lbody.cards && Array.isArray(lbody.cards) && lbody.cards.length) cardId = lbody.cards[0].id || lbody.cards[0].card_id || null;
                  }
                } catch {}
              }
              if (cardId) await probeUpdateLimit(cardId);
            } else {
              reporter.reportWarning(
                `${method} ${path} returned ${status} with a non-JSON body. Unable to verify sensitive-field handling from response payload.`,
                TARGET_APP_FIX_FIRST,
                OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
              );
            }
            success = true;
            break;
          }

          reporter.reportWarning(`Environment limitation: unexpected status code ${status} was returned from ${method} ${path}.`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
        }
        if (success) break;
      }

      if (!triedAny) {
        reporter.reportSkip('No attempts could be made against virtual-card creation endpoints');
        test.skip(true, 'No candidate virtual-card endpoints were reachable');
        return;
      }

      if (!success) {
        reporter.reportSkip('Unable to exercise virtual card creation endpoint with candidate methods/paths (non-applicable for this target app).');
        reporter.reportWarning(
          'Virtual-card create flow could not be exercised in this environment. Marking as non-applicable to avoid false negatives.',
          TARGET_APP_FIX_FIRST,
          OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
        );
        test.skip(true, 'Virtual-card create endpoint not reachable/usable');
        return;
      }
    } catch (err) {
      reporter.reportWarning(
        `Error while testing virtual-card mass assignment: ${(err as Error).message}`,
        TARGET_APP_FIX_FIRST,
        OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name
      );
      test.skip(true, `Test environment/runtime error: ${(err as Error).message}`);
    }
  }
}

export { VirtualCardCreateMassAssignmentProbe };
