import { test, expect, request } from '@playwright/test';
import { createRandomUser } from '../../utils/credentials';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { tryLogin, ensureTestUser, parseSetCookieValue, buildCookieHeaderFromSetCookie, performUiLogin } from '../utils';

/**
 * Mass Assignment: Virtual Card Creation
 *
 * Targets the documented endpoint: POST /api/virtual-cards (see API docs)
 * Attempts to set sensitive fields during card creation that should be
 * controlled by the server (limit, ownerId, isBlocked, isAdmin, etc.).
 */

test('Mass assignment: creating virtual card should not allow sensitive fields', async ({ baseURL, page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);

  if (!baseURL) {
    reporter.reportWarning('baseURL not provided; unable to run test against API', [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
    expect(false, 'baseURL not provided').toBeTruthy();
    return;
  }

  const api = await request.newContext({ baseURL: baseURL.toString() });
  const attacker = createRandomUser('sec-atta', false);

  // Authenticate using persisted fixture credentials when available
  const user = await ensureTestUser(api as any);

  async function ensureAuthHeaders(): Promise<Record<string, string> | null> {
    // Try to login first
    const loginAttempt = await tryLogin(api as any, user.email || user.username || '', user.password);
    let attemptObj: any = loginAttempt;
    // If the API login endpoint exists but returned a 401/403 or no token, prefer UI login
    // so we can obtain session cookies/csrf. Some apps expose an auth endpoint that
    // always returns a 200/400 but still requires a token created via UI flows.
    try {
      if (attemptObj && !attemptObj.token && attemptObj.res) {
        const st = attemptObj.res.status && attemptObj.res.status();
        if (st === 401 || st === 403) {
          attemptObj = null;
        } else {
          // also check response body for common 'Token is missing' message
          try {
            const txt = await attemptObj.res.text();
            if (txt && txt.toLowerCase().includes('token is missing')) attemptObj = null;
          } catch (e) {}
        }
      }
    } catch (e) {}
    // If login didn't succeed, try to register the user and login again
    if (!attemptObj) {
      const createUserCandidates = ['/api/users', '/api/auth/register', '/api/register', '/register', '/users'];
      for (const p of createUserCandidates) {
        try {
          const r = await api.post(p, { data: JSON.stringify({ email: user.email, username: user.username, password: user.password }), headers: { 'Content-Type': 'application/json' } }).catch(() => null as any);
          if (r && [200, 201, 302, 204].includes(r.status())) {
            // try login again
            const re = await tryLogin(api as any, user.email || user.username || '', user.password);
            if (re) { attemptObj = re; break; }
          }
          const rf = await api.post(p, { form: { email: user.email || '', username: user.username || '', password: user.password } }).catch(() => null as any);
          if (rf && [200, 201, 302, 204].includes(rf.status())) {
            const re = await tryLogin(api as any, user.email || user.username || '', user.password);
            if (re) { attemptObj = re; break; }
          }
        } catch (e) {
          // continue trying other register endpoints
        }
      }
    }

    // If still not obtained via API, try UI login using Playwright page to handle CSRF/session flows
    if (!attemptObj && page) {
      try {
        const ui = await performUiLogin(page, baseURL?.toString() || 'http://localhost', { email: user.email, username: user.username, password: user.password });
        if (ui && ui.cookieHeader) {
          return { 'Content-Type': 'application/json', 'Cookie': ui.cookieHeader };
        }
      } catch (e) {
        // ignore and continue to try to derive cookies from API responses
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
          // also attach original set-cookie for debugging
          headers['x-original-set-cookie'] = Array.isArray(sc) ? sc.join('; ') : String(sc);
          return headers;
        }
      }
    }
    return headers;
  }

  let authHeaders = await ensureAuthHeaders() || { 'Content-Type': 'application/json' };

  // Debug: surface resolved auth headers so we can see if cookie/token was obtained
  try {
    // eslint-disable-next-line no-console
    console.log('[mass-assign] Resolved auth headers:', JSON.stringify(authHeaders));
  } catch (e) {}

  // If we don't have an Authorization header but the API returns "Token is missing",
  // try a few common token endpoints to request a bearer token using credentials.
  async function tryFetchTokenWithCredentials() {
    if (authHeaders && authHeaders.Authorization) return null;
    const tokenCandidates = ['/api/auth/token', '/api/token', '/auth/token', '/api/login', '/api/auth/login'];
    for (const p of tokenCandidates) {
      try {
        // Try JSON-style token request
        const r = await api.post(p, { data: JSON.stringify({ username: user.email || user.username, email: user.email, password: user.password }), headers: { 'Content-Type': 'application/json' } }).catch(() => null as any);
        if (!r) continue;
        const status = r.status();
        const text = await r.text().catch(() => null);
        let json = null;
        try { if (text) json = JSON.parse(text); } catch (e) {}
        // look for token in JSON
        if (json && (json.token || json.access_token || json.jwt || json.id_token)) {
          const token = json.token || json.access_token || json.jwt || json.id_token;
          // eslint-disable-next-line no-console
          console.log(`[mass-assign] Obtained token from ${p}`);
          return token;
        }
        // also check headers and cookies
        const authHeader = r.headers && (r.headers()['authorization'] || r.headers()['x-auth-token']);
        if (authHeader) {
          const maybe = String(authHeader).split(' ').pop();
          if (maybe) {
            // eslint-disable-next-line no-console
            console.log(`[mass-assign] Obtained token from header on ${p}`);
            return maybe;
          }
        }
      } catch (e) {
        // ignore and continue
      }
    }
    return null;
  }

  // Attempt token fetch if no auth header
  try {
    if (!authHeaders.Authorization) {
      const token = await tryFetchTokenWithCredentials();
      if (token) {
        authHeaders.Authorization = `Bearer ${token}`;
        // eslint-disable-next-line no-console
        console.log('[mass-assign] Using Bearer token for auth');
      }
    }
  } catch (e) {
    // ignore
  }

  // As a final fallback: if we still only have Content-Type header, force a UI login
  // attempt to obtain session cookies (some apps only create sessions via browser flows).
  try {
    const minimal = Object.keys(authHeaders).length === 1 && authHeaders['Content-Type'] === 'application/json';
    if (minimal && page) {
      // eslint-disable-next-line no-console
      console.log('[mass-assign] No auth obtained via API; attempting UI login fallback');
      try {
        const ui = await performUiLogin(page, baseURL?.toString() || 'http://localhost', { email: user.email, username: user.username, password: user.password });
        if (ui && ui.cookieHeader) {
          authHeaders['Cookie'] = ui.cookieHeader;
          // eslint-disable-next-line no-console
          console.log('[mass-assign] Obtained cookies via UI login');
        }
      } catch (e) {
        // ignore failure
      }
    }
  } catch (e) {}
  let payload = {
    cardholderName: 'Attacker Card',
    currency: 'USD',
    // Sensitive fields that must NOT be mass-assignable on creation
    limit: 9999999,
    daily_limit: 9999999,
    ownerId: 'attacker-owner-id',
    isBlocked: false,
    isAdmin: true
  };

  // Try to fetch OpenAPI/Swagger spec to construct an exact request payload shape
  async function fetchOpenApiSpec() {
    const candidates = ['/openapi.json', '/swagger.json', '/api/openapi.json', '/api/swagger.json', '/api/docs/swagger.json', '/api/docs/openapi.json', '/swagger/v1/swagger.json'];
    for (const c of candidates) {
      try {
        const r = await api.get(c).catch(() => null as any);
        if (r && r.status() === 200) {
          const text = await r.text().catch(() => null);
          if (!text) continue;
          try { const json = JSON.parse(text); return json; } catch(e) { continue; }
        }
      } catch (e) { continue; }
    }
    return null;
  }

  function buildSampleFromSchema(schema: any): any {
    if (!schema) return null;
    // If it's a $ref, attempt to resolve simple local refs (components/schemas)
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
    if (schema.type === 'array' && schema.items) {
      return [buildSampleFromSchema(schema.items)];
    }
    if (schema.example !== undefined) return schema.example;
    return null;
  }

  // Attempt to fetch and build payload from OpenAPI spec; fall back to default payload
  let openapiSpec: any = null;
  try {
    openapiSpec = await fetchOpenApiSpec();
  } catch (e) {}
  if (openapiSpec && openapiSpec.paths) {
    const p = openapiSpec.paths['/api/virtual-cards/create'] || openapiSpec.paths['/api/virtual-cards'] || openapiSpec.paths['/virtual-cards/create'];
    if (p && p.post && p.post.requestBody) {
      const content = p.post.requestBody.content || p.post.requestBody['application/json'] || p.post.requestBody['content'];
      let schema = null;
      if (content && content['application/json'] && content['application/json'].schema) schema = content['application/json'].schema;
      // swagger 2.0 may have schema directly
      if (!schema && p.post.requestBody.schema) schema = p.post.requestBody.schema;
      const sample = buildSampleFromSchema(schema);
      if (sample) {
        // merge malicious fields into sample to test mass-assignment
        Object.assign(sample, {
          limit: 9999999,
          daily_limit: 9999999,
          ownerId: 'attacker-owner-id',
          isBlocked: false,
          isAdmin: true
        });
        // override payload
        // @ts-ignore
        payload = sample;
      }
    }
  }

  try {
    // Try multiple candidate paths and methods to handle 405 (Method Not Allowed)
    const candidatePaths = [
      '/api/virtual-cards/create', '/api/virtual-cards', '/api/virtual-cards/',
      '/virtual-cards/create', '/virtual-cards', '/api/v1/virtual-cards'
    ];
    const methods: ('POST' | 'PUT' | 'PATCH')[] = ['POST', 'PUT', 'PATCH'];
    let triedAny = false;
    let success = false;

    for (const path of candidatePaths) {
      for (const method of methods) {
        triedAny = true;
        let res: any = null;
        // Try several request styles: api.post with JSON, api.post with form, and fetch with body
        try {
          // 1) api.post JSON style
          try {
            res = await api.post(path, { data: JSON.stringify(payload), headers: { ...(authHeaders || {}), 'Content-Type': 'application/json' } }).catch(() => null as any);
            if (res) {
              // ensure we have a response-like object
            }
          } catch (e) { res = null; }

          // 2) if no response or method mismatch, try form submit
          if (!res) {
            try {
              res = await api.post(path, { form: payload, headers: { ...(authHeaders || {}) } }).catch(() => null as any);
            } catch (e) { res = null; }
          }

          // 3) As a last resort, use fetch with explicit body (some servers expect `body`)
          if (!res) {
            try {
              res = await api.fetch(path, { method, headers: authHeaders || {}, data: JSON.stringify(payload) }).catch(() => null as any);
            } catch (e) { res = null; }
          }
        } catch (e) {
          // network-level issue for this attempt, try next
          continue;
        }

        if (!res) continue;

        let status = res.status();
        // Capture response text for diagnostics and attempt to parse JSON safely
        const responseText = await res.text().catch(() => null);
        let body: any = null;
        try {
          if (responseText) body = JSON.parse(responseText);
        } catch (e) {
          // not JSON - keep body as null and leave responseText for debugging
        }
        // Log attempt details for easier debugging when tests fail
        console.log(`[mass-assign] Attempt ${method} ${path} => status=${status}`);
        if (responseText) console.log(`[mass-assign] Response (truncated 2000 chars): ${responseText.substring(0, 2000)}`);

        // If server says method not allowed, try other method/path combinations
        if (status === 405) {
          // continue to next method/path
          continue;
        }

        // If auth required, try to obtain fresh auth and retry once
        if (status === 401 || status === 403) {
          const fresh = await ensureAuthHeaders();
          if (fresh) {
            authHeaders = fresh;
            try {
              res = await api.fetch(path, { method, headers: authHeaders, data: JSON.stringify(payload) });
            } catch (e) {
              reporter.reportWarning(`Network error retrying ${method} ${path} after re-authentication: ${(e as Error).message}`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
              continue;
            }
            if (!res) continue;
            // update status to the retried response
            status = res.status();
          } else {
            reporter.reportWarning(`Authentication required but could not login/register fixture user (status ${status}).`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
            expect(false, `Authentication required for ${method} ${path} and automatic auth failed`).toBeTruthy();
            return;
          }
        }

        // Not found — try other path
        if (status === 404) continue;

        // If validation error (server rejected bad fields), this is good
        if ([400, 422].includes(status)) {
          reporter.reportPass(`${method} ${path} rejected suspicious fields with status ${status}`, OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
          expect([400, 422]).toContain(status);
          success = true;
          break;
        }

        // Success-like responses — inspect body
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

            // Additionally, attempt to probe the update-limit endpoint for the created card (if we can determine card id)
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
                try { if (utext) ubody = JSON.parse(utext); } catch(e) {}
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
              } catch (e) {
                // ignore probe errors
              }
            }

            // Try to find card id in response body
            let cardId: string | number | null = null;
            if (body.id) cardId = body.id;
            if (!cardId && body.card_id) cardId = body.card_id;
            if (!cardId && body.cardId) cardId = body.cardId;
            if (!cardId && body.data && (body.data.id || body.data.card_id)) cardId = body.data.id || body.data.card_id;
            if (!cardId) {
              // Try to GET the user's cards to find an id
              try {
                const list = await api.get('/api/virtual-cards', { headers: authHeaders }).catch(() => null as any);
                if (list && [200,201].includes(list.status())) {
                  const ltext = await list.text().catch(() => null);
                  let lbody = null;
                  try { if (ltext) lbody = JSON.parse(ltext); } catch(e) {}
                  if (Array.isArray(lbody) && lbody.length) cardId = lbody[0].id || lbody[0].card_id || lbody[0].cardId || null;
                  if (lbody && lbody.cards && Array.isArray(lbody.cards) && lbody.cards.length) cardId = lbody.cards[0].id || lbody.cards[0].card_id || null;
                }
              } catch (e) {}
            }
            if (cardId) await probeUpdateLimit(cardId);
          } else {
            reporter.reportWarning(`${method} ${path} returned status ${status} but response body was not JSON; responseText attached for debugging.`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
            // dump responseText in the failure to aid debugging
            expect(false, `Endpoint ${method} ${path} returned non-JSON body: ${responseText ? responseText.substring(0,2000) : '<empty>'}`).toBeTruthy();
          }
          success = true;
          break;
        }

        // Other unexpected codes — record a warning and continue
        reporter.reportWarning(`Unexpected status code ${status} from ${method} ${path}`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
      }
      if (success) break;
    }

    if (!triedAny) {
      reporter.reportWarning('No attempts could be made against /api/virtual-cards', [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
      expect(false, 'No attempts could be made against /api/virtual-cards').toBeTruthy();
      return;
    }

    if (!success) {
      reporter.reportWarning('Unable to exercise virtual card creation endpoint with the candidate methods/paths. Manual review recommended.', [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
      expect(false, 'Unable to exercise virtual card creation endpoint with the candidate methods/paths.').toBeTruthy();
      return;
    }

  } catch (err) {
    reporter.reportWarning(`Error while testing /api/virtual-cards: ${(err as Error).message}`, [], OWASP_VULNERABILITIES.API6_MASS_ASSIGNMENT.name);
    expect(false, `Error while testing /api/virtual-cards: ${(err as Error).message}`).toBeTruthy();
  }
});
