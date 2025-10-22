Security checklist

This repository includes a Playwright-based security checklist under tests/security.

Modes
- Soft mode: set SECURITY_SOFT=1 — tests WARN but don't fail the run. Good for PR checks.
- Strict mode: run without SECURITY_SOFT — findings fail the job. Good for main branch gating.

How to run
Soft mode (warnings only): SECURITY_SOFT=1 npm run test:sec
Strict mode (fail on findings): npm run test:sec

What is included
- Authentication & session: cookie flags, JWT sanity, session fixation, logout hygiene, brute-force checks.
- Authorization: IDOR checks and role scoping templates.
- CSRF: templates to check state-changing endpoints require CSRF tokens.
- Input validation: XSS, SQLi/NoSQLi probes, file upload validation.
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS.
- CORS checks: preflight/Origin handling.
- Availability & Abuse: rate limiting and payload size handling.
- Supply chain: CSP/SRI checks and dependency audit reminder.

Notes
- Tests are intentionally non-destructive and best-effort. They will skip when endpoints are not present or when they cannot safely perform an action.
- Extend the tests with app-specific endpoints and resource model to increase coverage (BOLA/IDOR checks need resource endpoints and predictable IDs).
