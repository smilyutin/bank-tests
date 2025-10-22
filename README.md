# Bank tests

Playwright TypeScript test scaffold for API and UI tests.

Install and run:

```bash
npm install
npx playwright install
npm test
```

Defaults:
- Base URL: http://localhost:5001
- API docs: http://localhost:5001/api/docs/

Assumptions:
- API create user endpoint: POST /api/users or /api/auth/register (adjust test if different)
- UI signup path: /signup with inputs named or labeled 'email' and 'password' and a submit button containing 'Sign up' or 'Create account'

If selectors or endpoints differ, update the tests in `tests/api/create-user.spec.ts` and `tests/ui/create-user.spec.ts`.

Security test suite
-------------------

A Playwright-based security checklist is included under `tests/security`. It contains non-destructive checks for headers, cookies, session fixation, logout hygiene and brute-force throttling. Tests are soft-mode aware and will warn instead of failing when `SECURITY_SOFT=1`.

Run security checks (soft mode - warnings only):

```bash
SECURITY_SOFT=1 npm run test:sec
```

Run security checks (strict mode - failures will fail the run):

```bash
npm run test:sec
```

CI notes
--------

- Use soft mode in PR checks to warn about findings: `SECURITY_SOFT=1 npm run test:sec`.
- For main branch gating, run strict mode and fail on findings.
- Tests are intentionally non-destructive; if you need authenticated or destructive checks, update the specs carefully and document them in CI.
