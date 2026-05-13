// Return the CSP header value regardless of header casing.
export function getContentSecurityPolicy(headers: Record<string, string | undefined>): string | null {
  return headers['content-security-policy'] || headers['Content-Security-Policy'] || null;
}

// Check whether a CSP directive is present as a standalone directive name.
export function cspHasDirective(csp: string, directive: string): boolean {
  return new RegExp(`(?:^|;)\s*${directive}(?:\s|;|$)`, 'i').test(csp);
}

// Detect unsafe-inline usage in a CSP string.
export function cspHasUnsafeInline(csp: string): boolean {
  return csp.includes("'unsafe-inline'");
}

// Detect unsafe-eval usage in a CSP string.
export function cspHasUnsafeEval(csp: string): boolean {
  return csp.includes("'unsafe-eval'");
}

// Detect nonce or hash-based script allowances in a CSP string.
export function cspHasNonceOrHash(csp: string): boolean {
  return csp.includes("'nonce-") || csp.includes("'sha256-") || csp.includes("'sha384-");
}
