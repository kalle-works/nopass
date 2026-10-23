// The API origin must be allowed in connect-src or every vault request is
// blocked by our own CSP. Derived from the same env var the client uses.
export function resolveApiOrigin(apiUrl: string | undefined): string {
  try {
    return new URL(apiUrl ?? "http://localhost:3001").origin;
  } catch {
    return "http://localhost:3001";
  }
}

/**
 * Per-request Content-Security-Policy. Scripts run only with the request's
 * nonce ('strict-dynamic' lets those scripts load their own chunks); there is
 * no 'unsafe-inline' for scripts or style elements. 'wasm-unsafe-eval' lets
 * the OPAQUE login client (WebAssembly) compile; it does not allow JS eval.
 * 'unsafe-eval' is dev-only (React debugging).
 */
export function buildCsp({ nonce, isDev, apiOrigin }: { nonce: string; isDev: boolean; apiOrigin: string }): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    // style="" attributes (e.g. the import progress bar width) cannot carry a nonce
    "style-src-attr 'unsafe-inline'",
    // Self-hosted Geist fonts
    "font-src 'self'",
    // self + data URIs for inline SVG favicons
    "img-src 'self' data:",
    // self + the nopwd API + HaveIBeenPwned (only used on /vault/health)
    `connect-src 'self' ${apiOrigin} https://api.pwnedpasswords.com`,
    "worker-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "form-action 'self'",
    // Trusted Types: see trusted-types.ts. Dev keeps them off because the
    // dev server's HMR and overlay write plain strings into DOM sinks.
    ...(isDev ? [] : ["require-trusted-types-for 'script'", "trusted-types default"]),
    "upgrade-insecure-requests",
  ].join("; ");
}
