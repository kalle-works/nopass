import origins from "../api-origin.json";

/**
 * API base URL for this build. VITE_API_URL wins; otherwise release builds use
 * the production API and dev builds use localhost. The CSP connect-src in
 * tauri.conf.json is checked against the same api-origin.json by
 * scripts/check-csp.mjs, so the two cannot drift apart.
 */
export function resolveApiBase(env: { PROD: boolean; VITE_API_URL?: string | undefined }): string {
  return env.VITE_API_URL || (env.PROD ? origins.production : origins.development);
}
