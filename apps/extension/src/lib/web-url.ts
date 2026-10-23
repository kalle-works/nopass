/**
 * Derives the web vault origin from the API base the extension was built with.
 * Production serves the API from an "api." subdomain of the web app
 * (https://api.nopwd.dev -> https://nopwd.dev). The local dev API on :3001
 * pairs with the web dev server on :4020.
 */
export function webVaultUrl(apiBase: string): string {
  let url: URL;
  try {
    url = new URL(apiBase);
  } catch {
    return "https://nopwd.dev/vault";
  }
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (isLocal) return `${url.protocol}//${url.hostname}:4020/vault`;
  const host = url.hostname.startsWith("api.") ? url.hostname.slice(4) : url.hostname;
  return `${url.protocol}//${host}/vault`;
}

/** Hostname of an http(s) tab URL, or "" for anything else (chrome://, extension pages). */
export function siteHostname(tabUrl: string): string {
  try {
    const url = new URL(tabUrl);
    return url.protocol === "http:" || url.protocol === "https:" ? url.hostname : "";
  } catch {
    return "";
  }
}
