import { parse as parseDomain } from "tldts";

/**
 * Origin matching for autofill. The popup's "for this site" list and the
 * background's fill enforcement both go through originMatches, so the UI can
 * never offer a fill the background would refuse, or the reverse.
 *
 * Rules, for a saved item URL against the origin of the frame being filled:
 * - Scheme: https pages match https and http items (an upgrade is safe). An
 *   http page matches only an item saved with an explicit http:// URL (the
 *   per-item opt-in), or any item when the host is loopback (local dev).
 *   Anything else (file:, ftp:, data:, ...) never matches.
 * - Port: the effective port must be equal (443 for https, 80 for http).
 *   An http item upgraded to https compares against the default https port.
 * - Host: exact match, or the page is a subdomain of an item host that is
 *   itself a registrable domain (item example.com fills login.example.com).
 *   An item saved for a subdomain (login.example.com) fills only that host.
 *   Registrable domains come from the Public Suffix List including private
 *   suffixes, so foo.github.io never matches bar.github.io, and an item host
 *   that is a bare public suffix (github.io, co.uk) matches nothing but itself.
 *   IP addresses and single-label hosts only ever match exactly.
 */

const PSL_OPTIONS = { allowPrivateDomains: true } as const;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname) || hostname.endsWith(".localhost");
}

function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/** Returns the hostname of a URL, or null if the URL is invalid. */
export function hostnameOf(url: string): string | null {
  return parseUrl(url)?.hostname || null;
}

/** Registrable domain (eTLD+1) of a hostname per the PSL, or null for IPs and bare suffixes. */
export function registrableDomain(hostname: string): string | null {
  return parseDomain(hostname, PSL_OPTIONS).domain;
}

function defaultPort(protocol: string): string {
  return protocol === "https:" ? "443" : "80";
}

function hostMatches(itemHost: string, pageHost: string): boolean {
  if (itemHost === pageHost) return true;
  if (!pageHost.endsWith(`.${itemHost}`)) return false;
  // Subdomain fill only from an item saved for the registrable domain itself
  return registrableDomain(itemHost) === itemHost;
}

/** True if a single saved item URL may be filled into a frame with the given origin. */
export function originMatches(itemUrl: string, pageOrigin: string): boolean {
  const item = parseUrl(itemUrl);
  const page = parseUrl(pageOrigin);
  if (!item || !page || !item.hostname || !page.hostname) return false;
  if (item.protocol !== "https:" && item.protocol !== "http:") return false;

  if (page.protocol === "http:") {
    if (item.protocol !== "http:" && !isLoopback(page.hostname)) return false;
  } else if (page.protocol !== "https:") {
    return false;
  }

  // An http item compared against an https page is upgraded, so its port
  // is only carried over when the schemes agree
  const itemPort =
    item.protocol === page.protocol ? item.port || defaultPort(page.protocol) : defaultPort(page.protocol);
  if (itemPort !== (page.port || defaultPort(page.protocol))) return false;

  return hostMatches(item.hostname, page.hostname);
}

/** True if any of the item's saved URLs matches the page origin. */
export function urlMatches(itemUrls: string[], pageUrl: string): boolean {
  return itemUrls.some((u) => originMatches(u, pageUrl));
}

/** True if name contains query (case-insensitive). */
export function nameMatches(name: string, query: string): boolean {
  if (!query) return true;
  return name.toLowerCase().includes(query.toLowerCase());
}
