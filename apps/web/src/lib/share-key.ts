/** The slice of `window` that taking the key needs; a plain object in tests. */
export interface ShareKeyWindow {
  location: { hash: string; pathname: string; search: string };
  history: { replaceState(data: unknown, unused: string, url: string): void };
}

/**
 * Reads the share's decryption key from the URL fragment and removes the
 * fragment from the address bar, so the key does not linger in the visible URL,
 * tab history entry or a screenshot after the page has it. Returns null when
 * the URL carries no key; the URL is then left as it is.
 */
export function takeShareKey(win: ShareKeyWindow): string | null {
  const key = new URLSearchParams(win.location.hash.slice(1)).get("k");
  if (!key) return null;
  win.history.replaceState(null, "", win.location.pathname + win.location.search);
  return key;
}
