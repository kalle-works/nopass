/**
 * Returns the normalized URL when it is http(s), otherwise null. Item URLs are
 * user data (and arrive through imports and shares), so schemes like
 * javascript: or data: must never reach an href or window.open.
 */
export function safeHttpUrl(raw: string | undefined | null): string | null {
  if (!raw) return null;
  try {
    const url = new URL(raw.trim());
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
