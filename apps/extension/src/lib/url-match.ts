/** Returns the hostname of a URL, or null if the URL is invalid. */
export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** True if the item URL list contains a URL with the same hostname as tabUrl. */
export function urlMatches(itemUrls: string[], tabUrl: string): boolean {
  const tabHost = hostnameOf(tabUrl);
  if (!tabHost) return false;
  return itemUrls.some((u) => hostnameOf(u) === tabHost);
}

/** True if name contains query (case-insensitive). */
export function nameMatches(name: string, query: string): boolean {
  if (!query) return true;
  return name.toLowerCase().includes(query.toLowerCase());
}
