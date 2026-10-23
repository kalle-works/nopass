/**
 * Which pre-upgrade trust records belong to which account on a shared device.
 *
 * Before trust state was keyed by the account key, it lived under ids the
 * server supplied (default vault id, user id). At every unlock a client
 * records, locally, the account's trustStateId next to the ids it was given.
 * A legacy record is taken over only by the account that recorded its id
 * here, and never if another account on the device recorded the same id.
 */

/** trustStateId -> legacy ids (vault ids, user ids) that account recorded. */
export type TrustIndex = Record<string, string[]>;

export function recordLegacyIds(index: TrustIndex, trustId: string, ids: Array<string | null | undefined>): TrustIndex {
  const known = new Set(index[trustId] ?? []);
  for (const id of ids) if (id) known.add(id);
  return { ...index, [trustId]: [...known] };
}

/** Legacy storage keys (`prefix + id`) that belong to this account and to no other. */
export function ownLegacyKeys(index: TrustIndex, trustId: string, keys: string[], prefix: string): string[] {
  const mine = new Set(index[trustId] ?? []);
  const others = new Set(
    Object.entries(index)
      .filter(([id]) => id !== trustId)
      .flatMap(([, ids]) => ids),
  );
  return keys.filter((key) => {
    if (!key.startsWith(prefix)) return false;
    const id = key.slice(prefix.length);
    return mine.has(id) && !others.has(id);
  });
}
