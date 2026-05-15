/**
 * CRDT merge engine for vault sync.
 *
 * Strategy: Last-Write-Wins (LWW) at the item level, using (deviceId, sequenceNumber)
 * as the Lamport clock for ordering. Tombstones (delete events) win over upserts.
 *
 * The encrypted blobs are treated as opaque — the merge logic works on metadata only.
 */
import type { EncryptedVaultItem, SyncEvent, VectorClock } from "@nopass/types";

export interface MergeResult {
  items: EncryptedVaultItem[];
  newClock: VectorClock;
}

/**
 * Apply a batch of sync events to the current local item set.
 * Returns the merged item set and updated vector clock.
 */
export function applySyncEvents(
  local: EncryptedVaultItem[],
  events: SyncEvent[],
  currentClock: VectorClock,
): MergeResult {
  const itemMap = new Map<string, EncryptedVaultItem>(local.map((i) => [i.id, i]));

  // Track the latest event per item (LWW: highest sequence number wins)
  const latestEvent = new Map<string, SyncEvent>();

  for (const event of events) {
    const existing = latestEvent.get(event.itemId);
    if (!existing || isMostRecent(event, existing)) {
      latestEvent.set(event.itemId, event);
    }
  }

  // Apply winning events
  for (const [itemId, event] of latestEvent) {
    if (event.eventType === "delete") {
      const item = itemMap.get(itemId);
      if (item) {
        itemMap.set(itemId, { ...item, deletedAt: event.createdAt });
      }
    }
    // For "upsert" events the full blob is on the EncryptedVaultItem from the server fetch,
    // not in the delta. The delta is for field-level partial updates (future use).
    // The full item is fetched via GET /vaults/:id/items after sync.
  }

  // Update vector clock
  const newClock = { ...currentClock };
  for (const event of events) {
    const current = newClock[event.deviceId] ?? -1;
    if (event.sequenceNumber > current) {
      newClock[event.deviceId] = event.sequenceNumber;
    }
  }

  return {
    items: Array.from(itemMap.values()),
    newClock,
  };
}

/**
 * Determine if event A is more recent than event B.
 * Delete events always win over upsert events at the same sequence.
 */
function isMostRecent(a: SyncEvent, b: SyncEvent): boolean {
  if (a.sequenceNumber !== b.sequenceNumber) {
    return a.sequenceNumber > b.sequenceNumber;
  }
  // Tiebreak: delete wins over upsert (tombstone priority)
  if (a.eventType === "delete" && b.eventType !== "delete") return true;
  if (b.eventType === "delete" && a.eventType !== "delete") return false;
  // Final tiebreak: lexicographic device ID (deterministic, same result on all clients)
  return a.deviceId > b.deviceId;
}

/**
 * Build a SyncRequest from the current local vector clock.
 */
export function buildSyncCheckpoints(
  clock: VectorClock,
): Array<{ deviceId: string; lastSyncedSequence: number }> {
  return Object.entries(clock).map(([deviceId, lastSyncedSequence]) => ({
    deviceId,
    lastSyncedSequence,
  }));
}
