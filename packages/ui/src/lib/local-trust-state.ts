/**
 * Client-side trust state that must outlive a session but is not secret:
 * the highest revision seen per vault item (rollback protection), the
 * identity keys pinned for other users, and per-org key pins.
 *
 * Everything is stored under trustStateId(vaultMacKey), an HMAC under the
 * account key. The server cannot pick that name, so it cannot steer a device
 * to an empty store by serving different user or vault ids. It can still
 * withhold data, and anyone with access to this browser's storage can clear
 * it; both limits are documented in docs/security-model.md.
 */
import {
  type KeyPinStore,
  type OrgEpochStore,
  MemoryRevisionStore,
  type RevisionSnapshot,
  type TrustIndex,
  applyV2OnlyMarker,
  ownLegacyKeys,
  recordLegacyIds,
  trustStateId,
  v2OnlyMarker,
} from "@nopass/crypto";
import type { ApiClient } from "./api-client";
import type { OrgLedgerEntry } from "./org-trust";

function readJson<T>(key: string, fallback: T): T {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(key: string, value: unknown): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // storage unavailable — protection degrades to this session only
  }
}

const TRUST_INDEX_KEY = "nopass:trust-index";

/** Ids the server gave this account at unlock, as legacy record names to claim. */
export interface AccountIds {
  vaultId?: string | null;
  userId?: string | null;
}

/**
 * Before trust state was keyed by the account key it lived under ids the
 * server supplied: `nopass:item-revisions:<defaultVaultId>` and
 * `nopass:key-pins:<userId>`. Each unlock records, locally, which of those
 * ids belong to this account (see trust-index). Only legacy records whose id
 * this account recorded, and no other account on this browser did, are
 * folded into the new store and removed; everything else stays in place for
 * its own account.
 */
function takeLegacyRecords<T>(prefix: string, trustId: string, accountIds?: AccountIds): T[] {
  if (typeof localStorage === "undefined") return [];
  let index = readJson<TrustIndex>(TRUST_INDEX_KEY, {});
  if (accountIds) {
    index = recordLegacyIds(index, trustId, [accountIds.vaultId, accountIds.userId]);
    writeJson(TRUST_INDEX_KEY, index);
  }
  const keys: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key) keys.push(key);
  }
  return ownLegacyKeys(index, trustId, keys, prefix).map((key) => {
    const value = readJson<T>(key, {} as T);
    localStorage.removeItem(key);
    return value;
  });
}

/**
 * Revision store for the account that owns `vaultMacKey`, with the server's
 * v2-only marker applied if it verifies. A failed marker fetch (offline) only
 * means v1 items stay readable for this session.
 */
export async function openRevisionStore(
  vaultMacKey: CryptoKey,
  api?: Pick<ApiClient, "keys">,
  token?: string,
  accountIds?: AccountIds,
): Promise<MemoryRevisionStore> {
  const trustId = await trustStateId(vaultMacKey);
  const key = `nopass:item-revisions:v2:${trustId}`;
  const store = new MemoryRevisionStore(readJson<Partial<RevisionSnapshot>>(key, {}), (snapshot) =>
    writeJson(key, snapshot),
  );
  // record() keeps the higher of the two, so merging is a max per item
  for (const legacy of takeLegacyRecords<Record<string, number>>("nopass:item-revisions:", trustId, accountIds)) {
    for (const [itemId, revision] of Object.entries(legacy)) store.record(itemId, revision);
  }
  if (api && token) {
    try {
      const { marker } = await api.keys.vaultFormat(token);
      await applyV2OnlyMarker(marker, vaultMacKey, store);
    } catch {
      // offline or server error — keep what this device already knows
    }
  }
  return store;
}

/** Record that every item is v2: on the server for other devices, and locally. */
export async function publishV2Only(
  vaultMacKey: CryptoKey,
  store: MemoryRevisionStore,
  api: Pick<ApiClient, "keys">,
  token: string,
): Promise<void> {
  await api.keys.setVaultFormat({ marker: await v2OnlyMarker(vaultMacKey) }, token);
  store.markV2Only();
}

/** Identity keys this account has pinned for other users, keyed by user id. */
export async function openKeyPinStore(vaultMacKey: CryptoKey, accountIds?: AccountIds): Promise<KeyPinStore> {
  const trustId = await trustStateId(vaultMacKey);
  const key = `nopass:key-pins:v2:${trustId}`;
  const pins = readJson<Record<string, string>>(key, {});
  // Union; a pin already in the new store wins over an older one
  const legacy = takeLegacyRecords<Record<string, string>>("nopass:key-pins:", trustId, accountIds);
  for (const record of legacy) {
    for (const [userId, identityKey] of Object.entries(record)) pins[userId] ??= identityKey;
  }
  if (legacy.length > 0) writeJson(key, pins);
  return {
    get: (userId) => pins[userId],
    set: (userId, identityPublicKeyB64) => {
      pins[userId] = identityPublicKeyB64;
      writeJson(key, pins);
    },
  };
}

/** Highest org-key epoch accepted per org on this device. */
export async function openOrgEpochStore(vaultMacKey: CryptoKey): Promise<OrgEpochStore> {
  const key = `nopass:org-epochs:v1:${await trustStateId(vaultMacKey)}`;
  const epochs = readJson<Record<string, number>>(key, {});
  return {
    get: (orgId) => epochs[orgId],
    record: (orgId, epoch) => {
      if (epoch <= (epochs[orgId] ?? 0)) return;
      epochs[orgId] = epoch;
      writeJson(key, epochs);
    },
  };
}

/**
 * What this device has seen of each org (item ids, member ids). A rotation
 * refuses to proceed if the server's lists lack any of them, so a server
 * cannot quietly leave an item un-rekeyed or a member out.
 */
export interface OrgLedger {
  get(orgId: string): OrgLedgerEntry;
  remember(orgId: string, seen: Partial<OrgLedgerEntry>): void;
  forget(orgId: string, gone: Partial<OrgLedgerEntry>): void;
}

export async function openOrgLedger(vaultMacKey: CryptoKey): Promise<OrgLedger> {
  const key = `nopass:org-ledger:v1:${await trustStateId(vaultMacKey)}`;
  const ledger = readJson<Record<string, OrgLedgerEntry>>(key, {});
  const entry = (orgId: string) => (ledger[orgId] ??= { items: [], members: [] });
  return {
    get: (orgId) => ({ items: [...entry(orgId).items], members: [...entry(orgId).members] }),
    remember: (orgId, seen) => {
      const e = entry(orgId);
      e.items = [...new Set([...e.items, ...(seen.items ?? [])])];
      e.members = [...new Set([...e.members, ...(seen.members ?? [])])];
      writeJson(key, ledger);
    },
    forget: (orgId, gone) => {
      const e = entry(orgId);
      e.items = e.items.filter((id) => !gone.items?.includes(id));
      e.members = e.members.filter((id) => !gone.members?.includes(id));
      writeJson(key, ledger);
    },
  };
}
