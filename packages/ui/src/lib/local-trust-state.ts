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
  applyV2OnlyMarker,
  trustStateId,
  v2OnlyMarker,
} from "@nopass/crypto";
import type { ApiClient } from "./api-client";

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

/**
 * Before trust state was keyed by the account key it lived under ids the
 * server supplied: `nopass:item-revisions:<defaultVaultId>` and
 * `nopass:key-pins:<userId>`. Their key names are the only local record of
 * which account they belonged to. If this browser holds exactly one such
 * record, it belongs to the account that used this device before the
 * upgrade, and is folded into the new store and removed. With several (more
 * than one account on this browser) there is no local way to tell which is
 * ours, so they are left alone rather than guessed from server data.
 */
function takeLegacyRecord<T>(prefix: string, current: string): T | null {
  if (typeof localStorage === "undefined") return null;
  const legacy: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(prefix) && !key.startsWith(current) && !key.slice(prefix.length).includes(":")) {
      legacy.push(key);
    }
  }
  if (legacy.length !== 1) return null;
  const value = readJson<T | null>(legacy[0]!, null);
  localStorage.removeItem(legacy[0]!);
  return value;
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
): Promise<MemoryRevisionStore> {
  const key = `nopass:item-revisions:v2:${await trustStateId(vaultMacKey)}`;
  const store = new MemoryRevisionStore(readJson<Partial<RevisionSnapshot>>(key, {}), (snapshot) =>
    writeJson(key, snapshot),
  );
  // record() keeps the higher of the two, so merging is a max per item
  const legacy = takeLegacyRecord<Record<string, number>>("nopass:item-revisions:", "nopass:item-revisions:v2:");
  for (const [itemId, revision] of Object.entries(legacy ?? {})) store.record(itemId, revision);
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
export async function openKeyPinStore(vaultMacKey: CryptoKey): Promise<KeyPinStore> {
  const key = `nopass:key-pins:v2:${await trustStateId(vaultMacKey)}`;
  const pins = readJson<Record<string, string>>(key, {});
  // Union; a pin already in the new store wins over an older one
  const legacy = takeLegacyRecord<Record<string, string>>("nopass:key-pins:", "nopass:key-pins:v2:");
  if (legacy) {
    for (const [userId, identityKey] of Object.entries(legacy)) pins[userId] ??= identityKey;
    writeJson(key, pins);
  }
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
