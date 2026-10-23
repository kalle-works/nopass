/**
 * Versioned vault item envelope.
 *
 * v1 (legacy): blob = AES-256-GCM(json) with no AAD, blobMac = HMAC(iv || ct).
 *   Nothing ties the ciphertext to the row it sits in, so a malicious server
 *   can swap blobs between items, relabel item_type, or serve an older blob.
 *
 * v2: blob = 0x02 || revision (u64 BE) || AES-256-GCM(json, aad), blobMac = "".
 *   The AAD is a canonical encoding of the format version, owner scope, item
 *   id, item type and revision, so decryption fails unless the blob is read
 *   back as exactly the item it was written as. GCM already authenticates the
 *   ciphertext and the AAD, so the v1 HMAC adds nothing and is dropped; the
 *   empty blobMac is also how v2 is told apart from v1 on the wire.
 *
 * Owner scope: personal items bind to "personal" rather than a user id. The
 * personal vault key is unique per account, so a blob moved to another user
 * already fails to decrypt; the id would add no protection. Org items share a
 * key across members, so they bind the org id. The vault id is deliberately
 * not bound: personal vaults share one key and items move between them
 * without being re-encrypted.
 *
 * Rollback: the revision is a client-chosen counter that only goes up. The
 * caller passes a RevisionStore holding the highest revision seen per item;
 * an older revision, or a v1 blob for an item that has been seen as v2, is
 * rejected. Limits: a device with no history accepts whatever it is served
 * first, the server can withhold a newer revision (freeze) or resurrect a
 * deleted item, and the store is only as durable as the local storage behind
 * it.
 */
import type { EncryptedVaultItem, VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { decryptItem } from "./aes-gcm";
import type { EncryptedBlob } from "./types";

const FORMAT_V2 = 2;
const HEADER_LEN = 9;
const AAD_LABEL = new TextEncoder().encode("nopwd-item");

export type ItemScope = { kind: "personal" } | { kind: "org"; orgId: string };

export interface ItemBinding {
  scope: ItemScope;
  itemId: string;
  itemType: VaultItemType;
}

/**
 * Highest revision seen per item. `record` must never lower a stored value.
 * `v2Only` is set once the account is known to hold no v1 items any more;
 * from then on v1 blobs are refused like any other rollback.
 */
export interface RevisionStore {
  get(itemId: string): number | undefined;
  record(itemId: string, revision: number): void;
  readonly v2Only: boolean;
  markV2Only(): void;
}

/** Persisted form of a MemoryRevisionStore. */
export interface RevisionSnapshot {
  revisions: Record<string, number>;
  v2Only: boolean;
}

export class LegacyItemRejectedError extends Error {
  constructor(itemId: string) {
    super(`vault item ${itemId} was served in the old v1 format after this account finished moving to v2 — refusing it`);
    this.name = "LegacyItemRejectedError";
  }
}

export class ItemRollbackError extends Error {
  constructor(itemId: string, revision: number, highestSeen: number) {
    super(
      `vault item ${itemId} was served at revision ${revision}, older than revision ${highestSeen} seen before — refusing a possible rollback`,
    );
    this.name = "ItemRollbackError";
  }
}

export class MemoryRevisionStore implements RevisionStore {
  private readonly revisions: Map<string, number>;
  private legacyClosed: boolean;

  /** `onChange` receives a snapshot after every change, for persisting it. */
  constructor(
    initial: Partial<RevisionSnapshot> = {},
    private readonly onChange?: (snapshot: RevisionSnapshot) => void,
  ) {
    this.revisions = new Map(Object.entries(initial.revisions ?? {}));
    this.legacyClosed = initial.v2Only === true;
  }

  get(itemId: string): number | undefined {
    return this.revisions.get(itemId);
  }

  record(itemId: string, revision: number): void {
    if (revision <= (this.revisions.get(itemId) ?? -1)) return;
    this.revisions.set(itemId, revision);
    this.onChange?.(this.toJSON());
  }

  get v2Only(): boolean {
    return this.legacyClosed;
  }

  markV2Only(): void {
    if (this.legacyClosed) return;
    this.legacyClosed = true;
    this.onChange?.(this.toJSON());
  }

  toJSON(): RevisionSnapshot {
    return { revisions: Object.fromEntries(this.revisions), v2Only: this.legacyClosed };
  }
}

// ── Account-bound identifiers ────────────────────────────────────────────────
//
// Both are HMACs under the vault MAC key, which only this account's clients
// hold: the server can neither choose them nor forge them.

const subtleEnc = new TextEncoder();

async function macLabel(vaultMacKey: CryptoKey, label: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", vaultMacKey, subtleEnc.encode(label)));
}

/**
 * Stable name for this account's local trust state (revision high-water
 * marks, pins). Derived from the account key, so a server cannot point a
 * device at a fresh, empty store by changing ids it serves.
 */
export async function trustStateId(vaultMacKey: CryptoKey): Promise<string> {
  const mac = await macLabel(vaultMacKey, "nopwd-trust-state-id-v1");
  return Array.from(mac.subarray(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

const V2_ONLY_LABEL = "nopwd-vault-format-v2-only-v1";

/** Account-level marker, stored on the server, saying every item is v2. */
export async function v2OnlyMarker(vaultMacKey: CryptoKey): Promise<string> {
  return toBase64(await macLabel(vaultMacKey, V2_ONLY_LABEL));
}

/**
 * Apply a marker fetched from the server: if it verifies under this account's
 * key, refuse v1 items from now on. A missing or forged marker changes
 * nothing — the server can withhold it, but cannot fake it or undo a device
 * that has already seen it.
 */
export async function applyV2OnlyMarker(
  marker: string | null,
  vaultMacKey: CryptoKey,
  revisions: RevisionStore,
): Promise<boolean> {
  if (!marker) return revisions.v2Only;
  let ok = false;
  try {
    ok = await crypto.subtle.verify("HMAC", vaultMacKey, fromBase64(marker), subtleEnc.encode(V2_ONLY_LABEL));
  } catch {
    ok = false;
  }
  if (ok) revisions.markV2Only();
  return revisions.v2Only;
}

export function bindingForItem(item: Pick<EncryptedVaultItem, "id" | "itemType" | "orgId">): ItemBinding {
  return {
    scope: item.orgId ? { kind: "org", orgId: item.orgId } : { kind: "personal" },
    itemId: item.id,
    itemType: item.itemType,
  };
}

export function isLegacyItemBlob(blob: Pick<EncryptedBlob, "blobMac">): boolean {
  return blob.blobMac !== "";
}

function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`not a UUID: ${uuid}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function u64be(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`invalid revision: ${n}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

/** Canonical AAD: label || 0 || version || scope || itemId || len(type) || type || revision. */
export function itemAad(binding: ItemBinding, revision: number): Uint8Array<ArrayBuffer> {
  const type = new TextEncoder().encode(binding.itemType);
  if (type.length > 255) throw new Error("item type too long");
  const scope =
    binding.scope.kind === "org"
      ? Uint8Array.of(1, ...uuidBytes(binding.scope.orgId))
      : Uint8Array.of(0);
  const parts = [
    AAD_LABEL,
    Uint8Array.of(0, FORMAT_V2),
    scope,
    uuidBytes(binding.itemId),
    Uint8Array.of(type.length),
    type,
    u64be(revision),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Encrypt an item as a v2 envelope at the given revision. */
export async function encryptItemV2(
  plaintext: VaultItemPlaintext,
  binding: ItemBinding,
  revision: number,
  vaultEncKey: CryptoKey,
): Promise<EncryptedBlob> {
  if (plaintext.type !== binding.itemType) {
    throw new Error(`item type mismatch: plaintext is ${plaintext.type}, binding is ${binding.itemType}`);
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: itemAad(binding, revision) },
      vaultEncKey,
      new TextEncoder().encode(JSON.stringify(plaintext)),
    ),
  );
  const blob = new Uint8Array(HEADER_LEN + ct.length);
  blob[0] = FORMAT_V2;
  blob.set(u64be(revision), 1);
  blob.set(ct, HEADER_LEN);
  return { blob: toBase64(blob), blobIv: toBase64(iv), blobMac: "" };
}

export interface DecryptedItem {
  plaintext: VaultItemPlaintext;
  /** 0 for a v1 blob */
  revision: number;
  format: 1 | 2;
}

/**
 * Decrypt an item in either format, checking it against its binding and, when
 * a store is given, against the highest revision seen for it.
 */
export async function decryptVaultItem(
  encrypted: EncryptedBlob,
  binding: ItemBinding,
  keys: { vaultEncKey: CryptoKey; vaultMacKey: CryptoKey },
  revisions?: RevisionStore,
): Promise<DecryptedItem> {
  let result: DecryptedItem;
  if (isLegacyItemBlob(encrypted) && revisions?.v2Only) throw new LegacyItemRejectedError(binding.itemId);
  if (isLegacyItemBlob(encrypted)) {
    result = { plaintext: await decryptItem(encrypted, keys.vaultEncKey, keys.vaultMacKey), revision: 0, format: 1 };
  } else {
    const blob = fromBase64(encrypted.blob);
    if (blob.length <= HEADER_LEN || blob[0] !== FORMAT_V2) {
      throw new Error(`vault item ${binding.itemId} has an unknown envelope format`);
    }
    const rawRevision = new DataView(blob.buffer).getBigUint64(1);
    if (rawRevision > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`vault item ${binding.itemId} has an out-of-range revision`);
    }
    const revision = Number(rawRevision);
    const pt = await crypto.subtle
      .decrypt(
        { name: "AES-GCM", iv: fromBase64(encrypted.blobIv), additionalData: itemAad(binding, revision) },
        keys.vaultEncKey,
        blob.subarray(HEADER_LEN),
      )
      .catch(() => {
        throw new Error(`vault item ${binding.itemId} failed authentication — it may have been tampered with or moved`);
      });
    result = {
      plaintext: JSON.parse(new TextDecoder().decode(pt)) as VaultItemPlaintext,
      revision,
      format: 2,
    };
  }

  // v1 has no authenticated type, so the row's label is checked against the plaintext
  if (result.plaintext.type !== binding.itemType) {
    throw new Error(`vault item ${binding.itemId} type does not match its contents`);
  }
  if (revisions) {
    const highest = revisions.get(binding.itemId);
    if (highest !== undefined && result.revision < highest) {
      throw new ItemRollbackError(binding.itemId, result.revision, highest);
    }
    revisions.record(binding.itemId, result.revision);
  }
  return result;
}

/**
 * Encrypt an item for writing at the next revision. `current` is the result
 * of decrypting the blob being replaced (null for a new item): the new
 * revision has to beat it even on a device that has never seen the item,
 * or other devices would refuse the edit as a rollback. Record the returned
 * revision in the store only once the server has accepted the write.
 */
export async function encryptVaultItem(
  plaintext: VaultItemPlaintext,
  binding: ItemBinding,
  vaultEncKey: CryptoKey,
  revisions: RevisionStore | undefined,
  current: Pick<DecryptedItem, "revision"> | null,
): Promise<{ encrypted: EncryptedBlob; revision: number }> {
  const revision = Math.max(revisions?.get(binding.itemId) ?? 0, current?.revision ?? 0) + 1;
  return { encrypted: await encryptItemV2(plaintext, binding, revision, vaultEncKey), revision };
}

/**
 * Re-encrypt every decryptable v1 item as v2. `write` persists one item and
 * should throw on failure (conflict, network); failures are counted and the
 * item is left for the next run or the next normal save.
 */
export async function upgradeLegacyItems(
  items: EncryptedVaultItem[],
  keys: { vaultEncKey: CryptoKey; vaultMacKey: CryptoKey },
  revisions: RevisionStore,
  write: (item: EncryptedVaultItem, encrypted: EncryptedBlob) => Promise<void>,
): Promise<{ upgraded: number; failed: number }> {
  let upgraded = 0;
  let failed = 0;
  for (const item of items) {
    if (item.deletedAt !== null || !isLegacyItemBlob(item)) continue;
    const binding = bindingForItem(item);
    try {
      const current = await decryptVaultItem(item, binding, keys, revisions);
      const { encrypted, revision } = await encryptVaultItem(
        current.plaintext,
        binding,
        keys.vaultEncKey,
        revisions,
        current,
      );
      await write(item, encrypted);
      revisions.record(item.id, revision);
      upgraded++;
    } catch {
      failed++;
    }
  }
  return { upgraded, failed };
}
