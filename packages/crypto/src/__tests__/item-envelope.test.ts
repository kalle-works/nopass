import { describe, expect, it } from "vitest";
import type { EncryptedVaultItem, LoginItem } from "@nopass/types";
import { encryptItem } from "../aes-gcm";
import {
  type ItemBinding,
  ItemRollbackError,
  LegacyItemRejectedError,
  MemoryRevisionStore,
  applyV2OnlyMarker,
  decryptVaultItem,
  encryptItemV2,
  encryptVaultItem,
  trustStateId,
  upgradeLegacyItems,
  v2OnlyMarker,
} from "../item-envelope";
import { stretchMasterKey } from "../kdf";

const keysPromise = stretchMasterKey(new Uint8Array(32).fill(0x42), "test@example.com");

const LOGIN: LoginItem = {
  type: "login",
  name: "GitHub",
  username: "alice",
  password: "super-secret-123",
  urls: ["https://github.com"],
  customFields: [],
};

const ITEM_A = "11111111-1111-4111-8111-111111111111";
const ITEM_B = "22222222-2222-4222-8222-222222222222";
const ORG = "33333333-3333-4333-8333-333333333333";
const bindingA: ItemBinding = { scope: { kind: "personal" }, itemId: ITEM_A, itemType: "login" };

function row(id: string, blob: { blob: string; blobIv: string; blobMac: string }): EncryptedVaultItem {
  return {
    id,
    vaultId: "44444444-4444-4444-8444-444444444444",
    userId: "55555555-5555-4555-8555-555555555555",
    itemType: "login",
    ...blob,
    version: 1,
    deletedAt: null,
    createdAt: "",
    updatedAt: "",
  };
}

/** Rewrite the revision field in a v2 blob's cleartext header. */
function withHeaderRevision(blobB64: string, revision: number): string {
  const bytes = Uint8Array.from(atob(blobB64), (c) => c.charCodeAt(0));
  new DataView(bytes.buffer).setBigUint64(1, BigInt(revision));
  return btoa(String.fromCharCode(...bytes));
}

describe("v2 item envelope", () => {
  it("decrypts only as the item, type, scope and revision it was written as", async () => {
    const keys = await keysPromise;
    const enc = await encryptItemV2(LOGIN, bindingA, 3, keys.vaultEncKey);

    await expect(decryptVaultItem(enc, bindingA, keys)).resolves.toMatchObject({ plaintext: LOGIN, revision: 3 });
    await expect(decryptVaultItem(enc, { ...bindingA, itemId: ITEM_B }, keys)).rejects.toThrow();
    await expect(decryptVaultItem(enc, { ...bindingA, itemType: "note" }, keys)).rejects.toThrow();
    await expect(decryptVaultItem(enc, { ...bindingA, scope: { kind: "org", orgId: ORG } }, keys)).rejects.toThrow();
    await expect(
      decryptVaultItem({ ...enc, blob: withHeaderRevision(enc.blob, 4) }, bindingA, keys),
    ).rejects.toThrow();
  });

  it("still decrypts v1 items", async () => {
    const keys = await keysPromise;
    const v1 = await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey);
    await expect(decryptVaultItem(v1, bindingA, keys)).resolves.toMatchObject({ plaintext: LOGIN, format: 1 });
  });

  it("rejects a v1 item whose row type was relabelled", async () => {
    const keys = await keysPromise;
    const v1 = await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey);
    await expect(decryptVaultItem(v1, { ...bindingA, itemType: "note" }, keys)).rejects.toThrow();
  });
});

describe("rollback protection", () => {
  it("rejects an older revision than one already seen", async () => {
    const keys = await keysPromise;
    const store = new MemoryRevisionStore();
    const old = await encryptItemV2(LOGIN, bindingA, 1, keys.vaultEncKey);
    const current = await encryptItemV2({ ...LOGIN, password: "rotated" }, bindingA, 2, keys.vaultEncKey);

    await decryptVaultItem(current, bindingA, keys, store);
    await expect(decryptVaultItem(old, bindingA, keys, store)).rejects.toBeInstanceOf(ItemRollbackError);
  });

  it("rejects a v1 blob once the item has been seen as v2", async () => {
    const keys = await keysPromise;
    const store = new MemoryRevisionStore();
    const v1 = await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey);
    const v2 = await encryptItemV2(LOGIN, bindingA, 1, keys.vaultEncKey);

    await decryptVaultItem(v2, bindingA, keys, store);
    await expect(decryptVaultItem(v1, bindingA, keys, store)).rejects.toBeInstanceOf(ItemRollbackError);
  });

  it("writes past the highest revision seen", async () => {
    const keys = await keysPromise;
    const store = new MemoryRevisionStore({ revisions: { [ITEM_A]: 7 } });
    const { encrypted, revision } = await encryptVaultItem(LOGIN, bindingA, keys.vaultEncKey, store, { revision: 3 });
    expect(revision).toBe(8);
    await expect(decryptVaultItem(encrypted, bindingA, keys, store)).resolves.toMatchObject({ revision: 8 });
  });

  it("writes past the item's current revision on a device with no history", async () => {
    const keys = await keysPromise;
    const current = await decryptVaultItem(await encryptItemV2(LOGIN, bindingA, 5, keys.vaultEncKey), bindingA, keys);
    const otherDevice = new MemoryRevisionStore({ revisions: { [ITEM_A]: 5 } });

    const edit = await encryptVaultItem(LOGIN, bindingA, keys.vaultEncKey, new MemoryRevisionStore(), current);
    await expect(decryptVaultItem(edit.encrypted, bindingA, keys, otherDevice)).resolves.toMatchObject({
      revision: 6,
    });
  });

  it("rejects revisions beyond the safe integer range", async () => {
    const keys = await keysPromise;
    const enc = await encryptItemV2(LOGIN, bindingA, 1, keys.vaultEncKey);
    const bytes = Uint8Array.from(atob(enc.blob), (c) => c.charCodeAt(0));
    new DataView(bytes.buffer).setBigUint64(1, 2n ** 53n);
    await expect(
      decryptVaultItem({ ...enc, blob: btoa(String.fromCharCode(...bytes)) }, bindingA, keys),
    ).rejects.toThrow(/out-of-range/);
  });
});

describe("upgradeLegacyItems", () => {
  it("rewrites v1 items as v2 and leaves v2 items alone", async () => {
    const keys = await keysPromise;
    const store = new MemoryRevisionStore();
    const legacy = row(ITEM_A, await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey));
    const current = row(
      ITEM_B,
      await encryptItemV2(LOGIN, { ...bindingA, itemId: ITEM_B }, 1, keys.vaultEncKey),
    );
    const written = new Map<string, EncryptedVaultItem>();

    const result = await upgradeLegacyItems([legacy, current], keys, store, async (item, encrypted) => {
      written.set(item.id, { ...item, ...encrypted });
    });

    expect(result).toEqual({ upgraded: 1, failed: 0 });
    expect([...written.keys()]).toEqual([ITEM_A]);
    const upgraded = await decryptVaultItem(written.get(ITEM_A)!, bindingA, keys, store);
    expect(upgraded).toMatchObject({ plaintext: LOGIN, format: 2 });
  });
});

describe("v2-only marker", () => {
  it("refuses v1 items once a marker made with this account's key is applied", async () => {
    const keys = await keysPromise;
    const v1 = await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey);
    const store = new MemoryRevisionStore();

    await applyV2OnlyMarker(await v2OnlyMarker(keys.vaultMacKey), keys.vaultMacKey, store);
    await expect(decryptVaultItem(v1, bindingA, keys, store)).rejects.toBeInstanceOf(LegacyItemRejectedError);
  });

  it("ignores a marker the server forged", async () => {
    const keys = await keysPromise;
    const other = await stretchMasterKey(new Uint8Array(32).fill(0x43), "other@example.com");
    const v1 = await encryptItem(LOGIN, keys.vaultEncKey, keys.vaultMacKey);
    const store = new MemoryRevisionStore();

    await applyV2OnlyMarker(await v2OnlyMarker(other.vaultMacKey), keys.vaultMacKey, store);
    await expect(decryptVaultItem(v1, bindingA, keys, store)).resolves.toMatchObject({ format: 1 });
  });
});

describe("trustStateId", () => {
  it("is fixed by the account key alone", async () => {
    const keys = await keysPromise;
    const other = await stretchMasterKey(new Uint8Array(32).fill(0x43), "other@example.com");
    expect(await trustStateId(keys.vaultMacKey)).toBe(await trustStateId(keys.vaultMacKey));
    expect(await trustStateId(keys.vaultMacKey)).not.toBe(await trustStateId(other.vaultMacKey));
  });
});
