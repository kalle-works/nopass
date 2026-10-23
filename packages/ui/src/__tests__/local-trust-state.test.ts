import { beforeEach, describe, expect, it } from "vitest";
import {
  ItemRollbackError,
  type ItemBinding,
  decryptVaultItem,
  encryptItemV2,
  stretchMasterKey,
} from "@nopass/crypto";
import type { LoginItem } from "@nopass/types";
import { openKeyPinStore, openRevisionStore } from "../lib/local-trust-state";

const ITEM = "11111111-1111-4111-8111-111111111111";
const binding: ItemBinding = { scope: { kind: "personal" }, itemId: ITEM, itemType: "login" };
const LOGIN: LoginItem = { type: "login", name: "x", username: "u", password: "p", urls: [], customFields: [] };

describe("openRevisionStore", () => {
  beforeEach(() => localStorage.clear());

  // The server once chose the store's name (via the default vault id it
  // served). Whatever ids it serves now, the same account must land in the
  // same store, so a replay stays refused.
  it("keeps refusing a replayed revision however the account's vault ids change", async () => {
    const keys = await stretchMasterKey(new Uint8Array(32).fill(7), "a@example.com");
    const old = await encryptItemV2(LOGIN, binding, 1, keys.vaultEncKey);
    const current = await encryptItemV2(LOGIN, binding, 2, keys.vaultEncKey);

    // Session 1: the server reports default vault A
    const sessionA = await openRevisionStore(keys.vaultMacKey);
    await decryptVaultItem(current, binding, keys, sessionA);

    // Session 2: the server now reports default vault B and replays revision 1
    const sessionB = await openRevisionStore(keys.vaultMacKey);
    await expect(decryptVaultItem(old, binding, keys, sessionB)).rejects.toBeInstanceOf(ItemRollbackError);
  });
});

describe("migration from server-keyed trust state", () => {
  beforeEach(() => localStorage.clear());

  const ALICE_IDS = { vaultId: "vault-1", userId: "user-1" };

  it("folds the pre-upgrade records this account recorded into the new stores and removes them", async () => {
    const keys = await stretchMasterKey(new Uint8Array(32).fill(7), "a@example.com");
    const OTHER = "22222222-2222-4222-8222-222222222222";
    // Already in the new store: a higher revision and a newer pin must survive
    (await openRevisionStore(keys.vaultMacKey)).record(OTHER, 3);
    (await openKeyPinStore(keys.vaultMacKey)).set("carol", "carol-key");
    // What this browser kept from before the upgrade
    localStorage.setItem("nopass:item-revisions:vault-1", JSON.stringify({ [ITEM]: 5, [OTHER]: 1 }));
    localStorage.setItem("nopass:key-pins:user-1", JSON.stringify({ bob: "bob-key", carol: "old-carol-key" }));

    const revisions = await openRevisionStore(keys.vaultMacKey, undefined, undefined, ALICE_IDS);
    const pins = await openKeyPinStore(keys.vaultMacKey, ALICE_IDS);

    expect(revisions.get(ITEM)).toBe(5);
    expect(revisions.get(OTHER)).toBe(3);
    expect(pins.get("bob")).toBe("bob-key");
    expect(pins.get("carol")).toBe("carol-key");
    expect(localStorage.getItem("nopass:item-revisions:vault-1")).toBeNull();
    expect(localStorage.getItem("nopass:key-pins:user-1")).toBeNull();

    // The migrated mark protects like any other: a replay of revision 4 is refused
    const replay = await encryptItemV2(LOGIN, binding, 4, keys.vaultEncKey);
    await expect(decryptVaultItem(replay, binding, keys, revisions)).rejects.toBeInstanceOf(ItemRollbackError);
  });

  it("on a shared browser takes only its own records and leaves the other account's in place", async () => {
    const alice = await stretchMasterKey(new Uint8Array(32).fill(7), "a@example.com");
    const bob = await stretchMasterKey(new Uint8Array(32).fill(8), "b@example.com");
    localStorage.setItem("nopass:item-revisions:vault-1", JSON.stringify({ [ITEM]: 5 }));
    localStorage.setItem("nopass:item-revisions:vault-2", JSON.stringify({ [ITEM]: 9 }));

    // Bob unlocked here before and recorded his vault id
    await openRevisionStore(bob.vaultMacKey, undefined, undefined, { vaultId: "vault-2" });
    const mine = await openRevisionStore(alice.vaultMacKey, undefined, undefined, ALICE_IDS);

    expect(mine.get(ITEM)).toBe(5);
    expect(localStorage.getItem("nopass:item-revisions:vault-1")).toBeNull();
    expect(localStorage.getItem("nopass:item-revisions:vault-2")).toBeNull(); // taken by bob, his own
    expect((await openRevisionStore(bob.vaultMacKey)).get(ITEM)).toBe(9);
  });

  it("never takes a record whose id this account has not recorded", async () => {
    const keys = await stretchMasterKey(new Uint8Array(32).fill(7), "a@example.com");
    localStorage.setItem("nopass:item-revisions:vault-2", JSON.stringify({ [ITEM]: 9 }));

    const revisions = await openRevisionStore(keys.vaultMacKey, undefined, undefined, ALICE_IDS);
    expect(revisions.get(ITEM)).toBeUndefined();
    expect(localStorage.getItem("nopass:item-revisions:vault-2")).not.toBeNull();
  });
});
