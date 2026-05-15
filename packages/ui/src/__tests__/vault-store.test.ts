import { describe, expect, it, beforeEach } from "vitest";
import { useNopassStore } from "../store/vault-store";
import type { EncryptedVaultItem, SrpVerifyResponse } from "@nopass/types";
import type { DerivedKeys } from "@nopass/crypto";

// Reset store state between tests
beforeEach(() => {
  useNopassStore.setState({
    sessionToken: null,
    userId: null,
    defaultVaultId: null,
    vaultEncKey: null,
    vaultMacKey: null,
    email: null,
    kdfParams: null,
    items: [],
    isLoading: false,
    lastSyncAt: null,
  });
});

function makeFakeKey(name: string): CryptoKey {
  return { type: "secret", algorithm: { name }, usages: [], extractable: false } as unknown as CryptoKey;
}

function makeFakeAuthResponse(partial: Partial<SrpVerifyResponse> = {}): SrpVerifyResponse {
  return {
    sessionToken: "tok-abc",
    userId: "user-1",
    defaultVaultId: "vault-1",
    serverProofM2: "proof",
    ...partial,
  };
}

function makeFakeKeys(): DerivedKeys {
  return {
    stretchedMasterKey: makeFakeKey("AES-GCM"),
    vaultEncKey: makeFakeKey("AES-GCM"),
    vaultMacKey: makeFakeKey("HMAC"),
  };
}

function makeItem(
  id: string,
  itemType: EncryptedVaultItem["itemType"] = "login",
  deletedAt: string | null = null,
): EncryptedVaultItem {
  return {
    id,
    vaultId: "vault-1",
    userId: "user-1",
    itemType,
    blob: "enc",
    blobIv: "iv",
    blobMac: "mac",
    version: 1,
    deletedAt,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

describe("isUnlocked", () => {
  it("returns false when vault is locked", () => {
    expect(useNopassStore.getState().isUnlocked()).toBe(false);
  });

  it("returns true after setSession", () => {
    useNopassStore.getState().setSession(makeFakeAuthResponse(), "test@example.com", makeFakeKeys());
    expect(useNopassStore.getState().isUnlocked()).toBe(true);
  });

  it("returns false after lock()", () => {
    useNopassStore.getState().setSession(makeFakeAuthResponse(), "test@example.com", makeFakeKeys());
    useNopassStore.getState().lock();
    expect(useNopassStore.getState().isUnlocked()).toBe(false);
  });
});

describe("setSession", () => {
  it("stores session token, userId, defaultVaultId", () => {
    const keys = makeFakeKeys();
    useNopassStore.getState().setSession(
      makeFakeAuthResponse({ sessionToken: "tok-xyz", userId: "uid-1", defaultVaultId: "vault-99" }),
      "alice@example.com",
      keys,
    );
    const state = useNopassStore.getState();
    expect(state.sessionToken).toBe("tok-xyz");
    expect(state.userId).toBe("uid-1");
    expect(state.defaultVaultId).toBe("vault-99");
    expect(state.email).toBe("alice@example.com");
    expect(state.vaultEncKey).toBe(keys.vaultEncKey);
    expect(state.vaultMacKey).toBe(keys.vaultMacKey);
  });

  it("clears kdfParams after session is set", () => {
    useNopassStore.setState({ kdfParams: { type: "argon2id", memoryKib: 65536, iterations: 3, parallelism: 4 } });
    useNopassStore.getState().setSession(makeFakeAuthResponse(), "test@example.com", makeFakeKeys());
    expect(useNopassStore.getState().kdfParams).toBeNull();
  });
});

describe("lock", () => {
  it("clears key material and items", () => {
    const keys = makeFakeKeys();
    useNopassStore.getState().setSession(makeFakeAuthResponse(), "test@example.com", keys);
    useNopassStore.getState().setItems([makeItem("item-1"), makeItem("item-2")]);

    useNopassStore.getState().lock();
    const state = useNopassStore.getState();

    expect(state.vaultEncKey).toBeNull();
    expect(state.vaultMacKey).toBeNull();
    expect(state.items).toHaveLength(0);
    // session token preserved (needed for re-auth)
    expect(state.sessionToken).toBe("tok-abc");
  });
});

describe("setItems / upsertItem / markDeleted", () => {
  it("setItems replaces all items", () => {
    useNopassStore.getState().setItems([makeItem("a"), makeItem("b")]);
    useNopassStore.getState().setItems([makeItem("c")]);
    expect(useNopassStore.getState().items).toHaveLength(1);
    expect(useNopassStore.getState().items[0]!.id).toBe("c");
  });

  it("upsertItem adds new item", () => {
    useNopassStore.getState().upsertItem(makeItem("new-1"));
    expect(useNopassStore.getState().items).toHaveLength(1);
  });

  it("upsertItem updates existing item", () => {
    useNopassStore.getState().upsertItem(makeItem("item-1"));
    useNopassStore.getState().upsertItem({ ...makeItem("item-1"), version: 2 });
    const items = useNopassStore.getState().items;
    expect(items).toHaveLength(1);
    expect(items[0]!.version).toBe(2);
  });

  it("markDeleted sets deletedAt on item", () => {
    useNopassStore.getState().setItems([makeItem("item-1")]);
    useNopassStore.getState().markDeleted("item-1");
    const item = useNopassStore.getState().items.find((i) => i.id === "item-1");
    expect(item!.deletedAt).not.toBeNull();
  });

  it("markDeleted does not affect other items", () => {
    useNopassStore.getState().setItems([makeItem("a"), makeItem("b")]);
    useNopassStore.getState().markDeleted("a");
    const b = useNopassStore.getState().items.find((i) => i.id === "b");
    expect(b!.deletedAt).toBeNull();
  });
});

describe("activeItems / itemsByType", () => {
  it("activeItems excludes deleted items", () => {
    useNopassStore.getState().setItems([
      makeItem("live"),
      makeItem("dead", "login", new Date().toISOString()),
    ]);
    expect(useNopassStore.getState().activeItems()).toHaveLength(1);
    expect(useNopassStore.getState().activeItems()[0]!.id).toBe("live");
  });

  it("itemsByType filters by type", () => {
    useNopassStore.getState().setItems([
      makeItem("login-1", "login"),
      makeItem("note-1", "note"),
      makeItem("card-1", "card"),
    ]);
    expect(useNopassStore.getState().itemsByType("login")).toHaveLength(1);
    expect(useNopassStore.getState().itemsByType("note")).toHaveLength(1);
    expect(useNopassStore.getState().itemsByType("identity")).toHaveLength(0);
  });

  it("itemsByType excludes deleted items of that type", () => {
    useNopassStore.getState().setItems([
      makeItem("login-1", "login"),
      makeItem("login-2", "login", new Date().toISOString()),
    ]);
    expect(useNopassStore.getState().itemsByType("login")).toHaveLength(1);
  });
});

describe("setLoading / setLastSyncAt / setDefaultVaultId", () => {
  it("setLoading updates isLoading", () => {
    useNopassStore.getState().setLoading(true);
    expect(useNopassStore.getState().isLoading).toBe(true);
    useNopassStore.getState().setLoading(false);
    expect(useNopassStore.getState().isLoading).toBe(false);
  });

  it("setLastSyncAt stores timestamp", () => {
    const ts = new Date().toISOString();
    useNopassStore.getState().setLastSyncAt(ts);
    expect(useNopassStore.getState().lastSyncAt).toBe(ts);
  });

  it("setDefaultVaultId updates vault id", () => {
    useNopassStore.getState().setDefaultVaultId("vault-new");
    expect(useNopassStore.getState().defaultVaultId).toBe("vault-new");
  });
});
