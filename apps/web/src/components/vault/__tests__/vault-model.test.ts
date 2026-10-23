import { describe, expect, it } from "vitest";
import type { EncryptedVaultItem, LoginItem, NoteItem, VaultItemPlaintext } from "@nopass/types";
import { filterItems, hostOf, matchesQuery, type FilterState } from "../vault-model";

const login = (over: Partial<LoginItem> = {}): LoginItem => ({
  type: "login",
  name: "GitHub",
  username: "kalle@example.com",
  password: "pw",
  urls: ["https://github.com/login"],
  customFields: [],
  tags: ["work"],
  notes: "deploy account",
  ...over,
});

describe("matchesQuery", () => {
  it("finds an item by title, username, host, tag or notes", () => {
    const item = login();
    for (const q of ["gith", "kalle@", "github.com", "work", "deploy"]) {
      expect(matchesQuery(item, q), q).toBe(true);
    }
  });

  it("does not match text that only appears in the password", () => {
    expect(matchesQuery(login({ password: "hunter2-secret" }), "hunter2")).toBe(false);
  });

  it("requires every term to match, in any field", () => {
    expect(matchesQuery(login(), "github work")).toBe(true);
    expect(matchesQuery(login(), "github personal")).toBe(false);
  });

  it("searches secure note content", () => {
    const note: NoteItem = { type: "note", name: "Wifi", content: "router admin panel", tags: [] };
    expect(matchesQuery(note, "router")).toBe(true);
  });
});

describe("hostOf", () => {
  it("accepts URLs without a scheme", () => {
    expect(hostOf("github.com/login")).toBe("github.com");
  });
});

describe("filterItems", () => {
  const enc = (id: string, vaultId: string, itemType: EncryptedVaultItem["itemType"]) =>
    ({ id, vaultId, itemType }) as EncryptedVaultItem;
  const items = [enc("a", "v1", "login"), enc("b", "v2", "login"), enc("c", "v1", "note")];
  const plaintexts = new Map<string, VaultItemPlaintext>([
    ["a", login()],
    ["b", login({ name: "GitLab", tags: ["home"] })],
    ["c", { type: "note", name: "Wifi", content: "", tags: ["work"] }],
  ]);
  const base: FilterState = {
    vaultId: null,
    filter: "all",
    tag: null,
    query: "",
    reviewIds: null,
    favorites: new Set(),
  };

  it("combines vault, type, tag and search with AND", () => {
    const ids = (s: Partial<FilterState>) => filterItems(items, plaintexts, { ...base, ...s }).map((i) => i.id);
    expect(ids({ vaultId: "v1", filter: "login", tag: "work", query: "git" })).toEqual(["a"]);
    expect(ids({ tag: "WORK" })).toEqual(["a", "c"]);
    expect(ids({ reviewIds: new Set(["b"]) })).toEqual(["b"]);
  });

  it("hides items that are not decrypted yet while searching", () => {
    expect(filterItems(items, new Map(), { ...base, query: "git" })).toEqual([]);
    expect(filterItems(items, new Map(), base)).toHaveLength(3);
  });
});
