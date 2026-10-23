import { describe, expect, it } from "vitest";
import { ownLegacyKeys, recordLegacyIds } from "../trust-index";

describe("ownLegacyKeys", () => {
  const keys = ["p:vault-a", "p:vault-b", "p:vault-c"];

  it("hands an account only the legacy records it recorded locally", () => {
    let index = recordLegacyIds({}, "alice", ["vault-a"]);
    index = recordLegacyIds(index, "bob", ["vault-b"]);
    expect(ownLegacyKeys(index, "alice", keys, "p:")).toEqual(["p:vault-a"]);
    expect(ownLegacyKeys(index, "bob", keys, "p:")).toEqual(["p:vault-b"]);
  });

  it("never hands over a record another account on the device also recorded", () => {
    let index = recordLegacyIds({}, "alice", ["vault-a"]);
    index = recordLegacyIds(index, "mallory", ["vault-a"]);
    expect(ownLegacyKeys(index, "alice", keys, "p:")).toEqual([]);
  });

  it("hands over nothing to an account that recorded no ids", () => {
    expect(ownLegacyKeys(recordLegacyIds({}, "bob", ["vault-b"]), "alice", keys, "p:")).toEqual([]);
  });
});
