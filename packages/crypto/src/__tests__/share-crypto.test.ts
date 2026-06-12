import { describe, it, expect } from "vitest";
import {
  generateShareKey,
  importShareKey,
  encryptSharePayload,
  decryptSharePayload,
} from "../share-crypto";
import type { LoginItem } from "@nopass/types";

const ITEM: LoginItem = {
  type: "login",
  name: "Wifi",
  username: "family",
  password: "hunter2-but-long",
  urls: [],
  customFields: [],
  tags: ["home"],
};

describe("share crypto", () => {
  it("round-trips an item through the share key", async () => {
    const { key, keyB64url } = await generateShareKey();
    const blob = await encryptSharePayload(ITEM, key);

    const recipientKey = await importShareKey(keyB64url);
    const decrypted = await decryptSharePayload(blob, recipientKey);
    expect(decrypted).toEqual(ITEM);
  });

  it("produces URL-fragment-safe keys", async () => {
    for (let i = 0; i < 10; i++) {
      const { keyB64url } = await generateShareKey();
      expect(keyB64url).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });

  it("fails to decrypt with a different key", async () => {
    const { key } = await generateShareKey();
    const blob = await encryptSharePayload(ITEM, key);
    const { keyB64url: otherKey } = await generateShareKey();
    const wrong = await importShareKey(otherKey);
    await expect(decryptSharePayload(blob, wrong)).rejects.toThrow();
  });

  it("rejects malformed keys", async () => {
    await expect(importShareKey("too-short")).rejects.toThrow();
  });
});
