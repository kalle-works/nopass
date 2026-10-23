import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptItem, encryptItem } from "@nopass/crypto";
import type { NoteItem } from "@nopass/types";
import { importKeys } from "../auth.js";
import type { Session } from "../session.js";

const session = (): Session => ({
  sessionToken: "t",
  email: "a@b.c",
  vaultEncKeyB64: randomBytes(32).toString("base64"),
  vaultMacKeyB64: randomBytes(32).toString("base64"),
  defaultVaultId: "v",
  apiUrl: "http://localhost",
});

const NOTE: NoteItem = { type: "note", name: "n", content: "secret" };

describe("importKeys", () => {
  it("returns read-only keys by default", async () => {
    const { vaultEncKey, vaultMacKey } = await importKeys(session());
    await expect(encryptItem(NOTE, vaultEncKey, vaultMacKey)).rejects.toThrow();
  });

  it("returns keys that can write items the read-only keys decrypt when asked to", async () => {
    const s = session();
    const writer = await importKeys(s, { write: true });
    const reader = await importKeys(s);
    const blob = await encryptItem(NOTE, writer.vaultEncKey, writer.vaultMacKey);
    expect(await decryptItem(blob, reader.vaultEncKey, reader.vaultMacKey)).toEqual(NOTE);
  });
});
