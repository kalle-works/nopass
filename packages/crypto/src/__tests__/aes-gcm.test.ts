import { describe, expect, it } from "vitest";
import { decryptItem, encryptItem } from "../aes-gcm";
import type { LoginItem, VaultItemPlaintext } from "@nopass/types";
import { stretchMasterKey } from "../kdf";

const MASTER_KEY = new Uint8Array(32).fill(0x42);

async function getKeys() {
  return stretchMasterKey(MASTER_KEY, "test@example.com");
}

const SAMPLE_LOGIN: LoginItem = {
  type: "login",
  name: "GitHub",
  username: "alice",
  password: "super-secret-123",
  urls: ["https://github.com"],
  customFields: [],
};

describe("encryptItem / decryptItem", () => {
  it("round-trips a login item", async () => {
    const { vaultEncKey, vaultMacKey } = await getKeys();
    const encrypted = await encryptItem(SAMPLE_LOGIN, vaultEncKey, vaultMacKey);
    const decrypted = await decryptItem(encrypted, vaultEncKey, vaultMacKey);
    expect(decrypted).toEqual(SAMPLE_LOGIN);
  });

  it("produces unique IVs on every encrypt", async () => {
    const { vaultEncKey, vaultMacKey } = await getKeys();
    const e1 = await encryptItem(SAMPLE_LOGIN, vaultEncKey, vaultMacKey);
    const e2 = await encryptItem(SAMPLE_LOGIN, vaultEncKey, vaultMacKey);
    expect(e1.blobIv).not.toBe(e2.blobIv);
    expect(e1.blob).not.toBe(e2.blob);
  });

  it("rejects tampered ciphertext", async () => {
    const { vaultEncKey, vaultMacKey } = await getKeys();
    const encrypted = await encryptItem(SAMPLE_LOGIN, vaultEncKey, vaultMacKey);

    // Flip a byte in the ciphertext
    const blobBytes = atob(encrypted.blob).split("").map((c) => c.charCodeAt(0));
    blobBytes[0] ^= 0xff;
    const tamperedBlob = btoa(String.fromCharCode(...blobBytes));

    await expect(
      decryptItem({ ...encrypted, blob: tamperedBlob }, vaultEncKey, vaultMacKey),
    ).rejects.toThrow();
  });

  it("rejects tampered MAC", async () => {
    const { vaultEncKey, vaultMacKey } = await getKeys();
    const encrypted = await encryptItem(SAMPLE_LOGIN, vaultEncKey, vaultMacKey);

    const macBytes = atob(encrypted.blobMac).split("").map((c) => c.charCodeAt(0));
    macBytes[0] ^= 0xff;
    const tamperedMac = btoa(String.fromCharCode(...macBytes));

    await expect(
      decryptItem({ ...encrypted, blobMac: tamperedMac }, vaultEncKey, vaultMacKey),
    ).rejects.toThrow("MAC verification failed");
  });

  it("round-trips a note item", async () => {
    const { vaultEncKey, vaultMacKey } = await getKeys();
    const note: VaultItemPlaintext = {
      type: "note",
      name: "Secret recipe",
      content: "Add a pinch of salt",
    };
    const encrypted = await encryptItem(note, vaultEncKey, vaultMacKey);
    const decrypted = await decryptItem(encrypted, vaultEncKey, vaultMacKey);
    expect(decrypted).toEqual(note);
  });
});
