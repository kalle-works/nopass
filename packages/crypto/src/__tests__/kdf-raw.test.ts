import { describe, expect, it } from "vitest";
import { deriveMasterKey, stretchMasterKeyRaw } from "../kdf";
import type { KdfParams } from "../types";

const TEST_PARAMS: KdfParams = {
  type: "argon2id",
  memoryKib: 8192,
  iterations: 1,
  parallelism: 1,
};

describe("stretchMasterKeyRaw", () => {
  it("returns 32-byte enc and mac key buffers", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, "user@example.com");
    expect(encKeyBytes.byteLength).toBe(32);
    expect(macKeyBytes.byteLength).toBe(32);
  });

  it("is deterministic", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const r1 = await stretchMasterKeyRaw(masterKey, "user@example.com");
    const r2 = await stretchMasterKeyRaw(masterKey, "user@example.com");
    expect(r1.encKeyBytes).toEqual(r2.encKeyBytes);
    expect(r1.macKeyBytes).toEqual(r2.macKeyBytes);
  });

  it("enc and mac keys are different", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, "user@example.com");
    expect(encKeyBytes).not.toEqual(macKeyBytes);
  });

  it("differs by email", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const r1 = await stretchMasterKeyRaw(masterKey, "alice@example.com");
    const r2 = await stretchMasterKeyRaw(masterKey, "bob@example.com");
    expect(r1.encKeyBytes).not.toEqual(r2.encKeyBytes);
  });

  it("is email-case-insensitive", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const r1 = await stretchMasterKeyRaw(masterKey, "User@Example.COM");
    const r2 = await stretchMasterKeyRaw(masterKey, "user@example.com");
    expect(r1.encKeyBytes).toEqual(r2.encKeyBytes);
  });

  it("returns Uint8Array<ArrayBuffer> (assignable to BufferSource)", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, "user@example.com");
    // Should be importable as a CryptoKey (BufferSource requirement)
    await expect(
      crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    ).resolves.toBeDefined();
  });

  it("raw bytes match CryptoKey imported for encryption", async () => {
    const masterKey = await deriveMasterKey("test-password", "user@example.com", TEST_PARAMS);
    const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, "user@example.com");

    // Import raw bytes into CryptoKey
    const encKey = await crypto.subtle.importKey(
      "raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
    const macKey = await crypto.subtle.importKey(
      "raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"],
    );

    // These keys should work for actual crypto operations
    const { encryptItem, decryptItem } = await import("../aes-gcm");
    const plaintext = { type: "login" as const, name: "Test", username: "user", password: "pw", urls: [], customFields: [] };
    const encrypted = await encryptItem(plaintext, encKey, macKey);
    const decrypted = await decryptItem(encrypted, encKey, macKey);
    expect(decrypted).toEqual(plaintext);
  });
}, 30_000);
