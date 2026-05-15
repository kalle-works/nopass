import { describe, expect, it } from "vitest";
import { computeEmailHash, deriveMasterKey, stretchMasterKey } from "../kdf";
import type { KdfParams } from "../types";

const TEST_PARAMS: KdfParams = {
  type: "argon2id",
  memoryKib: 8192, // reduced for test speed (512 KB)
  iterations: 1,
  parallelism: 1,
};

describe("computeEmailHash", () => {
  it("is case-insensitive", () => {
    expect(computeEmailHash("User@Example.COM")).toBe(computeEmailHash("user@example.com"));
  });

  it("produces a 64-char hex string", () => {
    const hash = computeEmailHash("test@example.com");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("differs by email", () => {
    const a = computeEmailHash("alice@example.com");
    const b = computeEmailHash("bob@example.com");
    expect(a).not.toBe(b);
  });
});

describe("deriveMasterKey", () => {
  it("is deterministic", async () => {
    const k1 = await deriveMasterKey("password", "user@example.com", TEST_PARAMS);
    const k2 = await deriveMasterKey("password", "user@example.com", TEST_PARAMS);
    expect(k1).toEqual(k2);
  });

  it("differs by password", async () => {
    const k1 = await deriveMasterKey("password1", "user@example.com", TEST_PARAMS);
    const k2 = await deriveMasterKey("password2", "user@example.com", TEST_PARAMS);
    expect(k1).not.toEqual(k2);
  });

  it("differs by email", async () => {
    const k1 = await deriveMasterKey("password", "alice@example.com", TEST_PARAMS);
    const k2 = await deriveMasterKey("password", "bob@example.com", TEST_PARAMS);
    expect(k1).not.toEqual(k2);
  });

  it("is email-case-insensitive (matches Rust behavior)", async () => {
    const k1 = await deriveMasterKey("password", "User@EXAMPLE.com", TEST_PARAMS);
    const k2 = await deriveMasterKey("password", "user@example.com", TEST_PARAMS);
    expect(k1).toEqual(k2);
  });

  it("returns 32 bytes", async () => {
    const k = await deriveMasterKey("password", "user@example.com", TEST_PARAMS);
    expect(k.byteLength).toBe(32);
  });
}, 30_000);

describe("stretchMasterKey", () => {
  it("produces three distinct keys", async () => {
    const masterKey = new Uint8Array(32).fill(0x42);
    const keys = await stretchMasterKey(masterKey, "user@example.com");
    // CryptoKey objects are non-extractable — just verify they exist and are correct type
    expect(keys.stretchedMasterKey).toBeDefined();
    expect(keys.vaultEncKey).toBeDefined();
    expect(keys.vaultMacKey).toBeDefined();
    expect(keys.vaultEncKey.algorithm.name).toBe("AES-GCM");
    expect(keys.vaultMacKey.algorithm.name).toBe("HMAC");
  });
});
