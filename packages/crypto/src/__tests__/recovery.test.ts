import { describe, it, expect } from "vitest";
import {
  generateRecoveryCode,
  normalizeRecoveryCode,
  deriveRecoveryKeys,
  wrapVaultSubkeys,
  unwrapVaultSubkeys,
} from "../recovery";
import { deriveMasterKey, stretchMasterKeyAllRaw } from "../kdf";

// Small params so tests stay fast — production uses DEFAULT_KDF_PARAMS
const TEST_KDF = { type: "argon2id" as const, memoryKib: 1024, iterations: 1, parallelism: 1 };
const EMAIL = "alice@example.com";

describe("recovery code generation", () => {
  it("produces 8 dash-separated groups of 4 Crockford base32 chars", () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
  });

  it("never contains the ambiguous letters I, L, O, U", () => {
    for (let i = 0; i < 20; i++) {
      expect(generateRecoveryCode()).not.toMatch(/[ILOU]/);
    }
  });

  it("is unique across generations", () => {
    const seen = new Set(Array.from({ length: 50 }, () => generateRecoveryCode()));
    expect(seen.size).toBe(50);
  });
});

describe("normalizeRecoveryCode", () => {
  it("strips dashes and whitespace and uppercases", () => {
    expect(normalizeRecoveryCode("abcd-2345 jkmn")).toBe("ABCD2345JKMN");
  });

  it("maps confusable letters to Crockford canonical characters", () => {
    expect(normalizeRecoveryCode("OIlo")).toBe("0110");
    expect(normalizeRecoveryCode("uV")).toBe("VV");
  });
});

describe("deriveRecoveryKeys", () => {
  it("is deterministic for the same code and email", async () => {
    const code = generateRecoveryCode();
    const a = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    const b = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    expect(a.authKeyB64).toBe(b.authKeyB64);
  });

  it("tolerates formatting differences in the entered code", async () => {
    const code = generateRecoveryCode();
    const a = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    const b = await deriveRecoveryKeys(code.toLowerCase().replace(/-/g, " "), EMAIL, TEST_KDF);
    expect(a.authKeyB64).toBe(b.authKeyB64);
  });

  it("differs across codes and across emails", async () => {
    const code = generateRecoveryCode();
    const a = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    const b = await deriveRecoveryKeys(generateRecoveryCode(), EMAIL, TEST_KDF);
    const c = await deriveRecoveryKeys(code, "bob@example.com", TEST_KDF);
    expect(a.authKeyB64).not.toBe(b.authKeyB64);
    expect(a.authKeyB64).not.toBe(c.authKeyB64);
  });
});

describe("wrap/unwrap vault subkeys", () => {
  it("round-trips the three subkeys through the recovery blob", async () => {
    const masterKey = await deriveMasterKey("hunter2 correct horse", EMAIL, TEST_KDF);
    const subkeys = await stretchMasterKeyAllRaw(masterKey, EMAIL);
    const expected = {
      smk: [...subkeys.smkBytes],
      enc: [...subkeys.encKeyBytes],
      mac: [...subkeys.macKeyBytes],
    };

    const code = generateRecoveryCode();
    const { wrapKey } = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    const blob = await wrapVaultSubkeys(subkeys, wrapKey);

    const { wrapKey: wrapKey2 } = await deriveRecoveryKeys(code, EMAIL, TEST_KDF);
    const unwrapped = await unwrapVaultSubkeys(blob, wrapKey2);

    expect([...unwrapped.smkBytes]).toEqual(expected.smk);
    expect([...unwrapped.encKeyBytes]).toEqual(expected.enc);
    expect([...unwrapped.macKeyBytes]).toEqual(expected.mac);
  });

  it("fails to unwrap with the wrong code", async () => {
    const masterKey = await deriveMasterKey("hunter2 correct horse", EMAIL, TEST_KDF);
    const subkeys = await stretchMasterKeyAllRaw(masterKey, EMAIL);

    const { wrapKey } = await deriveRecoveryKeys(generateRecoveryCode(), EMAIL, TEST_KDF);
    const blob = await wrapVaultSubkeys(subkeys, wrapKey);

    const { wrapKey: wrongKey } = await deriveRecoveryKeys(generateRecoveryCode(), EMAIL, TEST_KDF);
    await expect(unwrapVaultSubkeys(blob, wrongKey)).rejects.toThrow();
  });
});
