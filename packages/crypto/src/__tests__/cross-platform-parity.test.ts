/**
 * Cross-platform parity tests.
 *
 * These vectors are computed with the exact same parameters in both TS and Rust.
 * A test failure here means the TS and Rust KDF implementations have diverged.
 *
 * Reference Rust test: crates/nopass-crypto/src/kdf.rs :: cross_platform_parity
 *
 * Parameters:
 *   password  : "correct horse battery staple"
 *   email     : "alice@example.com"
 *   memory_kib: 4096
 *   iterations: 1
 *   parallelism: 1
 */
import { describe, expect, it } from "vitest";
import { deriveMasterKey, stretchMasterKeyRaw } from "../kdf";
import type { KdfParams } from "../types";

const PARITY_PARAMS: KdfParams = {
  type: "argon2id",
  memoryKib: 4096,
  iterations: 1,
  parallelism: 1,
};

const KNOWN_MASTER_KEY   = "5586138d4e49edaee8036d44fd531c31c5af69198dd2670e821d002262a795f1";
const KNOWN_ENC_KEY      = "aae88de470c73778fcb96f189fa1bf80f869ae9aaff25117355c3e015843ca3c";
const KNOWN_MAC_KEY      = "d35595df72fd49310849020d96bc031443952a689f13004b2fdee9d4b2e7a867";

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

describe("cross-platform KDF parity (TS ↔ Rust)", () => {
  it("deriveMasterKey produces the expected bytes", async () => {
    const key = await deriveMasterKey(
      "correct horse battery staple",
      "alice@example.com",
      PARITY_PARAMS,
    );
    expect(toHex(key)).toBe(KNOWN_MASTER_KEY);
  });

  it("stretchMasterKeyRaw produces expected enc and mac key bytes", async () => {
    const masterKey = await deriveMasterKey(
      "correct horse battery staple",
      "alice@example.com",
      PARITY_PARAMS,
    );
    const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, "alice@example.com");
    expect(toHex(encKeyBytes)).toBe(KNOWN_ENC_KEY);
    expect(toHex(macKeyBytes)).toBe(KNOWN_MAC_KEY);
  });
}, 60_000);
