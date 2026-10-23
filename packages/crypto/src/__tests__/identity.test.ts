import { describe, expect, it } from "vitest";
import type { KeyBundle } from "@nopass/types";
import {
  type KeyPinStore,
  PinnedKeyChangedError,
  UnverifiableKeyError,
  deriveIdentityKey,
  safetyNumber,
  UntrustedOrgKeyError,
  signKeyBundle,
  signOrgKeyWrap,
  verifyOrgKeyWrap,
  verifyMemberKey,
} from "../identity";
import { stretchMasterKey } from "../kdf";
import { generateUserKeyPair } from "../org-crypto";

const ALICE = "11111111-1111-4111-8111-111111111111";

class MapPins implements KeyPinStore {
  readonly pins = new Map<string, string>();
  get(userId: string) {
    return this.pins.get(userId);
  }
  set(userId: string, key: string) {
    this.pins.set(userId, key);
  }
}

async function makeUser(seedByte: number) {
  const { stretchedMasterKey } = await stretchMasterKey(new Uint8Array(32).fill(seedByte), "u@example.com");
  const pair = await generateUserKeyPair(stretchedMasterKey);
  const identity = await deriveIdentityKey(pair.protectedPrivateKey, pair.protectedPrivateKeyIv, stretchedMasterKey);
  const bundle: KeyBundle = {
    userId: ALICE,
    publicKey: identity.rsaPublicKeyB64,
    identityPublicKey: identity.publicKeyB64,
    publicKeySignature: signKeyBundle(ALICE, identity.rsaPublicKeyB64, identity.secretKey),
  };
  return { pair, stretchedMasterKey, identity, bundle };
}

describe("identity key derivation", () => {
  it("is stable for the same private key and signs the RSA key the user actually holds", async () => {
    const { pair, stretchedMasterKey, identity } = await makeUser(1);
    const again = await deriveIdentityKey(pair.protectedPrivateKey, pair.protectedPrivateKeyIv, stretchedMasterKey);
    expect(again.publicKeyB64).toBe(identity.publicKeyB64);
    expect(identity.rsaPublicKeyB64).toBe(pair.publicKeyB64);
  });
});

describe("safety numbers", () => {
  it("are stable for the same key and differ for a different key", async () => {
    const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(5)));
    const other = btoa(String.fromCharCode(...new Uint8Array(32).fill(6)));
    expect(safetyNumber(ALICE, key)).toBe(safetyNumber(ALICE, key));
    expect(safetyNumber(ALICE, key)).toMatch(/^\d{5}( \d{5}){5}$/);
    expect(safetyNumber(ALICE, key)).not.toBe(safetyNumber(ALICE, other));
  });
});

describe("verifyMemberKey", () => {
  it("rejects an RSA key the identity key did not sign", async () => {
    const alice = await makeUser(1);
    const mallory = await makeUser(2);
    const swapped = { ...alice.bundle, publicKey: mallory.bundle.publicKey };
    expect(() => verifyMemberKey(swapped, new MapPins())).toThrow(UnverifiableKeyError);
  });

  it("pins on first contact and hard-fails when the identity key later changes", async () => {
    const alice = await makeUser(1);
    // A server substituting its own keys can produce a validly self-signed bundle
    const mallory = await makeUser(2);
    const pins = new MapPins();

    expect(verifyMemberKey(alice.bundle, pins)).toMatchObject({
      rsaPublicKeyB64: alice.bundle.publicKey,
      firstSeen: true,
    });
    expect(verifyMemberKey(alice.bundle, pins).firstSeen).toBe(false);
    expect(() => verifyMemberKey(mallory.bundle, pins)).toThrow(PinnedKeyChangedError);
  });

  it("refuses users who have not published an identity key", () => {
    const legacy: KeyBundle = { userId: ALICE, publicKey: "AAAA", identityPublicKey: null, publicKeySignature: null };
    expect(() => verifyMemberKey(legacy, new MapPins())).toThrow(UnverifiableKeyError);
  });
});

describe("verifyOrgKeyWrap", () => {
  const ORG = "22222222-2222-4222-8222-222222222222";
  const BOB = "33333333-3333-4333-8333-333333333333";

  async function signedWrap() {
    const alice = await makeUser(1);
    const wrap = {
      orgId: ORG,
      recipientUserId: BOB,
      signerUserId: ALICE,
      role: "member",
      encryptedOrgKey: btoa("wrapped-org-key-bytes"),
    };
    return { alice, wrap, signature: signOrgKeyWrap(wrap, alice.identity.secretKey) };
  }

  it("accepts a wrap signed by the inviter for this org, recipient and role", async () => {
    const { alice, wrap, signature } = await signedWrap();
    expect(verifyOrgKeyWrap(wrap, signature, alice.bundle, new MapPins()).safetyNumber).toBe(
      safetyNumber(ALICE, alice.bundle.identityPublicKey!),
    );
  });

  it("rejects a wrap the server replaced or re-targeted", async () => {
    const { alice, wrap, signature } = await signedWrap();
    const pins = new MapPins();
    for (const tampered of [
      { ...wrap, encryptedOrgKey: btoa("server-chosen-org-key") },
      { ...wrap, orgId: "44444444-4444-4444-8444-444444444444" },
      { ...wrap, role: "admin" },
    ]) {
      expect(() => verifyOrgKeyWrap(tampered, signature, alice.bundle, pins)).toThrow(UntrustedOrgKeyError);
    }
    expect(() => verifyOrgKeyWrap(wrap, null, alice.bundle, pins)).toThrow(UntrustedOrgKeyError);
  });

  it("rejects a wrap the server signed with its own identity in the inviter's name", async () => {
    const { alice, wrap } = await signedWrap();
    const mallory = await makeUser(2);
    const pins = new MapPins();
    verifyMemberKey(alice.bundle, pins);

    const forged = signOrgKeyWrap(wrap, mallory.identity.secretKey);
    expect(() => verifyOrgKeyWrap(wrap, forged, mallory.bundle, pins)).toThrow(PinnedKeyChangedError);
  });
});
