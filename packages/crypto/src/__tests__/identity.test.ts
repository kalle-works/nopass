import { describe, expect, it } from "vitest";
import type { KeyBundle } from "@nopass/types";
import {
  type KeyPinStore,
  PinnedKeyChangedError,
  UnverifiableKeyError,
  deriveIdentityKey,
  safetyNumber,
  UnconfirmedSignersError,
  UntrustedOrgKeyError,
  confirmKey,
  signKeyBundle,
  signOrgKeyWrap,
  type OrgKeyWrap,
  type SignedWrapLink,
  verifyMemberKey,
  verifyOrgKeyChain,
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

async function makeUser(seedByte: number, userId = ALICE) {
  const { stretchedMasterKey } = await stretchMasterKey(new Uint8Array(32).fill(seedByte), "u@example.com");
  const pair = await generateUserKeyPair(stretchedMasterKey);
  const identity = await deriveIdentityKey(pair.protectedPrivateKey, pair.protectedPrivateKeyIv, stretchedMasterKey);
  const bundle: KeyBundle = {
    userId,
    publicKey: identity.rsaPublicKeyB64,
    identityPublicKey: identity.publicKeyB64,
    publicKeySignature: signKeyBundle(userId, identity.rsaPublicKeyB64, identity.secretKey),
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

  it("never pins on its own, and hard-fails on a changed key once the user confirmed one", async () => {
    const alice = await makeUser(1);
    // A server substituting its own keys can produce a validly self-signed bundle
    const mallory = await makeUser(2);
    const pins = new MapPins();

    expect(verifyMemberKey(alice.bundle, pins).firstSeen).toBe(true);
    expect(pins.get(ALICE)).toBeUndefined();

    confirmKey(alice.bundle, pins);
    expect(verifyMemberKey(alice.bundle, pins).firstSeen).toBe(false);
    expect(() => verifyMemberKey(mallory.bundle, pins)).toThrow(PinnedKeyChangedError);
  });

  it("refuses users who have not published an identity key", () => {
    const legacy: KeyBundle = { userId: ALICE, publicKey: "AAAA", identityPublicKey: null, publicKeySignature: null };
    expect(() => verifyMemberKey(legacy, new MapPins())).toThrow(UnverifiableKeyError);
  });
});

describe("verifyOrgKeyChain", () => {
  const ORG = "22222222-2222-4222-8222-222222222222";
  const OWNER = ALICE;
  const ADMIN = "33333333-3333-4333-8333-333333333333";
  const ME = "44444444-4444-4444-8444-444444444444";
  const expected = { orgId: ORG, recipientUserId: ME };

  class MapEpochs {
    readonly epochs = new Map<string, number>();
    get(orgId: string) {
      return this.epochs.get(orgId);
    }
    record(orgId: string, epoch: number) {
      this.epochs.set(orgId, epoch);
    }
  }

  type User = Awaited<ReturnType<typeof makeUser>>;
  function link(signer: User, wrap: Omit<OrgKeyWrap, "orgId" | "epoch" | "signerUserId">, epoch = 1): SignedWrapLink {
    const full = { ...wrap, orgId: ORG, epoch, signerUserId: signer.bundle.userId };
    return { wrap: full, signature: signOrgKeyWrap(full, signer.identity.secretKey), signer: signer.bundle };
  }

  /** owner (self-signed) -> admin -> me, everyone confirmed */
  async function setup(epoch = 1) {
    const owner = await makeUser(1, OWNER);
    const admin = await makeUser(2, ADMIN);
    const chain = [
      link(admin, { recipientUserId: ME, role: "member", encryptedOrgKey: btoa("key-for-me") }, epoch),
      link(owner, { recipientUserId: ADMIN, role: "admin", encryptedOrgKey: btoa("key-for-admin") }, epoch),
      link(owner, { recipientUserId: OWNER, role: "owner", encryptedOrgKey: btoa("key-for-owner") }, epoch),
    ];
    const pins = new MapPins();
    confirmKey(owner.bundle, pins);
    confirmKey(admin.bundle, pins);
    return { owner, admin, chain, pins, epochs: new MapEpochs() };
  }

  it("accepts a chain of confirmed admins ending in the owner's self-signed wrap", async () => {
    const { chain, pins, epochs } = await setup();
    expect(verifyOrgKeyChain(chain, expected, pins, epochs)).toEqual(chain[0]!.wrap);
  });

  it("asks for explicit confirmation of signers it has not pinned, and pins nothing", async () => {
    const { chain, epochs } = await setup();
    const pins = new MapPins();
    const err = (() => {
      try {
        verifyOrgKeyChain(chain, expected, pins, epochs);
      } catch (e) {
        return e;
      }
      return undefined;
    })();
    expect(err).toBeInstanceOf(UnconfirmedSignersError);
    expect((err as UnconfirmedSignersError).signers.map((s) => s.bundle.userId).sort()).toEqual([OWNER, ADMIN].sort());
    expect(pins.pins.size).toBe(0);
  });

  it("refuses an unsigned wrap", async () => {
    const { chain, pins, epochs } = await setup();
    const unsigned = [{ ...chain[0]!, signature: null }, ...chain.slice(1)];
    expect(() => verifyOrgKeyChain(unsigned, expected, pins, epochs)).toThrow(UntrustedOrgKeyError);
  });

  it("refuses a key shared by a plain member", async () => {
    const { owner, admin, pins, epochs } = await setup();
    const chain = [
      link(admin, { recipientUserId: ME, role: "member", encryptedOrgKey: btoa("server-key") }),
      link(owner, { recipientUserId: ADMIN, role: "member", encryptedOrgKey: btoa("key-for-admin") }),
      link(owner, { recipientUserId: OWNER, role: "owner", encryptedOrgKey: btoa("key-for-owner") }),
    ];
    expect(() => verifyOrgKeyChain(chain, expected, pins, epochs)).toThrow(UntrustedOrgKeyError);
  });

  it("refuses a self-signed wrap from anyone but an owner", async () => {
    const { admin, pins, epochs } = await setup();
    const chain = [link(admin, { recipientUserId: ADMIN, role: "admin", encryptedOrgKey: btoa("k") })];
    expect(() => verifyOrgKeyChain(chain, { orgId: ORG, recipientUserId: ADMIN }, pins, epochs)).toThrow(
      UntrustedOrgKeyError,
    );
  });

  it("refuses a wrap the server replaced", async () => {
    const { chain, pins, epochs } = await setup();
    const replaced = [{ ...chain[0]!, wrap: { ...chain[0]!.wrap, encryptedOrgKey: btoa("server-key") } }, ...chain.slice(1)];
    expect(() => verifyOrgKeyChain(replaced, expected, pins, epochs)).toThrow(UntrustedOrgKeyError);
  });

  it("refuses an old key epoch once a newer one was accepted", async () => {
    const { chain, pins, epochs } = await setup(1);
    epochs.record(ORG, 2);
    expect(() => verifyOrgKeyChain(chain, expected, pins, epochs)).toThrow(UntrustedOrgKeyError);
  });

  it("detects a signer's identity swapped by the server", async () => {
    const { chain, pins, epochs } = await setup();
    const mallory = await makeUser(9, ADMIN);
    const forged = [
      link(mallory, { recipientUserId: ME, role: "member", encryptedOrgKey: btoa("server-key") }),
      ...chain.slice(1),
    ];
    expect(() => verifyOrgKeyChain(forged, expected, pins, epochs)).toThrow(PinnedKeyChangedError);
  });
});
