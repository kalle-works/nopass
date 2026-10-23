import { describe, expect, it } from "vitest";
import {
  type KeyPinStore,
  type OrgEpochStore,
  chainFromServer,
  confirmKey,
  deriveIdentityKey,
  generateOrgKey,
  generateUserKeyPair,
  signKeyBundle,
  stretchMasterKey,
  verifyOrgKeyChain,
} from "@nopass/crypto";
import type { KeyBundle, OrgMember, WrapLink } from "@nopass/types";
import { buildResignedWraps, checkOrgKey, openOrgKey } from "../lib/org-trust";

const ORG = "22222222-2222-4222-8222-222222222222";
const OWNER = "11111111-1111-4111-8111-111111111111";
const BOB = "33333333-3333-4333-8333-333333333333";
const CAROL = "44444444-4444-4444-8444-444444444444";

function memoryPins(): KeyPinStore {
  const m = new Map<string, string>();
  return { get: (u) => m.get(u), set: (u, k) => void m.set(u, k) };
}
function memoryEpochs(): OrgEpochStore {
  const m = new Map<string, number>();
  return { get: (o) => m.get(o), record: (o, e) => void m.set(o, e) };
}

async function makeUser(seed: number, userId: string) {
  const { stretchedMasterKey } = await stretchMasterKey(new Uint8Array(32).fill(seed), `${seed}@example.com`);
  const pair = await generateUserKeyPair(stretchedMasterKey);
  const identity = await deriveIdentityKey(pair.protectedPrivateKey, pair.protectedPrivateKeyIv, stretchedMasterKey);
  const bundle: KeyBundle = {
    userId,
    publicKey: identity.rsaPublicKeyB64,
    identityPublicKey: identity.publicKeyB64,
    publicKeySignature: signKeyBundle(userId, identity.rsaPublicKeyB64, identity.secretKey),
  };
  const member = (role: OrgMember["role"]): OrgMember => ({
    userId,
    role,
    status: "active",
    joinedAt: null,
    publicKey: bundle.publicKey,
    identityPublicKey: bundle.identityPublicKey,
    publicKeySignature: bundle.publicKeySignature,
  });
  return { pair, stretchedMasterKey, bundle, member };
}

describe("checkOrgKey", () => {
  it("never lets an unsigned wrap through, and offers re-signing only to the owner of their own wrap", async () => {
    const owner = await makeUser(1, OWNER);
    const unsigned = (recipient: string, role: WrapLink["role"], signer: string): WrapLink => ({
      recipientUserId: recipient,
      role,
      encryptedOrgKey: btoa("server-chosen-key"),
      wrapSignature: null,
      keyEpoch: null,
      signerUserId: signer,
      signer: owner.bundle,
    });
    const pins = memoryPins();
    confirmKey(owner.bundle, pins);

    expect(checkOrgKey(ORG, [unsigned(OWNER, "owner", OWNER)], { userId: OWNER, role: "owner" }, pins, memoryEpochs()))
      .toEqual({ status: "unsigned", canResign: true });
    expect(
      checkOrgKey(ORG, [unsigned(BOB, "member", OWNER)], { userId: BOB, role: "member" }, pins, memoryEpochs()),
    ).toEqual({ status: "unsigned", canResign: false });
  });
});

describe("openOrgKey", () => {
  it("never decrypts or hands out an unsigned wrap", async () => {
    const owner = await makeUser(1, OWNER);
    const pins = memoryPins();
    confirmKey(owner.bundle, pins);
    const unsigned: WrapLink = {
      recipientUserId: BOB,
      role: "member",
      encryptedOrgKey: btoa("server-chosen-key"),
      wrapSignature: null,
      keyEpoch: null,
      signerUserId: OWNER,
      signer: owner.bundle,
    };
    let decrypted = 0;

    const { orgKey } = await openOrgKey(ORG, [unsigned], { userId: BOB, role: "member" }, { pins, epochs: memoryEpochs() }, async () => {
      decrypted++;
      return generateOrgKey();
    });
    expect(orgKey).toBeNull();
    expect(decrypted).toBe(0);
  });
});

describe("buildResignedWraps", () => {
  it("re-signs confirmed members so their chain verifies, and skips unconfirmed ones", async () => {
    const owner = await makeUser(1, OWNER);
    const bob = await makeUser(2, BOB);
    const carol = await makeUser(3, CAROL);
    const pins = memoryPins();
    confirmKey(bob.bundle, pins);

    const { wraps, skipped } = await buildResignedWraps({
      orgId: ORG,
      ownerUserId: OWNER,
      orgKey: await generateOrgKey(),
      members: [owner.member("owner"), bob.member("member"), carol.member("member")],
      pins,
      identity: {
        protectedPrivateKey: owner.pair.protectedPrivateKey,
        protectedPrivateKeyIv: owner.pair.protectedPrivateKeyIv,
        stretchedMasterKey: owner.stretchedMasterKey,
      },
    });
    expect(skipped).toEqual([CAROL]);

    // What the server would serve Bob after the re-sign: his wrap, then the owner's
    const link = (userId: string, role: WrapLink["role"]): WrapLink => {
      const w = wraps.find((x) => x.userId === userId)!;
      return {
        recipientUserId: userId,
        role,
        encryptedOrgKey: w.encryptedOrgKey,
        wrapSignature: w.wrapSignature,
        keyEpoch: w.keyEpoch,
        signerUserId: OWNER,
        signer: owner.bundle,
      };
    };
    const bobPins = memoryPins();
    confirmKey(owner.bundle, bobPins);
    expect(() =>
      verifyOrgKeyChain(
        chainFromServer(ORG, [link(BOB, "member"), link(OWNER, "owner")]),
        { orgId: ORG, recipientUserId: BOB },
        bobPins,
        memoryEpochs(),
      ),
    ).not.toThrow();
  });
});
