import { describe, expect, it } from "vitest";
import {
  type KeyPinStore,
  type OrgEpochStore,
  UntrustedOrgKeyError,
  chainFromServer,
  confirmKey,
  decryptOrgKey,
  decryptUserPrivateKey,
  encryptItemV2,
  deriveIdentityKey,
  generateOrgKey,
  generateUserKeyPair,
  signKeyBundle,
  stretchMasterKey,
  verifyOrgKeyChain,
} from "@nopass/crypto";
import type { EncryptedVaultItem, KeyBundle, LoginItem, OrgMember, WrapLink } from "@nopass/types";
import {
  UnconfirmedMembersError,
  buildResignedWraps,
  buildRotation,
  checkOrgKey,
  decryptOrgItem,
  openOrgKey,
} from "../lib/org-trust";

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
      epoch: 1,
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

describe("buildRotation", () => {
  const ITEM = "55555555-5555-4555-8555-555555555555";
  const SECRET: LoginItem = { type: "login", name: "db", username: "root", password: "s3cret", urls: [], customFields: [] };

  async function orgWithItem() {
    const owner = await makeUser(1, OWNER);
    const bob = await makeUser(2, BOB);
    const carol = await makeUser(3, CAROL);
    const oldKey = await generateOrgKey();
    const binding = { scope: { kind: "org" as const, orgId: ORG }, itemId: ITEM, itemType: "login" as const };
    const item: EncryptedVaultItem = {
      id: ITEM,
      vaultId: ORG,
      userId: OWNER,
      orgId: ORG,
      itemType: "login",
      ...(await encryptItemV2(SECRET, binding, 4, oldKey)),
      version: 1,
      deletedAt: null,
      createdAt: "",
      updatedAt: "",
    };
    const pins = memoryPins();
    confirmKey(bob.bundle, pins);
    confirmKey(carol.bundle, pins);
    const identity = {
      protectedPrivateKey: owner.pair.protectedPrivateKey,
      protectedPrivateKeyIv: owner.pair.protectedPrivateKeyIv,
      stretchedMasterKey: owner.stretchedMasterKey,
    };
    return { owner, bob, carol, oldKey, item, pins, identity };
  }

  it("cuts the removed member off, keeps remaining members in, and re-keys every item", async () => {
    const { owner, bob, oldKey, item, pins, identity } = await orgWithItem();

    // Carol is removed: she keeps only the old key she already had
    const { request } = await buildRotation({
      orgId: ORG,
      ownerUserId: OWNER,
      currentEpoch: 1,
      oldKey,
      items: [item],
      remainingMembers: [owner.member("owner"), bob.member("member")],
      pins,
      identity,
    });
    expect(request.newEpoch).toBe(2);
    expect(request.wraps.map((w) => w.userId).sort()).toEqual([OWNER, BOB].sort());
    expect(request.items.map((i) => i.id)).toEqual([ITEM]);
    const rotated = { ...item, ...request.items[0]! };

    // Carol's old key no longer opens what the org holds after the rotation
    await expect(decryptOrgItem(rotated, ORG, { current: oldKey, retired: [] })).rejects.toThrow();

    // Bob unwraps his new copy with his own private key and reads the item
    const bobWrap = request.wraps.find((w) => w.userId === BOB)!;
    const bobPrivate = await decryptUserPrivateKey(
      bob.pair.protectedPrivateKey,
      bob.pair.protectedPrivateKeyIv,
      bob.stretchedMasterKey,
    );
    const bobKey = await decryptOrgKey(bobWrap.encryptedOrgKey, bobPrivate);
    await expect(decryptOrgItem(rotated, ORG, { current: bobKey, retired: [] })).resolves.toMatchObject({
      plaintext: SECRET,
      revision: 5,
    });

    // Bob's new chain verifies at epoch 2, after which epoch-1 wraps are refused
    const link = (userId: string, role: WrapLink["role"], epoch: number, encryptedOrgKey: string, signature: string): WrapLink => ({
      recipientUserId: userId,
      role,
      encryptedOrgKey,
      wrapSignature: signature,
      keyEpoch: epoch,
      signerUserId: OWNER,
      signer: owner.bundle,
    });
    const ownerWrap = request.wraps.find((w) => w.userId === OWNER)!;
    const bobPins = memoryPins();
    confirmKey(owner.bundle, bobPins);
    const epochs = memoryEpochs();
    const { orgKey } = await openOrgKey(
      ORG,
      [
        link(BOB, "member", 2, bobWrap.encryptedOrgKey, bobWrap.wrapSignature),
        link(OWNER, "owner", 2, ownerWrap.encryptedOrgKey, ownerWrap.wrapSignature),
      ],
      { userId: BOB, role: "member" },
      { pins: bobPins, epochs },
      async (wrapped) => decryptOrgKey(wrapped, bobPrivate),
    );
    expect(orgKey).not.toBeNull();
    expect(epochs.get(ORG)).toBe(2);

    const stale = await buildResignedWraps({
      orgId: ORG,
      epoch: 1,
      ownerUserId: OWNER,
      orgKey: oldKey,
      members: [owner.member("owner"), bob.member("member")],
      pins,
      identity,
    });
    const staleBob = stale.wraps.find((w) => w.userId === BOB)!;
    const staleOwner = stale.wraps.find((w) => w.userId === OWNER)!;
    expect(() =>
      verifyOrgKeyChain(
        chainFromServer(ORG, [
          link(BOB, "member", 1, staleBob.encryptedOrgKey, staleBob.wrapSignature),
          link(OWNER, "owner", 1, staleOwner.encryptedOrgKey, staleOwner.wrapSignature),
        ]),
        { orgId: ORG, recipientUserId: BOB },
        bobPins,
        epochs,
      ),
    ).toThrow(UntrustedOrgKeyError);
  });

  it("refuses to build a rotation that would leave a remaining member without a key", async () => {
    const { owner, bob, oldKey, item, identity } = await orgWithItem();
    const nobodyConfirmed = memoryPins();
    await expect(
      buildRotation({
        orgId: ORG,
        ownerUserId: OWNER,
        currentEpoch: 1,
        oldKey,
        items: [item],
        remainingMembers: [owner.member("owner"), bob.member("member")],
        pins: nobodyConfirmed,
        identity,
      }),
    ).rejects.toBeInstanceOf(UnconfirmedMembersError);
  });

  it("reads items written before a rotation with a retired key, but prefers the current one", async () => {
    const { oldKey, item } = await orgWithItem();
    const newKey = await generateOrgKey();
    await expect(decryptOrgItem(item, ORG, { current: newKey, retired: [oldKey] })).resolves.toMatchObject({
      plaintext: SECRET,
    });
  });
});
