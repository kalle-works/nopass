/**
 * Decides whether an organization key served by the server may be used, and
 * re-signs legacy organizations. The rules live in verifyOrgKeyChain; this
 * module maps its outcome onto what the UI has to do next.
 */
import {
  type KeyPinStore,
  bindingForItem,
  decryptVaultItem,
  encryptItemV2,
  generateOrgKey,
  type OrgEpochStore,
  type OrgKeyWrap,
  PinnedKeyChangedError,
  UnconfirmedSignersError,
  chainFromServer,
  deriveIdentityKey,
  encryptOrgKeyForMember,
  signOrgKeyWrap,
  verifyMemberKey,
  verifyOrgKeyChain,
} from "@nopass/crypto";
import type { EncryptedVaultItem, KeyBundle, OrgMember, RotateKeyRequest, WrapLink } from "@nopass/types";

export type OrgKeyCheck =
  /** Verified: the key in `wrap` may be decrypted and used. */
  | { status: "ok"; wrap: OrgKeyWrap }
  /** The user must compare these safety numbers before the key is used. */
  | { status: "confirm"; signers: Array<{ bundle: KeyBundle; safetyNumber: string }> }
  /** Our own wrap is unsigned (legacy). Never usable as is; an owner can re-sign the org. */
  | { status: "unsigned"; canResign: boolean }
  | { status: "refused"; reason: string };

export function checkOrgKey(
  orgId: string,
  chain: WrapLink[],
  me: { userId: string; role: string },
  pins: KeyPinStore,
  epochs: OrgEpochStore,
): OrgKeyCheck {
  const own = chain[0];
  if (own && own.recipientUserId === me.userId && own.wrapSignature === null) {
    return { status: "unsigned", canResign: me.role === "owner" && own.signerUserId === me.userId };
  }
  try {
    const wrap = verifyOrgKeyChain(chainFromServer(orgId, chain), { orgId, recipientUserId: me.userId }, pins, epochs);
    return { status: "ok", wrap };
  } catch (e) {
    if (e instanceof UnconfirmedSignersError) return { status: "confirm", signers: e.signers };
    if (e instanceof PinnedKeyChangedError) {
      return {
        status: "refused",
        reason: "Someone who vouches for this organization's key has a changed identity key. Compare safety numbers with them before using it.",
      };
    }
    return { status: "refused", reason: e instanceof Error ? e.message : "This organization's key cannot be verified." };
  }
}

/**
 * The only way the UI obtains an org key: verify the chain, and decrypt our
 * wrap only if it checks out. `decrypt` is never called for an unsigned,
 * unconfirmed or refused wrap. On success the epoch is recorded so older
 * wraps are refused from now on.
 */
export async function openOrgKey(
  orgId: string,
  chain: WrapLink[],
  me: { userId: string; role: string },
  stores: { pins: KeyPinStore; epochs: OrgEpochStore },
  decrypt: (encryptedOrgKey: string) => Promise<CryptoKey>,
): Promise<{ check: OrgKeyCheck; orgKey: CryptoKey | null }> {
  const check = checkOrgKey(orgId, chain, me, stores.pins, stores.epochs);
  if (check.status !== "ok") return { check, orgKey: null };
  const orgKey = await decrypt(check.wrap.encryptedOrgKey);
  stores.epochs.record(orgId, check.wrap.epoch);
  return { check, orgKey };
}

export interface ResignInput {
  orgId: string;
  /** Key epoch the wraps are signed for: the org's current one */
  epoch: number;
  ownerUserId: string;
  orgKey: CryptoKey;
  members: OrgMember[];
  pins: KeyPinStore;
  identity: { protectedPrivateKey: string; protectedPrivateKeyIv: string; stretchedMasterKey: CryptoKey };
}

/**
 * Build owner-signed wraps for every member of a legacy org whose key the
 * owner has confirmed. Members without a published identity key, or not yet
 * confirmed, are returned in `skipped` and stay unable to use the org key
 * until the owner re-signs again.
 */
export async function buildResignedWraps(input: ResignInput): Promise<{
  wraps: Array<{ userId: string; encryptedOrgKey: string; wrapSignature: string; keyEpoch: number }>;
  skipped: string[];
}> {
  const { epoch } = input;
  const identity = await deriveIdentityKey(
    input.identity.protectedPrivateKey,
    input.identity.protectedPrivateKeyIv,
    input.identity.stretchedMasterKey,
  );
  try {
    const wraps = [];
    const skipped: string[] = [];
    for (const m of input.members) {
      const self = m.userId === input.ownerUserId;
      let rsaPublicKey: string;
      if (self) {
        rsaPublicKey = identity.rsaPublicKeyB64;
      } else {
        if (!m.publicKey) {
          skipped.push(m.userId);
          continue;
        }
        try {
          const verified = verifyMemberKey(
            {
              userId: m.userId,
              publicKey: m.publicKey,
              identityPublicKey: m.identityPublicKey,
              publicKeySignature: m.publicKeySignature,
            },
            input.pins,
          );
          if (verified.firstSeen) {
            skipped.push(m.userId);
            continue;
          }
          rsaPublicKey = verified.rsaPublicKeyB64;
        } catch {
          skipped.push(m.userId);
          continue;
        }
      }
      const encryptedOrgKey = await encryptOrgKeyForMember(input.orgKey, rsaPublicKey);
      const wrapSignature = signOrgKeyWrap(
        {
          orgId: input.orgId,
          epoch,
          recipientUserId: m.userId,
          signerUserId: input.ownerUserId,
          role: m.role,
          encryptedOrgKey,
        },
        identity.secretKey,
      );
      wraps.push({ userId: m.userId, encryptedOrgKey, wrapSignature, keyEpoch: epoch });
    }
    return { wraps, skipped };
  } finally {
    identity.secretKey.fill(0);
  }
}

/** Some remaining members' keys are not confirmed (or not published), so a rotation would leave them out. */
export class UnconfirmedMembersError extends Error {
  constructor(readonly userIds: string[]) {
    super(
      `Confirm the safety numbers of every remaining member before rotating the key (${userIds.length} not confirmed). Members who have not published a key yet must sign in once or be removed.`,
    );
    this.name = "UnconfirmedMembersError";
  }
}

export interface RotationInput {
  orgId: string;
  ownerUserId: string;
  currentEpoch: number;
  /** The key being retired: used here only to read items, never to write */
  oldKey: CryptoKey;
  /** Every org item, tombstones included */
  items: EncryptedVaultItem[];
  /** Members who keep access (the removed member, if any, is not in this list) */
  remainingMembers: OrgMember[];
  pins: KeyPinStore;
  identity: ResignInput["identity"];
}

/**
 * Build a complete org key rotation: a fresh key at currentEpoch + 1, every
 * org item re-encrypted under it (v2 envelope, org scope, next revision),
 * and an owner-signed wrap for every remaining member. Refuses to build a
 * partial rotation: every remaining member must be confirmed.
 */
export async function buildRotation(input: RotationInput): Promise<{
  newKey: CryptoKey;
  request: RotateKeyRequest;
}> {
  const newEpoch = input.currentEpoch + 1;
  const newKey = await generateOrgKey();
  const { wraps, skipped } = await buildResignedWraps({
    orgId: input.orgId,
    epoch: newEpoch,
    ownerUserId: input.ownerUserId,
    orgKey: newKey,
    members: input.remainingMembers,
    pins: input.pins,
    identity: input.identity,
  });
  if (skipped.length > 0) throw new UnconfirmedMembersError(skipped);

  const items = [];
  for (const item of input.items) {
    const binding = bindingForItem({ ...item, orgId: input.orgId });
    // Org items have no v1 form, so the AES key doubles as the unused MAC key
    const current = await decryptVaultItem(item, binding, { vaultEncKey: input.oldKey, vaultMacKey: input.oldKey });
    const encrypted = await encryptItemV2(current.plaintext, binding, current.revision + 1, newKey);
    items.push({ id: item.id, ...encrypted });
  }
  return { newKey, request: { newEpoch, wraps, items } };
}

/** The org keys a client holds: the current one, and retired ones kept only to read. */
export interface OrgKeyring {
  current: CryptoKey;
  retired: CryptoKey[];
}

/**
 * Decrypt an org item with the current key, falling back to retired keys for
 * reads that were in flight during a rotation. Writes must always use
 * `ring.current`; nothing here encrypts.
 */
export async function decryptOrgItem(item: EncryptedVaultItem, orgId: string, ring: OrgKeyring) {
  const binding = bindingForItem({ ...item, orgId });
  let lastError: unknown;
  for (const key of [ring.current, ...ring.retired]) {
    try {
      return await decryptVaultItem(item, binding, { vaultEncKey: key, vaultMacKey: key });
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}
