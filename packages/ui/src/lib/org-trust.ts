/**
 * Decides whether an organization key served by the server may be used, and
 * re-signs legacy organizations. The rules live in verifyOrgKeyChain; this
 * module maps its outcome onto what the UI has to do next.
 */
import {
  type KeyPinStore,
  bindingForItem,
  type RevisionStore,
  decryptVaultItem,
  encryptVaultItem,
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
    // The owner can always re-sign their org, whatever the server claims signed their copy
    return { status: "unsigned", canResign: me.role === "owner" };
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

/** What this device has seen of an org before: used to notice a server leaving things out. */
export interface OrgLedgerEntry {
  items: string[];
  members: string[];
}

/** The org's item or member list from the server lacks entries this device knows about. */
export class RotationSetIncompleteError extends Error {
  constructor(readonly missingItems: string[], readonly missingMembers: string[]) {
    super(
      [
        missingItems.length > 0 ? `${missingItems.length} item(s) this device has seen are missing from the server's list` : "",
        missingMembers.length > 0 ? `${missingMembers.length} member(s) this device has seen are missing from the server's list` : "",
      ]
        .filter(Boolean)
        .join("; ") + ". Rotating now would silently leave them out.",
    );
    this.name = "RotationSetIncompleteError";
  }
}

/** Some org items cannot be decrypted (damaged, tampered or rolled back). */
export class UndecryptableItemsError extends Error {
  constructor(readonly itemIds: string[]) {
    super(
      `${itemIds.length} organization item(s) cannot be decrypted, so they cannot be moved to the new key. Delete them as part of the rotation, or cancel.`,
    );
    this.name = "UndecryptableItemsError";
  }
}

export interface RotationInput {
  orgId: string;
  ownerUserId: string;
  currentEpoch: number;
  /** The key being retired: used here only to read items, never to write */
  oldKey: CryptoKey;
  /** Every org item the server listed, tombstones included */
  items: EncryptedVaultItem[];
  /** Every member the server listed */
  members: OrgMember[];
  /** The member to remove in this rotation, if any */
  removeUserId: string | null;
  /** What this device saw of the org before; anything missing from the server lists is refused */
  known: OrgLedgerEntry;
  /** Items the owner chose to delete because they cannot be decrypted */
  dropItemIds: string[];
  /**
   * Ledger entries missing from the server that the owner acknowledged as
   * gone (account deleted, invite declined or expired, removed elsewhere).
   * Anything missing and not acknowledged still refuses the rotation.
   */
  acknowledgedGone: OrgLedgerEntry;
  pins: KeyPinStore;
  revisions: RevisionStore;
  identity: ResignInput["identity"];
}

export interface RotationPlan {
  request: RotateKeyRequest;
  /** Revisions to record once the server accepted the rotation */
  revisions: Array<[string, number]>;
  keepsAccess: string[];
  losesAccess: string[];
  /** Acknowledged-gone ledger entries that really were missing; drop them from the ledger on success */
  acknowledgedGone: OrgLedgerEntry;
}

/**
 * Build a complete org key rotation: a fresh key at currentEpoch + 1, every
 * org item re-encrypted under it (v2 envelope, org scope, next revision), and
 * an owner-signed wrap for every remaining member. It refuses to build a
 * partial rotation: every remaining member must be confirmed, every item and
 * member this device has seen must be in the server's lists, and every item
 * must decrypt (through the revision store, so a rolled-back item counts as
 * undecryptable) unless the owner chose to delete it.
 */
export async function buildRotation(input: RotationInput): Promise<RotationPlan> {
  const serverItems = new Set(input.items.map((i) => i.id));
  const serverMembers = new Set(input.members.map((m) => m.userId));
  const goneItems = input.known.items.filter((id) => !serverItems.has(id) && !input.dropItemIds.includes(id));
  const goneMembers = input.known.members.filter((id) => !serverMembers.has(id));
  const missingItems = goneItems.filter((id) => !input.acknowledgedGone.items.includes(id));
  const missingMembers = goneMembers.filter((id) => !input.acknowledgedGone.members.includes(id));
  if (missingItems.length > 0 || missingMembers.length > 0) {
    throw new RotationSetIncompleteError(missingItems, missingMembers);
  }

  const remaining = input.members.filter((m) => m.userId !== input.removeUserId);
  const newEpoch = input.currentEpoch + 1;
  const newKey = await generateOrgKey();
  const { wraps, skipped } = await buildResignedWraps({
    orgId: input.orgId,
    epoch: newEpoch,
    ownerUserId: input.ownerUserId,
    orgKey: newKey,
    members: remaining,
    pins: input.pins,
    identity: input.identity,
  });
  if (skipped.length > 0) throw new UnconfirmedMembersError(skipped);

  const items = [];
  const revisions: Array<[string, number]> = [];
  const undecryptable: string[] = [];
  for (const item of input.items) {
    if (input.dropItemIds.includes(item.id)) continue;
    const binding = bindingForItem({ ...item, orgId: input.orgId });
    let current;
    try {
      // Org items have no v1 form, so the AES key doubles as the unused MAC key
      current = await decryptVaultItem(
        item,
        binding,
        { vaultEncKey: input.oldKey, vaultMacKey: input.oldKey },
        input.revisions,
      );
    } catch {
      undecryptable.push(item.id);
      continue;
    }
    const { encrypted, revision } = await encryptVaultItem(current.plaintext, binding, newKey, input.revisions, current);
    items.push({ id: item.id, ...encrypted });
    revisions.push([item.id, revision]);
  }
  if (undecryptable.length > 0) throw new UndecryptableItemsError(undecryptable);

  const deleteItemIds = input.dropItemIds.filter((id) => serverItems.has(id));
  return {
    request: { newEpoch, wraps, items, ...(deleteItemIds.length > 0 ? { deleteItemIds } : {}) },
    revisions,
    keepsAccess: remaining.map((m) => m.userId),
    losesAccess: input.removeUserId ? [input.removeUserId] : [],
    acknowledgedGone: { items: goneItems, members: goneMembers },
  };
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
