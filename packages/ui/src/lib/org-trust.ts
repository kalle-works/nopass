/**
 * Decides whether an organization key served by the server may be used, and
 * re-signs legacy organizations. The rules live in verifyOrgKeyChain; this
 * module maps its outcome onto what the UI has to do next.
 */
import {
  type KeyPinStore,
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
import type { KeyBundle, OrgMember, WrapLink } from "@nopass/types";

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

export interface ResignInput {
  orgId: string;
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
  const epoch = 1;
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
