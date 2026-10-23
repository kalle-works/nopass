import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, X } from "lucide-react";
import type { ApiClient } from "../lib/api-client";
import type { KeyBundle, OrgDetails, OrgMember, OrgSummary, PendingInvite as OrgInvite } from "@nopass/types";
import {
  computeEmailHash,
  confirmKey,
  decryptOrgKey,
  decryptUserPrivateKey,
  deriveIdentityKey,
  encryptOrgKeyForMember,
  generateOrgKey,
  generateUserKeyPair,
  PinnedKeyChangedError,
  safetyNumber,
  signOrgKeyWrap,
  verifyMemberKey,
  type KeyPinStore,
  type OrgEpochStore,
} from "@nopass/crypto";
import { useNopassStore } from "../store/vault-store";
import { ensureIdentityPublished } from "../lib/identity-migration";
import { openKeyPinStore, openOrgEpochStore } from "../lib/local-trust-state";
import { buildResignedWraps, checkOrgKey, type OrgKeyCheck } from "../lib/org-trust";
import { Button, IconButton } from "../primitives/Button";
import { Field, inputClass } from "../primitives/Field";
import { Badge, Banner, Dialog } from "../primitives/Feedback";
import { cx } from "../primitives/cx";

/** What the panel knows about a member's key, shown next to them in the list. */
type MemberKeyStatus =
  | { kind: "confirmed"; safetyNumber: string }
  | { kind: "unconfirmed"; safetyNumber: string; bundle: KeyBundle }
  | { kind: "changed" }
  | { kind: "unverifiable"; reason: string };

function memberBundle(m: OrgMember): KeyBundle | null {
  return m.publicKey
    ? {
        userId: m.userId,
        publicKey: m.publicKey,
        identityPublicKey: m.identityPublicKey,
        publicKeySignature: m.publicKeySignature,
      }
    : null;
}

function memberKeyStatus(m: OrgMember, ownUserId: string | null, pins: KeyPinStore | null): MemberKeyStatus {
  const bundle = memberBundle(m);
  if (!bundle) return { kind: "unverifiable", reason: "no key published yet" };
  // Your own key is checked against what this device derives on unlock, not pinned
  if (m.userId === ownUserId || !pins) {
    return m.identityPublicKey
      ? { kind: "confirmed", safetyNumber: safetyNumber(m.userId, m.identityPublicKey) }
      : { kind: "unverifiable", reason: "no identity key yet" };
  }
  try {
    const verified = verifyMemberKey(bundle, pins);
    return verified.firstSeen
      ? { kind: "unconfirmed", safetyNumber: verified.safetyNumber, bundle }
      : { kind: "confirmed", safetyNumber: verified.safetyNumber };
  } catch (e) {
    if (e instanceof PinnedKeyChangedError) return { kind: "changed" };
    return { kind: "unverifiable", reason: e instanceof Error ? e.message : "key cannot be verified" };
  }
}

/** An invite addressed to us, with the verdict on its org key. */
type ReceivedInvite = OrgInvite & { check: OrgKeyCheck };

interface PendingInvite {
  bundle: KeyBundle;
  email: string;
  emailHash: string;
  recipientPublicKey: string;
  safetyNumber: string;
  firstSeen: boolean;
}

interface TrustStores {
  pins: KeyPinStore;
  epochs: OrgEpochStore;
}

interface OrgPanelProps {
  apiClient: ApiClient;
  sessionToken: string;
  onOrgVaultKeyChange?: (orgId: string, orgKey: CryptoKey | null) => void;
}

/** Safety numbers the user must compare before going on, with one confirm action. */
function ConfirmSigners({
  signers,
  action,
  onConfirm,
}: {
  signers: Array<{ bundle: KeyBundle; safetyNumber: string }>;
  action: string;
  onConfirm: () => void;
}) {
  return (
    <div className="space-y-2 rounded-md border border-divider bg-surface p-3">
      <p className="text-meta text-fg">
        Compare these safety numbers with each person over a channel you trust (in person, a call). Only continue if
        every number matches.
      </p>
      <ul className="space-y-1">
        {signers.map((s) => (
          <li key={s.bundle.userId} className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-mono-sm text-muted">{s.bundle.userId.slice(0, 8)}…</span>
            <span className="font-mono text-mono-sm text-fg">{s.safetyNumber}</span>
          </li>
        ))}
      </ul>
      <div className="flex justify-end">
        <Button size="sm" variant="primary" onClick={onConfirm}>
          {action}
        </Button>
      </div>
    </div>
  );
}

export function OrgPanel({ apiClient, sessionToken, onOrgVaultKeyChange }: OrgPanelProps) {
  const [orgs, setOrgs] = useState<OrgSummary[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<OrgDetails | null>(null);
  const [orgCheck, setOrgCheck] = useState<OrgKeyCheck | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
  const [saving, setSaving] = useState(false);
  const [memberToRemove, setMemberToRemove] = useState<OrgMember | null>(null);
  const [pendingInvite, setPendingInvite] = useState<PendingInvite | null>(null);
  const [received, setReceived] = useState<ReceivedInvite[]>([]);
  const [resignOpen, setResignOpen] = useState(false);
  const [trust, setTrust] = useState<TrustStores | null>(null);
  // Bumped after the user confirms keys, so derived key statuses recompute
  const [pinVersion, setPinVersion] = useState(0);

  const { userId, vaultMacKey, stretchedMasterKey, protectedPrivateKey, protectedPrivateKeyIv } = useNopassStore();
  const memberKeys = useMemo(
    () =>
      new Map(selectedOrg?.members.map((m) => [m.userId, memberKeyStatus(m, userId, trust?.pins ?? null)]) ?? []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [selectedOrg, userId, trust, pinVersion],
  );
  const changedKeys = [...memberKeys.values()].filter((k) => k.kind === "changed").length;

  useEffect(() => {
    if (!vaultMacKey) return;
    let cancelled = false;
    Promise.all([openKeyPinStore(vaultMacKey), openOrgEpochStore(vaultMacKey)]).then(([pins, epochs]) => {
      if (!cancelled) setTrust({ pins, epochs });
    });
    return () => {
      cancelled = true;
    };
  }, [vaultMacKey]);

  useEffect(() => {
    if (trust) loadOrgs(trust);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [trust]);

  function confirm(bundles: KeyBundle[]) {
    if (!trust) return;
    for (const b of bundles) confirmKey(b, trust.pins);
    setPinVersion((v) => v + 1);
  }

  async function loadOrgs(stores: TrustStores) {
    setLoading(true);
    setError(null);
    try {
      const [list, invites] = await Promise.all([
        apiClient.orgs.list(sessionToken),
        apiClient.orgs.invites(sessionToken),
      ]);
      setOrgs(list);
      setReceived(
        userId
          ? invites.map((inv) => ({
              ...inv,
              check: checkOrgKey(inv.orgId, inv.wrapChain, { userId, role: inv.role }, stores.pins, stores.epochs),
            }))
          : [],
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load organizations");
    } finally {
      setLoading(false);
    }
  }

  async function acceptInvite(invite: ReceivedInvite) {
    if (invite.check.status !== "ok" || !trust) return;
    setError(null);
    try {
      await apiClient.orgs.accept(invite.orgId, sessionToken);
      trust.epochs.record(invite.orgId, invite.check.wrap.epoch);
      await loadOrgs(trust);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to accept invite");
    }
  }

  async function decryptOwnOrgKey(encryptedOrgKey: string): Promise<CryptoKey> {
    if (!stretchedMasterKey || !protectedPrivateKey || !protectedPrivateKeyIv) {
      throw new Error("No private key found. Please re-login.");
    }
    const privateKey = await decryptUserPrivateKey(protectedPrivateKey, protectedPrivateKeyIv, stretchedMasterKey);
    return decryptOrgKey(encryptedOrgKey, privateKey);
  }

  async function selectOrg(orgId: string) {
    if (!trust || !userId) return;
    setLoading(true);
    setError(null);
    try {
      const details = await apiClient.orgs.get(orgId, sessionToken);
      const check = checkOrgKey(details.id, details.wrapChain, { userId, role: details.role }, trust.pins, trust.epochs);
      setSelectedOrg(details);
      setOrgCheck(check);

      // The org key is used only once its whole signing chain checks out
      if (check.status === "ok") {
        trust.epochs.record(details.id, check.wrap.epoch);
        onOrgVaultKeyChange?.(orgId, await decryptOwnOrgKey(details.encryptedOrgKey));
      } else {
        onOrgVaultKeyChange?.(orgId, null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load org");
    } finally {
      setLoading(false);
    }
  }

  /**
   * Owner of a legacy (unsigned) org: re-sign their own wrap and every
   * confirmed member's. The owner vouches for a key that was never signed,
   * which is why this needs an explicit decision in the dialog.
   */
  async function resignOrg() {
    if (!selectedOrg || !trust || !userId || !stretchedMasterKey || !protectedPrivateKey || !protectedPrivateKeyIv) return;
    setSaving(true);
    setError(null);
    try {
      const orgKey = await decryptOwnOrgKey(selectedOrg.encryptedOrgKey);
      const { wraps, skipped } = await buildResignedWraps({
        orgId: selectedOrg.id,
        ownerUserId: userId,
        orgKey,
        members: selectedOrg.members,
        pins: trust.pins,
        identity: { protectedPrivateKey, protectedPrivateKeyIv, stretchedMasterKey },
      });
      await apiClient.orgs.rewrap(selectedOrg.id, { wraps }, sessionToken);
      setResignOpen(false);
      await selectOrg(selectedOrg.id);
      if (skipped.length > 0) {
        setError(
          `${skipped.length} member${skipped.length === 1 ? " was" : "s were"} not re-signed: confirm their safety numbers (or ask them to sign in once), then re-sign again.`,
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to re-sign organization");
    } finally {
      setSaving(false);
    }
  }

  async function createOrg() {
    if (!newOrgName.trim() || !stretchedMasterKey) return;
    setSaving(true);
    setError(null);
    try {
      // Reuse the account's key pair: the server keeps the first one it was
      // given, so wrapping the org key to a fresh pair would lock us out of
      // the org after the next sign-in.
      let keyPair;
      if (protectedPrivateKey && protectedPrivateKeyIv) {
        const identity = await deriveIdentityKey(protectedPrivateKey, protectedPrivateKeyIv, stretchedMasterKey);
        identity.secretKey.fill(0);
        keyPair = { publicKeyB64: identity.rsaPublicKeyB64, protectedPrivateKey, protectedPrivateKeyIv };
      } else {
        keyPair = await generateUserKeyPair(stretchedMasterKey);
      }
      const orgKey = await generateOrgKey();
      const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, keyPair.publicKeyB64);
      if (!userId) throw new Error("Sign in again to create an organization.");

      // The owner's self-signed wrap is the root every member's key chain ends in
      const orgId = crypto.randomUUID();
      const keyEpoch = 1;
      const identity = await deriveIdentityKey(
        keyPair.protectedPrivateKey,
        keyPair.protectedPrivateKeyIv,
        stretchedMasterKey,
      );
      const wrapSignature = signOrgKeyWrap(
        { orgId, epoch: keyEpoch, recipientUserId: userId, signerUserId: userId, role: "owner", encryptedOrgKey },
        identity.secretKey,
      );
      identity.secretKey.fill(0);

      const created = await apiClient.orgs.create(
        {
          id: orgId,
          wrapSignature,
          keyEpoch,
          name: newOrgName.trim(),
          publicKey: keyPair.publicKeyB64,
          protectedPrivateKey: keyPair.protectedPrivateKey,
          protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
          encryptedOrgKey,
        },
        sessionToken,
      );

      // Persist key pair in store so future org operations can use it
      useNopassStore.getState().setKeyPair(
        keyPair.protectedPrivateKey,
        keyPair.protectedPrivateKeyIv,
      );
      await ensureIdentityPublished(apiClient, sessionToken, {
        userId,
        protectedPrivateKey: keyPair.protectedPrivateKey,
        protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
        stretchedMasterKey,
      });

      setOrgs((prev) => [...prev, created]);
      setNewOrgName("");
      setShowCreateForm(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create org");
    } finally {
      setSaving(false);
    }
  }

  /** Step 1: fetch and verify the invitee's key, then show its safety number. */
  async function lookUpInvitee() {
    if (!inviteEmail.trim() || !trust) return;
    setSaving(true);
    setError(null);
    try {
      const email = inviteEmail.trim().toLowerCase();
      const emailHash = computeEmailHash(email);
      const bundle = await apiClient.orgs.getPublicKey(emailHash, sessionToken);
      const verified = verifyMemberKey(bundle, trust.pins);
      setPendingInvite({
        bundle,
        email,
        emailHash,
        recipientPublicKey: verified.rsaPublicKeyB64,
        safetyNumber: verified.safetyNumber,
        firstSeen: verified.firstSeen,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to look up member");
    } finally {
      setSaving(false);
    }
  }

  /** Step 2: the user confirmed the number — pin it and wrap the org key to it. */
  async function inviteMember() {
    if (!pendingInvite || !selectedOrg || !stretchedMasterKey || !trust || orgCheck?.status !== "ok") return;
    if (!protectedPrivateKey || !protectedPrivateKeyIv || !userId) {
      setError("No private key found. Please re-login.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      confirm([pendingInvite.bundle]);
      const { emailHash, recipientPublicKey } = pendingInvite;
      const orgKey = await decryptOwnOrgKey(selectedOrg.encryptedOrgKey);
      const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, recipientPublicKey);

      const keyEpoch = orgCheck.wrap.epoch;
      const identity = await deriveIdentityKey(protectedPrivateKey, protectedPrivateKeyIv, stretchedMasterKey);
      const wrapSignature = signOrgKeyWrap(
        {
          orgId: selectedOrg.id,
          epoch: keyEpoch,
          recipientUserId: pendingInvite.bundle.userId,
          signerUserId: userId,
          role: inviteRole,
          encryptedOrgKey,
        },
        identity.secretKey,
      );
      identity.secretKey.fill(0);

      await apiClient.orgs.invite(
        selectedOrg.id,
        { emailHash, role: inviteRole, encryptedOrgKey, wrapSignature, keyEpoch },
        sessionToken,
      );

      setInviteEmail("");
      setPendingInvite(null);
      setShowInviteForm(false);
      // Refresh member list
      await selectOrg(selectedOrg.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to invite member");
    } finally {
      setSaving(false);
    }
  }

  async function removeMember(userId: string) {
    if (!selectedOrg) return;
    try {
      await apiClient.orgs.removeMember(selectedOrg.id, userId, sessionToken);
      await selectOrg(selectedOrg.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to remove member");
    } finally {
      setMemberToRemove(null);
    }
  }

  const canManage =
    selectedOrg && orgCheck?.status === "ok" ? selectedOrg.role === "owner" || selectedOrg.role === "admin" : false;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-h2 font-semibold text-fg">Organizations</h2>
        <Button
          size="sm"
          onClick={() => {
            setShowCreateForm(true);
            setSelectedOrg(null);
          }}
        >
          New
        </Button>
      </div>

      {error && (
        <Banner
          tone="danger"
          action={
            <IconButton label="Dismiss error" onClick={() => setError(null)} className="-my-1 -mr-2">
              <X aria-hidden className="size-4" />
            </IconButton>
          }
        >
          {error}
        </Banner>
      )}

      {showCreateForm && (
        <div className="space-y-3 rounded-lg border border-divider bg-bg-subtle p-4">
          <Field
            label="Organization name"
            placeholder="Organization name"
            value={newOrgName}
            onChange={(e) => setNewOrgName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && createOrg()}
            autoFocus
          />
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              onClick={() => {
                setShowCreateForm(false);
                setNewOrgName("");
              }}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={createOrg}
              disabled={!newOrgName.trim()}
              pending={saving}
              pendingLabel="Creating…"
            >
              Create
            </Button>
          </div>
        </div>
      )}

      {loading && !selectedOrg && (
        <div className="space-y-2" aria-busy="true" aria-label="Loading organizations">
          {[...Array(2)].map((_, i) => (
            <div key={i} className="h-14 animate-pulse rounded-lg bg-surface-hover" />
          ))}
        </div>
      )}

      {!selectedOrg && received.length > 0 && (
        <div className="space-y-2">
          <p className="text-meta font-medium text-fg">Invitations</p>
          <ul className="divide-y divide-divider overflow-hidden rounded-lg border border-divider">
            {received.map((inv) => (
              <li key={inv.orgId} className="flex items-start justify-between gap-3 px-4 py-3">
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-ui font-medium text-fg">{inv.orgName}</span>
                    <Badge>{inv.role}</Badge>
                  </div>
                  {inv.check.status === "ok" && (
                    <p className="text-meta text-muted">Signed by people whose safety numbers you confirmed.</p>
                  )}
                  {inv.check.status === "confirm" && (
                    <ConfirmSigners
                      signers={inv.check.signers}
                      action="All numbers match"
                      onConfirm={() => {
                        if (inv.check.status !== "confirm" || !trust) return;
                        confirm(inv.check.signers.map((s) => s.bundle));
                        void loadOrgs(trust);
                      }}
                    />
                  )}
                  {inv.check.status === "unsigned" && (
                    <p className="text-meta text-danger">
                      This invite is not signed. Ask the organization owner to invite you again.
                    </p>
                  )}
                  {inv.check.status === "refused" && <p className="text-meta text-danger">{inv.check.reason}</p>}
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  disabled={inv.check.status !== "ok"}
                  onClick={() => acceptInvite(inv)}
                >
                  Accept
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!selectedOrg && !loading && (
        <>
          {orgs.length > 0 ? (
            <ul className="divide-y divide-divider overflow-hidden rounded-lg border border-divider">
              {orgs.map((org) => (
                <li key={org.id}>
                  <button
                    onClick={() => selectOrg(org.id)}
                    className="flex min-h-11 w-full items-center justify-between gap-3 px-4 py-2 text-left transition-colors duration-[120ms] hover:bg-surface-hover"
                  >
                    <span className="min-w-0">
                      <span className="block truncate text-ui font-medium text-fg">{org.name}</span>
                      <span className="block text-meta text-muted">
                        {org.memberCount} member{org.memberCount !== 1 ? "s" : ""}
                      </span>
                    </span>
                    <Badge>{org.role}</Badge>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-ui text-muted">
              No organizations yet. Create one to share items with your team.
            </p>
          )}
        </>
      )}

      {selectedOrg && (
        <div className="space-y-4">
          <Button
            variant="ghost"
            size="sm"
            icon={<ChevronLeft aria-hidden className="size-4" />}
            onClick={() => {
              setSelectedOrg(null);
              onOrgVaultKeyChange?.(selectedOrg.id, null);
            }}
          >
            All organizations
          </Button>

          {orgCheck?.status === "confirm" && (
            <ConfirmSigners
              signers={orgCheck.signers}
              action="All numbers match — use this organization"
              onConfirm={() => {
                if (orgCheck.status !== "confirm") return;
                confirm(orgCheck.signers.map((s) => s.bundle));
                void selectOrg(selectedOrg.id);
              }}
            />
          )}
          {orgCheck?.status === "unsigned" &&
            (orgCheck.canResign ? (
              <Banner
                tone="warning"
                action={
                  <Button size="sm" onClick={() => setResignOpen(true)}>
                    Re-sign
                  </Button>
                }
              >
                This organization was created before keys were signed, so its key can't be verified and is not used.
                Re-sign it to bring it under verification.
              </Banner>
            ) : (
              <Banner tone="danger">
                Your copy of this organization's key is not signed, so it is not used. Ask the owner to re-sign the
                organization.
              </Banner>
            ))}
          {orgCheck?.status === "refused" && <Banner tone="danger">{orgCheck.reason}</Banner>}

          <div className="flex items-center gap-2">
            <h3 className="truncate text-h3 font-semibold text-fg">{selectedOrg.name}</h3>
            <Badge>{selectedOrg.role}</Badge>
          </div>

          <div className="flex items-center justify-between gap-3">
            <p className="text-meta font-medium text-fg">Members ({selectedOrg.members.length})</p>
            {canManage && (
              <Button size="sm" onClick={() => setShowInviteForm(true)}>
                Invite
              </Button>
            )}
          </div>

          {showInviteForm && (
            <div className="space-y-3 rounded-lg border border-divider bg-bg-subtle p-4">
              <Field
                label="Email address"
                type="email"
                placeholder="name@example.com"
                value={inviteEmail}
                onChange={(e) => {
                  setInviteEmail(e.target.value);
                  setPendingInvite(null);
                }}
                autoFocus
              />
              {pendingInvite && (
                <div className="space-y-1 rounded-md border border-divider bg-surface p-3">
                  <p className="text-meta font-medium text-fg">Safety number for {pendingInvite.email}</p>
                  <p className="font-mono text-mono-sm text-fg" data-testid="invite-safety-number">
                    {pendingInvite.safetyNumber}
                  </p>
                  <p className="text-meta text-muted">
                    {pendingInvite.firstSeen
                      ? "First time you see this person's key. Ask them to read their safety number to you over a channel you trust; only send the invite if it matches."
                      : "Matches the key you saw for this person before."}
                  </p>
                </div>
              )}
              <div className="flex flex-col gap-1.5">
                <label htmlFor="invite-role" className="text-meta font-medium text-fg">
                  Role
                </label>
                <select
                  id="invite-role"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as "admin" | "member")}
                  className={cx(inputClass, "h-9")}
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  variant="ghost"
                  onClick={() => {
                    setShowInviteForm(false);
                    setInviteEmail("");
                    setPendingInvite(null);
                  }}
                >
                  Cancel
                </Button>
                {pendingInvite ? (
                  <Button variant="primary" onClick={inviteMember} pending={saving} pendingLabel="Inviting…">
                    {pendingInvite.firstSeen ? "Numbers match — send invite" : "Send invite"}
                  </Button>
                ) : (
                  <Button
                    variant="primary"
                    onClick={lookUpInvitee}
                    disabled={!inviteEmail.trim()}
                    pending={saving}
                    pendingLabel="Checking key…"
                  >
                    Continue
                  </Button>
                )}
              </div>
            </div>
          )}

          {changedKeys > 0 && (
            <Banner tone="danger">
              {changedKeys === 1 ? "A member's identity key has" : `${changedKeys} members' identity keys have`} changed
              since you last saw {changedKeys === 1 ? "it" : "them"}. Someone may be impersonating them. Do not invite
              anyone or share items until you have compared safety numbers with them directly.
            </Banner>
          )}

          <ul className="divide-y divide-divider overflow-hidden rounded-lg border border-divider">
            {selectedOrg.members.map((m: OrgMember) => {
              const key = memberKeys.get(m.userId);
              return (
                <li key={m.userId} className="flex min-h-11 items-center justify-between gap-3 px-4 py-2">
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="font-mono text-mono-sm text-muted">{m.userId.slice(0, 8)}…</span>
                      {m.userId === userId && <Badge>you</Badge>}
                      <Badge>{m.role}</Badge>
                      {m.status === "pending" && <Badge tone="warning">pending</Badge>}
                      {key?.kind === "changed" && <Badge tone="danger">key changed</Badge>}
                    </div>
                    {(key?.kind === "confirmed" || key?.kind === "unconfirmed") && (
                      <p className="font-mono text-mono-sm text-muted" title="Safety number — compare it with this member">
                        {key.safetyNumber}
                      </p>
                    )}
                    {key?.kind === "unconfirmed" && (
                      <p className="flex items-center gap-2 text-meta text-muted">
                        Not confirmed yet.
                        <Button size="sm" variant="ghost" onClick={() => confirm([key.bundle])}>
                          Numbers match
                        </Button>
                      </p>
                    )}
                    {key?.kind === "unverifiable" && <p className="text-meta text-muted">Key not verifiable: {key.reason}</p>}
                  </div>
                  {selectedOrg.role !== "member" && m.role !== "owner" && (
                    <Button variant="ghost" size="sm" onClick={() => setMemberToRemove(m)}>
                      Remove
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      <Dialog
        open={resignOpen}
        onClose={() => setResignOpen(false)}
        title="Re-sign this organization?"
        description="You will vouch for the organization key your account holds now and share it, signed, with every member whose safety number you have confirmed. Do this only if you have no reason to think the key was tampered with; if in doubt, create a new organization instead."
        footer={
          <>
            <Button variant="ghost" onClick={() => setResignOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={resignOrg} pending={saving} pendingLabel="Re-signing…">
              Re-sign
            </Button>
          </>
        }
      />

      <Dialog
        open={memberToRemove !== null}
        onClose={() => setMemberToRemove(null)}
        title={`Remove member ${memberToRemove?.userId.slice(0, 8) ?? ""}…?`}
        description={
          selectedOrg
            ? `They lose access to items shared in ${selectedOrg.name}. You can invite them again later.`
            : undefined
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setMemberToRemove(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={() => memberToRemove && removeMember(memberToRemove.userId)}>
              Remove member
            </Button>
          </>
        }
      />
    </div>
  );
}
