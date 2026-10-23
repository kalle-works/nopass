import { useEffect, useState } from "react";
import { ChevronLeft, X } from "lucide-react";
import type { ApiClient } from "../lib/api-client";
import type { OrgDetails, OrgMember, OrgSummary } from "@nopass/types";
import {
  computeEmailHash,
  decryptOrgKey,
  decryptUserPrivateKey,
  encryptOrgKeyForMember,
  exportOrgKey,
  generateOrgKey,
  generateUserKeyPair,
  importOrgKey,
} from "@nopass/crypto";
import { useNopassStore } from "../store/vault-store";
import { Button, IconButton } from "../primitives/Button";
import { Field, inputClass } from "../primitives/Field";
import { Badge, Banner, Dialog } from "../primitives/Feedback";
import { cx } from "../primitives/cx";

interface OrgPanelProps {
  apiClient: ApiClient;
  sessionToken: string;
  onOrgVaultKeyChange?: (orgId: string, orgKey: CryptoKey | null) => void;
}

export function OrgPanel({ apiClient, sessionToken, onOrgVaultKeyChange }: OrgPanelProps) {
  const [orgs, setOrgs] = useState<OrgSummary[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<OrgDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member">("member");
  const [saving, setSaving] = useState(false);
  const [memberToRemove, setMemberToRemove] = useState<OrgMember | null>(null);

  const { stretchedMasterKey, protectedPrivateKey, protectedPrivateKeyIv } = useNopassStore();

  useEffect(() => {
    loadOrgs();
  }, []);

  async function loadOrgs() {
    setLoading(true);
    setError(null);
    try {
      const list = await apiClient.orgs.list(sessionToken);
      setOrgs(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load organizations");
    } finally {
      setLoading(false);
    }
  }

  async function selectOrg(orgId: string) {
    setLoading(true);
    setError(null);
    try {
      const details = await apiClient.orgs.get(orgId, sessionToken);
      setSelectedOrg(details);

      // Decrypt the org key and bubble it up so the vault can use it
      if (onOrgVaultKeyChange && stretchedMasterKey && protectedPrivateKey && protectedPrivateKeyIv) {
        const privateKey = await decryptUserPrivateKey(
          protectedPrivateKey,
          protectedPrivateKeyIv,
          stretchedMasterKey,
        );
        const orgKey = await decryptOrgKey(details.encryptedOrgKey, privateKey);
        onOrgVaultKeyChange(orgId, orgKey);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load org");
    } finally {
      setLoading(false);
    }
  }

  async function createOrg() {
    if (!newOrgName.trim() || !stretchedMasterKey) return;
    setSaving(true);
    setError(null);
    try {
      const keyPair = await generateUserKeyPair(stretchedMasterKey);
      const orgKey = await generateOrgKey();
      const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, keyPair.publicKeyB64);

      const created = await apiClient.orgs.create(
        {
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

      setOrgs((prev) => [...prev, created]);
      setNewOrgName("");
      setShowCreateForm(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create org");
    } finally {
      setSaving(false);
    }
  }

  async function inviteMember() {
    if (!inviteEmail.trim() || !selectedOrg || !stretchedMasterKey) return;
    if (!protectedPrivateKey || !protectedPrivateKeyIv) {
      setError("No private key found. Please re-login.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const emailHash = computeEmailHash(inviteEmail.trim().toLowerCase());

      // Look up the invitee's public key
      const { publicKey: recipientPublicKey } = await apiClient.orgs.getPublicKey(
        emailHash,
        sessionToken,
      );

      // Decrypt our org key, then re-encrypt for the invitee
      const privateKey = await decryptUserPrivateKey(
        protectedPrivateKey,
        protectedPrivateKeyIv,
        stretchedMasterKey,
      );
      const orgKey = await decryptOrgKey(selectedOrg.encryptedOrgKey, privateKey);
      const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, recipientPublicKey);

      await apiClient.orgs.invite(
        selectedOrg.id,
        { emailHash, role: inviteRole, encryptedOrgKey },
        sessionToken,
      );

      setInviteEmail("");
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

  const canManage = selectedOrg ? selectedOrg.role === "owner" || selectedOrg.role === "admin" : false;

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
                onChange={(e) => setInviteEmail(e.target.value)}
                autoFocus
              />
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
                  }}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={inviteMember}
                  disabled={!inviteEmail.trim()}
                  pending={saving}
                  pendingLabel="Inviting…"
                >
                  Send invite
                </Button>
              </div>
            </div>
          )}

          <ul className="divide-y divide-divider overflow-hidden rounded-lg border border-divider">
            {selectedOrg.members.map((m: OrgMember) => (
              <li key={m.userId} className="flex min-h-11 items-center justify-between gap-3 px-4 py-2">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="font-mono text-mono-sm text-muted">{m.userId.slice(0, 8)}…</span>
                  <Badge>{m.role}</Badge>
                  {m.status === "pending" && <Badge tone="warning">pending</Badge>}
                </div>
                {selectedOrg.role !== "member" && m.role !== "owner" && (
                  <Button variant="ghost" size="sm" onClick={() => setMemberToRemove(m)}>
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

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
