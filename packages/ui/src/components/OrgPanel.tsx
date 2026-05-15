import { useCallback, useEffect, useState } from "react";
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
    if (!confirm("Remove this member from the organization?")) return;
    try {
      await apiClient.orgs.removeMember(selectedOrg.id, userId, sessionToken);
      await selectOrg(selectedOrg.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to remove member");
    }
  }

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Organizations</h2>
        <button
          onClick={() => setShowCreateForm(true)}
          className="text-sm px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          + New org
        </button>
      </div>

      {error && (
        <p className="mb-3 text-sm text-red-600 bg-red-50 rounded-lg px-3 py-2">{error}</p>
      )}

      {showCreateForm && (
        <div className="mb-4 p-3 border border-gray-200 rounded-lg bg-gray-50">
          <p className="text-sm font-medium text-gray-700 mb-2">New organization</p>
          <input
            type="text"
            placeholder="Organization name"
            value={newOrgName}
            onChange={(e) => setNewOrgName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && createOrg()}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <div className="flex gap-2 justify-end">
            <button
              onClick={() => { setShowCreateForm(false); setNewOrgName(""); }}
              className="text-sm px-3 py-1.5 text-gray-600 hover:text-gray-900"
            >
              Cancel
            </button>
            <button
              onClick={createOrg}
              disabled={saving || !newOrgName.trim()}
              className="text-sm px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg"
            >
              {saving ? "Creating…" : "Create"}
            </button>
          </div>
        </div>
      )}

      {loading && !selectedOrg && (
        <p className="text-sm text-gray-500">Loading…</p>
      )}

      {!selectedOrg && (
        <ul className="space-y-2">
          {orgs.map((org) => (
            <li key={org.id}>
              <button
                onClick={() => selectOrg(org.id)}
                className="w-full text-left px-3 py-2.5 rounded-lg border border-gray-200 hover:border-blue-400 hover:bg-blue-50 transition-colors"
              >
                <span className="block font-medium text-gray-900 text-sm">{org.name}</span>
                <span className="block text-xs text-gray-500 mt-0.5">
                  {org.memberCount} member{org.memberCount !== 1 ? "s" : ""} · {org.role}
                </span>
              </button>
            </li>
          ))}
          {orgs.length === 0 && !loading && (
            <li className="text-sm text-gray-500 text-center py-4">
              No organizations yet. Create one to share passwords with your team.
            </li>
          )}
        </ul>
      )}

      {selectedOrg && (
        <div>
          <button
            onClick={() => { setSelectedOrg(null); onOrgVaultKeyChange?.(selectedOrg.id, null); }}
            className="text-sm text-blue-600 hover:text-blue-800 mb-3 flex items-center gap-1"
          >
            ← All orgs
          </button>

          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-gray-900">{selectedOrg.name}</h3>
            <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full">
              {selectedOrg.role}
            </span>
          </div>

          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm font-medium text-gray-700">Members</p>
              {(selectedOrg.role === "owner" || selectedOrg.role === "admin") && (
                <button
                  onClick={() => setShowInviteForm(true)}
                  className="text-xs px-2 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded"
                >
                  + Invite
                </button>
              )}
            </div>

            {showInviteForm && (
              <div className="mb-3 p-3 border border-gray-200 rounded-lg bg-gray-50">
                <input
                  type="email"
                  placeholder="Email address"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as "admin" | "member")}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
                <div className="flex gap-2 justify-end">
                  <button
                    onClick={() => { setShowInviteForm(false); setInviteEmail(""); }}
                    className="text-sm px-3 py-1.5 text-gray-600 hover:text-gray-900"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={inviteMember}
                    disabled={saving || !inviteEmail.trim()}
                    className="text-sm px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg"
                  >
                    {saving ? "Inviting…" : "Send invite"}
                  </button>
                </div>
              </div>
            )}

            <ul className="divide-y divide-gray-100 border border-gray-200 rounded-lg overflow-hidden">
              {selectedOrg.members.map((m: OrgMember) => (
                <li key={m.userId} className="flex items-center justify-between px-3 py-2.5 bg-white">
                  <div>
                    <span className="text-sm text-gray-900 font-mono text-xs">{m.userId.slice(0, 8)}…</span>
                    <div className="flex gap-1.5 mt-0.5">
                      <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                        m.role === "owner" ? "bg-purple-100 text-purple-700" :
                        m.role === "admin" ? "bg-blue-100 text-blue-700" :
                        "bg-gray-100 text-gray-600"
                      }`}>
                        {m.role}
                      </span>
                      {m.status === "pending" && (
                        <span className="text-xs px-1.5 py-0.5 rounded-full bg-yellow-100 text-yellow-700">
                          pending
                        </span>
                      )}
                    </div>
                  </div>
                  {selectedOrg.role !== "member" && m.role !== "owner" && (
                    <button
                      onClick={() => removeMember(m.userId)}
                      className="text-xs text-red-500 hover:text-red-700 ml-2"
                    >
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
