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
    try {
      await apiClient.orgs.removeMember(selectedOrg.id, userId, sessionToken);
      await selectOrg(selectedOrg.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to remove member");
    }
  }

  const inputClass =
    "w-full px-3 py-2 border border-gray-200 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500";

  return (
    <div className="p-3">
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider">Organizations</p>
        <button
          onClick={() => { setShowCreateForm(true); setSelectedOrg(null); }}
          className="text-xs px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors font-medium"
        >
          New
        </button>
      </div>

      {error && (
        <div className="mb-3 flex items-start gap-2 p-2.5 text-xs text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <svg className="w-3.5 h-3.5 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto shrink-0">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      )}

      {showCreateForm && (
        <div className="mb-3 p-3 border border-gray-200 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700/50">
          <p className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-2">New organization</p>
          <input
            type="text"
            placeholder="Organization name"
            value={newOrgName}
            onChange={(e) => setNewOrgName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && createOrg()}
            className={inputClass + " mb-2"}
            autoFocus
          />
          <div className="flex gap-2 justify-end">
            <button
              onClick={() => { setShowCreateForm(false); setNewOrgName(""); }}
              className="text-xs px-2.5 py-1.5 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-md transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={createOrg}
              disabled={saving || !newOrgName.trim()}
              className="text-xs px-2.5 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-md font-medium transition-colors"
            >
              {saving ? "Creating…" : "Create"}
            </button>
          </div>
        </div>
      )}

      {loading && !selectedOrg && (
        <div className="space-y-1.5">
          {[...Array(2)].map((_, i) => (
            <div key={i} className="h-12 rounded-lg bg-gray-100 dark:bg-gray-700 animate-pulse" />
          ))}
        </div>
      )}

      {!selectedOrg && !loading && (
        <ul className="space-y-1">
          {orgs.map((org) => (
            <li key={org.id}>
              <button
                onClick={() => selectOrg(org.id)}
                className="w-full text-left px-3 py-2.5 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-blue-400 dark:hover:border-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors"
              >
                <span className="block font-medium text-gray-900 dark:text-white text-sm">{org.name}</span>
                <span className="block text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                  {org.memberCount} member{org.memberCount !== 1 ? "s" : ""} · {org.role}
                </span>
              </button>
            </li>
          ))}
          {orgs.length === 0 && (
            <li className="text-xs text-gray-400 dark:text-gray-500 text-center py-6 leading-relaxed">
              No organizations yet.<br />Create one to share passwords with your team.
            </li>
          )}
        </ul>
      )}

      {selectedOrg && (
        <div>
          <button
            onClick={() => { setSelectedOrg(null); onOrgVaultKeyChange?.(selectedOrg.id, null); }}
            className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 mb-3 flex items-center gap-1 transition-colors"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6" />
            </svg>
            All orgs
          </button>

          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-semibold text-gray-900 dark:text-white truncate">{selectedOrg.name}</p>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0 ml-2 ${
              selectedOrg.role === "owner" ? "bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300" :
              selectedOrg.role === "admin" ? "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300" :
              "bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400"
            }`}>
              {selectedOrg.role}
            </span>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-[11px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider">
                Members ({selectedOrg.members.length})
              </p>
              {(selectedOrg.role === "owner" || selectedOrg.role === "admin") && (
                <button
                  onClick={() => setShowInviteForm(true)}
                  className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-md transition-colors"
                >
                  Invite
                </button>
              )}
            </div>

            {showInviteForm && (
              <div className="mb-3 p-3 border border-gray-200 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700/50">
                <input
                  type="email"
                  placeholder="Email address"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className={inputClass + " mb-2"}
                  autoFocus
                />
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as "admin" | "member")}
                  className={inputClass + " mb-2"}
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
                <div className="flex gap-2 justify-end">
                  <button
                    onClick={() => { setShowInviteForm(false); setInviteEmail(""); }}
                    className="text-xs px-2.5 py-1.5 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-md transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={inviteMember}
                    disabled={saving || !inviteEmail.trim()}
                    className="text-xs px-2.5 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-md font-medium transition-colors"
                  >
                    {saving ? "Inviting…" : "Send invite"}
                  </button>
                </div>
              </div>
            )}

            <ul className="space-y-1">
              {selectedOrg.members.map((m: OrgMember) => (
                <li key={m.userId} className="flex items-center justify-between px-2.5 py-2 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-100 dark:border-gray-700">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                        m.role === "owner" ? "bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300" :
                        m.role === "admin" ? "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300" :
                        "bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-400"
                      }`}>
                        {m.role}
                      </span>
                      {m.status === "pending" && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 font-medium">
                          pending
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-gray-400 dark:text-gray-500 font-mono mt-0.5">{m.userId.slice(0, 8)}…</p>
                  </div>
                  {selectedOrg.role !== "member" && m.role !== "owner" && (
                    <button
                      onClick={() => removeMember(m.userId)}
                      className="text-[11px] text-red-400 hover:text-red-600 dark:hover:text-red-400 ml-2 shrink-0 px-1.5 py-0.5 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors"
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
