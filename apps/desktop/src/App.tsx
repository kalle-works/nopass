"use client";

import { useCallback, useEffect, useState } from "react";
import { UnlockScreen, useNopassStore, DecryptedVaultItemCard, ItemEditor, OrgPanel } from "@nopass/ui";
import { decryptItem, encryptItem } from "@nopass/crypto";
import type { EncryptedVaultItem, VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { createApiClient } from "@nopass/ui";
import { useBiometric } from "./hooks/useBiometric";
import { keychain, DEVICE_KEY_ACCOUNT } from "./hooks/useKeychain";
import { loadLocalItems, upsertLocalItem } from "./hooks/useLocalDb";

const API_BASE = import.meta.env["VITE_API_URL"] ?? "http://localhost:3001";
const api = createApiClient(API_BASE);

type Screen = "unlock-mode-select" | "unlock-srp" | "unlock-register" | "vault";
type SidebarTab = "vault" | "orgs";
type Filter = "all" | VaultItemType;

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
};

export default function App() {
  const [screen, setScreen] = useState<Screen>("unlock-mode-select");
  const [srpMode, setSrpMode] = useState<"login" | "register">("login");
  const biometric = useBiometric();

  const {
    isUnlocked, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey,
    items, isLoading, setItems, upsertItem, markDeleted, setLoading, lock,
  } = useNopassStore();

  // Transition to vault after unlock
  useEffect(() => {
    if (isUnlocked() && screen !== "vault") {
      setScreen("vault");
      syncFromApi();
    }
  });

  async function syncFromApi() {
    if (!sessionToken || !defaultVaultId) return;
    setLoading(true);
    try {
      const apiItems = await api.vault.items(defaultVaultId, sessionToken);
      setItems(apiItems);
      for (const item of apiItems) await upsertLocalItem(item);
    } catch {
      // Offline — load from local DB
      const localItems = await loadLocalItems();
      if (localItems.length > 0) setItems(localItems);
    } finally {
      setLoading(false);
    }
  }

  async function handleBiometricUnlock() {
    const ok = await biometric.authenticate("Unlock your nopass vault");
    if (!ok) return;

    const stored = await keychain.load(DEVICE_KEY_ACCOUNT);
    if (!stored) {
      alert("No device key found. Please sign in with your master password first.");
      return;
    }

    // The stored value is JSON: { sessionToken, defaultVaultId, vaultEncKeyB64, vaultMacKeyB64 }
    const data = JSON.parse(stored) as {
      sessionToken: string;
      defaultVaultId: string;
      vaultEncKeyB64: string;
      vaultMacKeyB64: string;
    };

    const encKeyBytes = Uint8Array.from(atob(data.vaultEncKeyB64), (c) => c.charCodeAt(0));
    const macKeyBytes = Uint8Array.from(atob(data.vaultMacKeyB64), (c) => c.charCodeAt(0));

    const [vaultEncKey, vaultMacKey] = await Promise.all([
      crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
      crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
    ]);

    useNopassStore.setState({
      sessionToken: data.sessionToken,
      defaultVaultId: data.defaultVaultId,
      vaultEncKey,
      vaultMacKey,
    });
  }

  function handleLock() {
    lock();
    setScreen("unlock-mode-select");
  }

  if (screen === "vault" && isUnlocked()) {
    return (
      <VaultScreen
        api={api}
        sessionToken={sessionToken!}
        defaultVaultId={defaultVaultId!}
        vaultEncKey={vaultEncKey!}
        vaultMacKey={vaultMacKey!}
        items={items}
        isLoading={isLoading}
        setItems={setItems}
        upsertItem={upsertItem}
        markDeleted={markDeleted}
        onLock={handleLock}
      />
    );
  }

  if (screen === "unlock-srp" || screen === "unlock-register") {
    return (
      <UnlockScreen
        apiClient={api}
        mode={srpMode}
        onSuccess={async () => {
          // After SRP login, save keys to Keychain for biometric unlock
          const state = useNopassStore.getState();
          if (state.vaultEncKey && state.vaultMacKey && biometric.available) {
            try {
              const encRaw = await crypto.subtle.exportKey("raw", state.vaultEncKey);
              const macRaw = await crypto.subtle.exportKey("raw", state.vaultMacKey);
              const encB64 = btoa(String.fromCharCode(...new Uint8Array(encRaw)));
              const macB64 = btoa(String.fromCharCode(...new Uint8Array(macRaw)));
              await keychain.save(DEVICE_KEY_ACCOUNT, JSON.stringify({
                sessionToken: state.sessionToken,
                defaultVaultId: state.defaultVaultId,
                vaultEncKeyB64: encB64,
                vaultMacKeyB64: macB64,
              }));
            } catch {
              // Keychain save failed — continue without biometric
            }
          }
          setScreen("vault");
        }}
        onSwitchMode={() => {
          setSrpMode((m) => (m === "login" ? "register" : "login"));
        }}
      />
    );
  }

  // Mode select screen (default)
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 dark:bg-gray-900 gap-4">
      <div className="w-full max-w-md p-8 bg-white dark:bg-gray-800 rounded-2xl shadow-lg">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white mb-1">nopass</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-8">
          Your zero-knowledge password manager
        </p>

        <div className="space-y-3">
          {biometric.available && (
            <button
              onClick={handleBiometricUnlock}
              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-xl transition-colors text-sm"
            >
              Unlock with Touch ID
            </button>
          )}

          <button
            onClick={() => { setSrpMode("login"); setScreen("unlock-srp"); }}
            className={`w-full py-3 px-4 font-medium rounded-xl transition-colors text-sm ${
              biometric.available
                ? "bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-900 dark:text-white"
                : "bg-blue-600 hover:bg-blue-700 text-white"
            }`}
          >
            Sign in with master password
          </button>

          <button
            onClick={() => { setSrpMode("register"); setScreen("unlock-register"); }}
            className="w-full py-3 px-4 bg-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 text-sm transition-colors"
          >
            Create new account
          </button>
        </div>
      </div>
    </div>
  );
}

interface VaultScreenProps {
  api: ReturnType<typeof createApiClient>;
  sessionToken: string;
  defaultVaultId: string;
  vaultEncKey: CryptoKey;
  vaultMacKey: CryptoKey;
  items: EncryptedVaultItem[];
  isLoading: boolean;
  setItems: (items: EncryptedVaultItem[]) => void;
  upsertItem: (item: EncryptedVaultItem) => void;
  markDeleted: (id: string) => void;
  onLock: () => void;
}

function VaultScreen({
  api, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey,
  items, isLoading, upsertItem, markDeleted, onLock,
}: VaultScreenProps) {
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("vault");
  const [decrypted, setDecrypted] = useState<Map<string, VaultItemPlaintext>>(new Map());
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [modal, setModal] = useState<
    | { mode: "create"; itemType: VaultItemType }
    | { mode: "edit"; entry: { item: EncryptedVaultItem; plaintext: VaultItemPlaintext } }
    | null
  >(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const active = items.filter((i) => i.deletedAt === null);
    Promise.all(
      active.map(async (item) => {
        try {
          return [item.id, await decryptItem(item, vaultEncKey, vaultMacKey)] as const;
        } catch {
          return null;
        }
      }),
    ).then((results) => {
      const map = new Map<string, VaultItemPlaintext>();
      for (const r of results) if (r) map.set(r[0], r[1]);
      setDecrypted(map);
    });
  }, [items, vaultEncKey, vaultMacKey]);

  const handleSave = useCallback(async (plaintext: VaultItemPlaintext) => {
    setSaving(true);
    setError(null);
    try {
      const enc = await encryptItem(plaintext, vaultEncKey, vaultMacKey);

      if (modal?.mode === "create") {
        const created = await api.vault.create(defaultVaultId, {
          itemType: plaintext.type, blob: enc.blob, blobIv: enc.blobIv, blobMac: enc.blobMac,
        }, sessionToken);
        upsertItem(created);
        await upsertLocalItem(created);
      } else if (modal?.mode === "edit") {
        await api.vault.update(defaultVaultId, modal.entry.item.id, {
          blob: enc.blob, blobIv: enc.blobIv, blobMac: enc.blobMac, version: modal.entry.item.version,
        }, sessionToken);
        const updated = { ...modal.entry.item, blob: enc.blob, blobIv: enc.blobIv, blobMac: enc.blobMac, version: modal.entry.item.version + 1 };
        upsertItem(updated);
        await upsertLocalItem(updated);
      }
      setModal(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }, [modal, api, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem]);

  const handleDelete = useCallback(async (item: EncryptedVaultItem) => {
    if (!confirm("Delete this item?")) return;
    try {
      await api.vault.delete(defaultVaultId, item.id, sessionToken);
      markDeleted(item.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }, [api, sessionToken, defaultVaultId, markDeleted]);

  const activeItems = items.filter((i) => i.deletedAt === null);
  const filteredItems = activeItems.filter((item) => {
    if (filter !== "all" && item.itemType !== filter) return false;
    if (search) {
      const plain = decrypted.get(item.id);
      return plain ? plain.name.toLowerCase().includes(search.toLowerCase()) : false;
    }
    return true;
  });

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      <aside className="w-52 flex flex-col border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0">
        <div className="px-4 py-5 border-b border-gray-200 dark:border-gray-700">
          <h1 className="text-base font-semibold text-gray-900 dark:text-white">nopass</h1>
        </div>
        {/* Sidebar tab switcher */}
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          {(["vault", "orgs"] as SidebarTab[]).map((t) => (
            <button key={t} onClick={() => setSidebarTab(t)}
              className={`flex-1 py-2 text-xs font-medium transition-colors ${
                sidebarTab === t
                  ? "border-b-2 border-blue-600 text-blue-700 dark:text-blue-300"
                  : "text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
              }`}
            >
              {t === "vault" ? "Vault" : "Teams"}
            </button>
          ))}
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {sidebarTab === "vault" && (["all", "login", "note", "card", "identity"] as Filter[]).map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                filter === f
                  ? "bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium"
                  : "text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              }`}
            >
              {f === "all" ? "All items" : TYPE_LABELS[f]}
              <span className="ml-1 text-xs text-gray-400">
                ({f === "all" ? activeItems.length : activeItems.filter((i) => i.itemType === f).length})
              </span>
            </button>
          ))}
          {sidebarTab === "orgs" && (
            <OrgPanel
              apiClient={api}
              sessionToken={sessionToken}
              onOrgVaultKeyChange={() => {}}
            />
          )}
        </nav>
        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <button onClick={onLock}
            className="w-full text-left px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg">
            Lock vault
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <input type="search" placeholder="Search…" value={search} onChange={(e) => setSearch(e.target.value)}
            className="flex-1 max-w-sm px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
          <div className="flex items-center gap-2 ml-auto">
            {(["login", "note", "card", "identity"] as VaultItemType[]).map((t) => (
              <button key={t} onClick={() => setModal({ mode: "create", itemType: t })}
                className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium">
                + {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              {error}
            </div>
          )}
          {isLoading ? (
            <div className="flex items-center justify-center h-32 text-gray-400 text-sm">Loading…</div>
          ) : filteredItems.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-gray-400 text-sm">
              {search ? "No matching items" : "No items yet — add one above"}
            </div>
          ) : (
            <div className="max-w-2xl space-y-1">
              {filteredItems.map((item) => {
                const plain = decrypted.get(item.id);
                return (
                  <div key={item.id} className="flex items-center group">
                    <div className="flex-1 min-w-0">
                      <DecryptedVaultItemCard item={item} decryptedName={plain?.name ?? "…"}
                        onClick={() => { if (plain) setModal({ mode: "edit", entry: { item, plaintext: plain } }); }} />
                    </div>
                    <button onClick={() => handleDelete(item)}
                      className="ml-2 px-2 py-1 text-xs text-red-500 hover:text-red-700 opacity-0 group-hover:opacity-100 transition-opacity">
                      Delete
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </main>
      </div>

      {modal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
              {modal.mode === "create" ? `New ${modal.itemType}` : `Edit ${modal.entry.plaintext.type}`}
            </h2>
            <ItemEditor
              itemType={modal.mode === "create" ? modal.itemType : modal.entry.plaintext.type}
              initial={modal.mode === "edit" ? modal.entry.plaintext : undefined}
              onSave={handleSave}
              onCancel={() => setModal(null)}
              saving={saving}
            />
          </div>
        </div>
      )}
    </div>
  );
}
