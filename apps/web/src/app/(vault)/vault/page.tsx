"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  useNopassStore,
  ItemEditor,
  DecryptedVaultItemCard,
} from "@nopass/ui";
import { decryptItem, encryptItem } from "@nopass/crypto";
import type { EncryptedVaultItem, VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { api } from "@/lib/api";

type Filter = "all" | VaultItemType;

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
};

interface DecryptedEntry {
  item: EncryptedVaultItem;
  plaintext: VaultItemPlaintext;
}

export default function VaultPage() {
  const router = useRouter();
  const {
    isUnlocked,
    sessionToken,
    defaultVaultId,
    vaultEncKey,
    vaultMacKey,
    items,
    isLoading,
    setItems,
    upsertItem,
    markDeleted,
    setLoading,
    lock,
  } = useNopassStore();

  const [decrypted, setDecrypted] = useState<Map<string, VaultItemPlaintext>>(new Map());
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [modal, setModal] = useState<
    | { mode: "create"; itemType: VaultItemType }
    | { mode: "edit"; entry: DecryptedEntry }
    | null
  >(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Redirect to login if vault is locked
  useEffect(() => {
    if (!isUnlocked()) {
      router.replace("/login");
    }
  }, [isUnlocked, router]);

  // Load items from API on mount
  useEffect(() => {
    if (!isUnlocked() || !sessionToken || !defaultVaultId) return;

    setLoading(true);
    api.vault
      .items(defaultVaultId, sessionToken)
      .then((apiItems) => {
        // Map camelCase API response to store shape
        setItems(apiItems);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load vault"))
      .finally(() => setLoading(false));
  }, [isUnlocked, sessionToken, defaultVaultId, setItems, setLoading]);

  // Decrypt all items whenever the encrypted list changes
  useEffect(() => {
    if (!vaultEncKey || !vaultMacKey) return;

    const enc = vaultEncKey;
    const mac = vaultMacKey;

    const active = items.filter((i) => i.deletedAt === null);

    Promise.all(
      active.map(async (item) => {
        try {
          const plain = await decryptItem(item, enc, mac);
          return [item.id, plain] as const;
        } catch {
          return null;
        }
      }),
    ).then((results) => {
      const map = new Map<string, VaultItemPlaintext>();
      for (const r of results) {
        if (r) map.set(r[0], r[1]);
      }
      setDecrypted(map);
    });
  }, [items, vaultEncKey, vaultMacKey]);

  const handleSave = useCallback(
    async (plaintext: VaultItemPlaintext) => {
      if (!sessionToken || !defaultVaultId || !vaultEncKey || !vaultMacKey) return;
      setSaving(true);
      setError(null);

      try {
        const encrypted = await encryptItem(plaintext, vaultEncKey, vaultMacKey);

        if (modal?.mode === "create") {
          const created = await api.vault.create(
            defaultVaultId,
            {
              itemType: plaintext.type,
              blob: encrypted.blob,
              blobIv: encrypted.blobIv,
              blobMac: encrypted.blobMac,
            },
            sessionToken,
          );
          upsertItem(created);
        } else if (modal?.mode === "edit") {
          await api.vault.update(
            defaultVaultId,
            modal.entry.item.id,
            {
              blob: encrypted.blob,
              blobIv: encrypted.blobIv,
              blobMac: encrypted.blobMac,
              version: modal.entry.item.version,
            },
            sessionToken,
          );
          upsertItem({
            ...modal.entry.item,
            blob: encrypted.blob,
            blobIv: encrypted.blobIv,
            blobMac: encrypted.blobMac,
            version: modal.entry.item.version + 1,
          });
        }

        setModal(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Save failed");
      } finally {
        setSaving(false);
      }
    },
    [modal, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem],
  );

  const handleDelete = useCallback(
    async (item: EncryptedVaultItem) => {
      if (!sessionToken || !defaultVaultId) return;
      if (!confirm("Delete this item? This cannot be undone.")) return;

      try {
        await api.vault.delete(defaultVaultId, item.id, sessionToken);
        markDeleted(item.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Delete failed");
      }
    },
    [sessionToken, defaultVaultId, markDeleted],
  );

  const handleLock = useCallback(() => {
    lock();
    router.replace("/login");
  }, [lock, router]);

  const activeItems = items.filter((i) => i.deletedAt === null);
  const filteredItems = activeItems.filter((item) => {
    if (filter !== "all" && item.itemType !== filter) return false;
    if (search) {
      const plain = decrypted.get(item.id);
      if (!plain) return false;
      return plain.name.toLowerCase().includes(search.toLowerCase());
    }
    return true;
  });

  if (!isUnlocked()) return null;

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <aside className="w-56 flex flex-col border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shrink-0">
        <div className="px-4 py-5 border-b border-gray-200 dark:border-gray-700">
          <h1 className="text-base font-semibold text-gray-900 dark:text-white">nopass</h1>
        </div>

        <nav className="flex-1 overflow-y-auto py-2">
          {(["all", "login", "note", "card", "identity"] as Filter[]).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
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
        </nav>

        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <button
            onClick={handleLock}
            className="w-full text-left px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            Lock vault
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
          <input
            type="search"
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 max-w-sm px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />

          <div className="flex items-center gap-2 ml-auto">
            {(["login", "note", "card", "identity"] as VaultItemType[]).map((t) => (
              <button
                key={t}
                onClick={() => setModal({ mode: "create", itemType: t })}
                className="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium"
              >
                + {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </header>

        {/* Item list */}
        <main className="flex-1 overflow-y-auto p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              {error}
            </div>
          )}

          {isLoading ? (
            <div className="flex items-center justify-center h-32 text-gray-400 text-sm">
              Loading…
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-gray-400">
              <p className="text-sm">
                {search ? "No matching items" : "No items yet — add one above"}
              </p>
            </div>
          ) : (
            <div className="max-w-2xl space-y-1">
              {filteredItems.map((item) => {
                const plain = decrypted.get(item.id);
                return (
                  <div key={item.id} className="flex items-center group">
                    <div className="flex-1 min-w-0">
                      <DecryptedVaultItemCard
                        item={item}
                        decryptedName={plain?.name ?? "…"}
                        onClick={() => {
                          if (plain) setModal({ mode: "edit", entry: { item, plaintext: plain } });
                        }}
                      />
                    </div>
                    <button
                      onClick={() => handleDelete(item)}
                      className="ml-2 px-2 py-1 text-xs text-red-500 hover:text-red-700 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      Delete
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </main>
      </div>

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
              {modal.mode === "create"
                ? `New ${modal.itemType}`
                : `Edit ${modal.entry.plaintext.type}`}
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
