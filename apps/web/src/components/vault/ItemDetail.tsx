"use client";

import { useState } from "react";
import { ChevronLeft, Star, X } from "lucide-react";
import { Badge, Button, Dialog, IconButton, cx, inputClass } from "@nopass/ui";
import type { LoginItem } from "@nopass/types";
import { ItemFields } from "./ItemFields";
import { ItemIcon } from "./ItemIcon";
import { useVault, type DecryptedEntry } from "./vault-context";
import { TYPE_SINGULAR } from "./vault-model";

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

export function ItemDetail({ entry }: { entry: DecryptedEntry }) {
  const v = useVault();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const { item, plaintext } = entry;
  const favorite = v.favorites.has(item.id);
  const login = plaintext.type === "login" ? (plaintext as LoginItem) : null;
  const reusedElsewhere = login?.password ? Math.max(0, (v.passwordUses.get(login.password) ?? 1) - 1) : 0;
  const breachCount = v.breaches.get(item.id) ?? 0;
  const vaultOptions = v.vaults.map((vault) => ({ id: vault.id, name: v.vaultNames.get(vault.id) ?? "…" }));

  return (
    <>
      <header className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-divider px-4 py-3">
        <IconButton label="Back to list" onClick={v.closeDetail} className="xl:hidden">
          <ChevronLeft aria-hidden className="size-4" />
        </IconButton>
        <ItemIcon type={item.itemType} name={plaintext.name} size={32} />
        <div className="min-w-0 flex-1 basis-40">
          <h2 className="truncate text-h2 font-semibold text-fg">{plaintext.name}</h2>
          <p className="flex items-center gap-2 text-meta text-muted">
            {TYPE_SINGULAR[item.itemType]}
            {breachCount > 0 && <Badge tone="danger">Breached</Badge>}
          </p>
        </div>
        <div className="flex items-center gap-1">
          <IconButton
            label={favorite ? "Remove from favorites" : "Add to favorites"}
            aria-pressed={favorite}
            onClick={() => v.toggleFavorite(item.id)}
            className={favorite ? "text-warning" : undefined}
          >
            <Star aria-hidden className="size-4" fill={favorite ? "currentColor" : "none"} />
          </IconButton>
          <Button size="sm" shortcut="E" onClick={v.startEdit}>
            Edit
          </Button>
          <Button size="sm" onClick={() => v.setShareOpen(true)}>
            Share
          </Button>
          <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(true)}>
            Delete
          </Button>
          <IconButton label="Close" onClick={v.deselect} className="hidden xl:inline-flex">
            <X aria-hidden className="size-4" />
          </IconButton>
        </div>
      </header>

      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-4">
        <ItemFields
          plaintext={plaintext}
          copy={v.copy}
          reusedElsewhere={reusedElsewhere}
          breachCount={breachCount}
        />

        {plaintext.tags && plaintext.tags.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <span className="text-meta font-medium text-fg">Tags</span>
            <div className="flex flex-wrap gap-1.5">
              {plaintext.tags.map((tag) => (
                <button
                  key={tag}
                  type="button"
                  onClick={() => v.setTagFilter(tag)}
                  title={`Show all items tagged ${tag}`}
                  className="rounded-sm bg-surface-active px-2 py-0.5 text-mono-sm text-muted transition-colors duration-[120ms] hover:bg-surface-selected hover:text-fg"
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        )}

        {vaultOptions.length > 1 && (
          <div className="flex flex-col gap-1.5">
            <label htmlFor="item-vault" className="text-meta font-medium text-fg">
              Vault
            </label>
            <select
              id="item-vault"
              value={item.vaultId}
              onChange={(e) => {
                if (e.target.value !== item.vaultId) v.moveItem(item, e.target.value);
              }}
              className={cx(inputClass, "h-9")}
            >
              {vaultOptions.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          </div>
        )}

        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-meta text-muted">
          <dt>Created</dt>
          <dd>{formatDate(item.createdAt)}</dd>
          <dt>Updated</dt>
          <dd>{formatDate(item.updatedAt)}</dd>
          <dt>ID</dt>
          <dd className="font-mono text-mono-sm">
            {item.id.slice(0, 8)}… · v{item.version}
          </dd>
        </dl>
      </div>

      <Dialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title={`Delete “${plaintext.name}”?`}
        description="This can't be undone."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                setConfirmDelete(false);
                v.deleteItem(item);
              }}
            >
              Delete item
            </Button>
          </>
        }
      />
    </>
  );
}
