"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Menu, Search, X } from "lucide-react";
import type { VaultItemType } from "@nopass/types";
import { Button, EmptyState, IconButton, Kbd, cx, inputClass } from "@nopass/ui";
import { ItemRow } from "./ItemRow";
import { NewItemMenu } from "./NewItemMenu";
import { useVault } from "./vault-context";
import { SORT_LABELS, TYPE_PLURAL, type SortKey } from "./vault-model";

function describeScope(v: ReturnType<typeof useVault>): string | null {
  const parts: string[] = [];
  if (v.activeVaultId) parts.push(v.vaultNames.get(v.activeVaultId) ?? "this vault");
  if (v.filter === "favorites") parts.push("Favorites");
  else if (v.filter !== "all") parts.push(TYPE_PLURAL[v.filter as VaultItemType]);
  if (v.tagFilter) parts.push(`tag “${v.tagFilter}”`);
  if (v.review) parts.push(v.review.label);
  return parts.length > 0 ? parts.join(", ") : null;
}

function FilteredEmpty() {
  const v = useVault();
  const query = v.search.trim();
  const scope = describeScope(v);
  const message = `${query ? `No items match “${query}”` : "No items"}${scope ? ` in ${scope}` : ""}.`;
  return (
    <EmptyState
      title={message}
      action={
        <Button variant="secondary" size="sm" onClick={v.clearFilters}>
          Clear filters
        </Button>
      }
    />
  );
}

function VaultEmpty({ onNew }: { onNew: () => void }) {
  const router = useRouter();
  return (
    <EmptyState
      title="Your vault is empty."
      description="Items are encrypted on this device before they sync."
      action={
        <Button variant="primary" onClick={() => router.push("/vault/import")}>
          Import from 1Password
        </Button>
      }
      secondary={
        <Button variant="secondary" onClick={onNew}>
          New item
        </Button>
      }
    />
  );
}

function ListSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading items" className="space-y-1 px-2 py-2">
      {[...Array(6)].map((_, i) => (
        <div key={i} className="flex h-[52px] animate-pulse items-center gap-3 px-3">
          <div className="size-5 rounded bg-surface-active" />
          <div className="flex-1 space-y-2">
            <div className="h-3 w-32 rounded-sm bg-surface-active" />
            <div className="h-2.5 w-48 rounded-sm bg-surface-hover" />
          </div>
        </div>
      ))}
    </div>
  );
}

export function ListPane({
  className,
  pickerOpen,
  setPickerOpen,
}: {
  className?: string;
  pickerOpen: boolean;
  setPickerOpen: (open: boolean) => void;
}) {
  const v = useVault();
  const { registerSearchInput } = v;
  const listRef = useRef<HTMLUListElement>(null);

  // Keep the keyboard cursor in view as arrow keys move it
  useEffect(() => {
    if (!v.selectedId) return;
    listRef.current
      ?.querySelector<HTMLElement>(`[data-item-id="${CSS.escape(v.selectedId)}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [v.selectedId]);

  const hasItems = v.items.length > 0;
  const editorOpen = v.creating !== null || v.editing;

  return (
    <section
      aria-label="Items"
      className={cx("min-h-0 w-full shrink-0 flex-col border-r border-divider bg-bg-subtle xl:w-[360px]", className)}
    >
      <div className="space-y-2 border-b border-divider p-3">
        <div className="flex items-center gap-2">
          <IconButton label="Open navigation" onClick={() => v.setDrawerOpen(true)} className="md:hidden">
            <Menu aria-hidden className="size-4" />
          </IconButton>
          <div className="relative min-w-0 flex-1">
            <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-icon" />
            <input
              ref={registerSearchInput}
              type="search"
              aria-label="Search items"
              placeholder="Search"
              value={v.search}
              onChange={(e) => v.setSearch(e.target.value)}
              className={cx(inputClass, "h-8 pl-8 pr-8")}
            />
            {!v.search && (
              <Kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">/</Kbd>
            )}
          </div>
          <NewItemMenu
            open={pickerOpen}
            onOpenChange={setPickerOpen}
            onPick={v.startCreate}
            primary={hasItems && !editorOpen}
          />
        </div>

        <div className="flex items-center justify-between gap-2">
          <p className="text-meta text-muted" aria-live="polite">
            {v.isLoading ? "Loading…" : `${v.filteredItems.length} ${v.filteredItems.length === 1 ? "item" : "items"}`}
          </p>
          <label className="flex items-center gap-1.5 text-meta text-muted">
            Sort
            <select
              value={v.sort}
              onChange={(e) => v.setSort(e.target.value as SortKey)}
              className="h-7 rounded border border-border bg-surface px-1.5 text-meta text-fg hover:border-border-strong"
            >
              {(Object.keys(SORT_LABELS) as SortKey[]).map((k) => (
                <option key={k} value={k}>
                  {SORT_LABELS[k]}
                </option>
              ))}
            </select>
          </label>
        </div>

        {(v.review || v.tagFilter) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {v.review && (
              <button
                type="button"
                onClick={() => v.setReview(null)}
                className="inline-flex items-center gap-1 rounded-sm bg-surface-active px-2 py-0.5 text-mono-sm text-fg hover:bg-surface-selected"
                aria-label={`Clear review filter: ${v.review.label}`}
              >
                Reviewing: {v.review.label}
                <X aria-hidden className="size-3" />
              </button>
            )}
            {v.tagFilter && (
              <button
                type="button"
                onClick={() => v.setTagFilter(null)}
                className="inline-flex items-center gap-1 rounded-sm bg-surface-active px-2 py-0.5 text-mono-sm text-fg hover:bg-surface-selected"
                aria-label={`Clear tag filter: ${v.tagFilter}`}
              >
                Tag: {v.tagFilter}
                <X aria-hidden className="size-3" />
              </button>
            )}
          </div>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {v.isLoading && !hasItems ? (
          <ListSkeleton />
        ) : v.filteredItems.length === 0 ? (
          hasItems ? (
            <FilteredEmpty />
          ) : (
            <VaultEmpty onNew={() => setPickerOpen(true)} />
          )
        ) : (
          <ul ref={listRef} className="space-y-0.5 py-2">
            {v.filteredItems.map((item) => (
              <ItemRow
                key={item.id}
                item={item}
                plaintext={v.decrypted.get(item.id)}
                selected={v.selectedId === item.id}
                breached={v.breaches.has(item.id)}
                copy={v.copy}
                onOpen={() => v.openItem(item.id)}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
