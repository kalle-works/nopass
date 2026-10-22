"use client";

import { ChevronLeft } from "lucide-react";
import { IconButton, ItemEditor, cx } from "@nopass/ui";
import type { VaultItemType } from "@nopass/types";
import { ItemDetail } from "./ItemDetail";
import { useVault } from "./vault-context";
import { TYPE_SINGULAR } from "./vault-model";

function EmptyDetail() {
  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <p className="max-w-xs text-center text-ui text-muted">
        Select an item to see its details, or press <kbd className="font-mono">N</kbd> to create one.
      </p>
    </div>
  );
}

/** Right-hand pane: read view, inline editor, or the new-item form. */
export function DetailPane({ className }: { className?: string }) {
  const v = useVault();
  const { selectedEntry, creating, editing } = v;

  let body;
  if (creating || (editing && selectedEntry)) {
    const itemType: VaultItemType = creating ?? (selectedEntry!.plaintext.type as VaultItemType);
    const title = creating
      ? `New ${TYPE_SINGULAR[itemType].toLowerCase()}`
      : `Edit ${selectedEntry!.plaintext.name}`;
    body = (
      <>
        <header className="flex items-center gap-3 border-b border-divider px-4 py-3">
          <IconButton label="Back to list" onClick={v.closeDetail} className="xl:hidden">
            <ChevronLeft aria-hidden className="size-4" />
          </IconButton>
          <h2 className="min-w-0 flex-1 truncate text-h2 font-semibold text-fg">{title}</h2>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 pt-4">
          <div className="mx-auto max-w-xl">
            <ItemEditor
              key={creating ? `new-${creating}` : selectedEntry!.item.id}
              itemType={itemType}
              initial={creating ? undefined : selectedEntry!.plaintext}
              onSave={v.saveItem}
              onCancel={v.cancelEdit}
              saving={v.saving}
            />
          </div>
        </div>
      </>
    );
  } else if (selectedEntry) {
    body = <ItemDetail entry={selectedEntry} />;
  } else {
    body = (
      <>
        <header className="flex items-center gap-3 border-b border-divider px-4 py-3 xl:hidden">
          <IconButton label="Back to list" onClick={v.closeDetail}>
            <ChevronLeft aria-hidden className="size-4" />
          </IconButton>
        </header>
        <EmptyDetail />
      </>
    );
  }

  return (
    <aside aria-label="Item details" className={cx("min-h-0 min-w-0 flex-1 flex-col bg-bg xl:min-w-[480px]", className)}>
      {body}
    </aside>
  );
}
