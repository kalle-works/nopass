"use client";

import { useEffect } from "react";
import type { LoginItem } from "@nopass/types";
import { useVault } from "./vault-context";
import { primaryCopy } from "./vault-model";

function isTextInput(el: HTMLElement | null): boolean {
  if (!el) return false;
  return el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable;
}

/**
 * Keyboard shortcuts of the item list: `/` search, `n` new, `e` edit,
 * `c` / `u` copy, arrows to move, Enter to open, Escape to back out.
 * Listens only while the list page is mounted and no dialog or palette is open.
 */
export function useListShortcuts({
  pickerOpen,
  setPickerOpen,
}: {
  pickerOpen: boolean;
  setPickerOpen: (open: boolean) => void;
}) {
  const v = useVault();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (v.paletteOpen || document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      const target = e.target as HTMLElement | null;
      const inInput = isTextInput(target);
      const inSearch = v.isSearchInput(target);
      const editorOpen = v.creating !== null || v.editing;

      if (e.key === "Escape") {
        if (pickerOpen) return; // the menu closes itself
        if (editorOpen) {
          v.cancelEdit();
        } else if (inSearch) {
          (target as HTMLInputElement).blur();
        } else if (v.selectedId || v.detailOpen) {
          v.deselect();
        }
        return;
      }

      if (e.metaKey || e.ctrlKey || e.altKey) return;

      const inList = Boolean(target?.closest('[aria-label="Items"]')) || target === document.body;

      if ((e.key === "ArrowDown" || e.key === "ArrowUp") && (inSearch || (!inInput && inList)) && !editorOpen) {
        if (v.filteredItems.length === 0) return;
        e.preventDefault();
        const current = v.filteredItems.findIndex((i) => i.id === v.selectedId);
        const delta = e.key === "ArrowDown" ? 1 : -1;
        const next = current === -1 ? (delta === 1 ? 0 : v.filteredItems.length - 1) : current + delta;
        const item = v.filteredItems[Math.min(Math.max(next, 0), v.filteredItems.length - 1)];
        if (item) v.moveCursor(item.id);
        return;
      }

      if (e.key === "Enter" && (inSearch || target === document.body) && v.selectedId && !editorOpen) {
        e.preventDefault();
        v.openItem(v.selectedId);
        return;
      }

      if (inInput) return;

      switch (e.key) {
        case "/":
          e.preventDefault();
          v.focusSearch();
          break;
        case "n":
          if (!pickerOpen) {
            e.preventDefault();
            setPickerOpen(true);
          }
          break;
        case "e":
          if (v.selectedEntry && !editorOpen) {
            e.preventDefault();
            v.startEdit();
          }
          break;
        case "c": {
          const quick = v.selectedEntry && !editorOpen ? primaryCopy(v.selectedEntry.plaintext) : null;
          if (quick) {
            e.preventDefault();
            void v.copyWithStatus(quick.value, quick.noun);
          }
          break;
        }
        case "u": {
          const plain = v.selectedEntry?.plaintext;
          if (plain?.type === "login" && !editorOpen) {
            const username = (plain as LoginItem).username;
            if (username) {
              e.preventDefault();
              void v.copyWithStatus(username, "Username");
            }
          }
          break;
        }
      }
    }

    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });
}
