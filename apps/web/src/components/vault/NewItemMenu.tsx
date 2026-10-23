"use client";

import { useEffect, useRef } from "react";
import { Plus } from "lucide-react";
import type { VaultItemType } from "@nopass/types";
import { Button, cx } from "@nopass/ui";

const NEW_OPTIONS: Array<{ label: string; type: VaultItemType }> = [
  { label: "Login", type: "login" },
  { label: "Note", type: "note" },
  { label: "Card", type: "card" },
  { label: "Identity", type: "identity" },
  { label: "SSH Key", type: "ssh_key" },
];

/** "New" button with its item-type menu. `n` opens it from the list page. */
export function NewItemMenu({
  open,
  onOpenChange,
  onPick,
  primary,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onPick: (type: VaultItemType) => void;
  primary: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onOpenChange(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onOpenChange(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    ref.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onOpenChange]);

  return (
    <div className="relative" ref={ref}>
      <Button
        data-testid="new-item-btn"
        variant={primary ? "primary" : "secondary"}
        size="sm"
        aria-haspopup="menu"
        aria-expanded={open}
        icon={<Plus aria-hidden className="size-4" />}
        shortcut="N"
        onClick={() => onOpenChange(!open)}
      >
        New
      </Button>
      {open && (
        <div
          data-testid="type-picker"
          role="menu"
          aria-label="New item type"
          className="absolute right-0 top-full z-30 mt-1 min-w-40 rounded-lg border border-divider bg-surface p-1 shadow-overlay animate-overlay-in"
        >
          {NEW_OPTIONS.map((o) => (
            <button
              key={o.type}
              type="button"
              role="menuitem"
              data-testid={`type-${o.label.toLowerCase()}`}
              onClick={() => {
                onOpenChange(false);
                onPick(o.type);
              }}
              onKeyDown={(e) => {
                const items = Array.from(
                  e.currentTarget.parentElement?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [],
                );
                const idx = items.indexOf(e.currentTarget);
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  items[(idx + 1) % items.length]?.focus();
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  items[(idx - 1 + items.length) % items.length]?.focus();
                }
              }}
              className={cx(
                "flex h-8 w-full items-center rounded px-2.5 text-left text-ui text-fg",
                "transition-colors duration-[120ms] hover:bg-surface-hover",
              )}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
