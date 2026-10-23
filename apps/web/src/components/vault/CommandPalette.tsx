"use client";

import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { useRouter } from "next/navigation";
import { Search } from "lucide-react";
import type { LoginItem, VaultItemType } from "@nopass/types";
import { Kbd, computeTotp, cx } from "@nopass/ui";
import { ItemIcon } from "./ItemIcon";
import { useVault } from "./vault-context";
import { safeHttpUrl } from "@/lib/safe-url";
import { filterItems, primaryCopy, sortItems, TYPE_SINGULAR, type Filter } from "./vault-model";

interface Command {
  id: string;
  group: "Items" | "Actions" | "Navigation";
  label: string;
  detail?: string | undefined;
  leading?: ComponentType | undefined;
  /** Item commands copy their main secret on Cmd/Ctrl+C. */
  copyValue?: { noun: string; value: string } | undefined;
  run: () => void | Promise<void>;
}

const NAV: Array<{ label: string; href?: string; filter?: Filter }> = [
  { label: "All items", filter: "all" },
  { label: "Favorites", filter: "favorites" },
  { label: "Health", href: "/vault/health" },
  { label: "Shared links", href: "/vault/shares" },
  { label: "Activity", href: "/vault/activity" },
  { label: "Teams", href: "/vault/teams" },
  { label: "Settings", href: "/vault/settings" },
  { label: "Devices", href: "/vault/devices" },
  { label: "Import", href: "/vault/import" },
  { label: "Billing", href: "/vault/billing" },
  { label: "Recovery", href: "/vault/recovery" },
];

const NEW_TYPES: VaultItemType[] = ["login", "note", "card", "identity", "ssh_key"];
const MAX_ITEMS = 6;

export function CommandPalette() {
  const { paletteOpen } = useVault();
  // Mounting only while open gives every opening a fresh query and cursor
  return paletteOpen ? <PaletteBody /> : null;
}

function PaletteBody() {
  const v = useVault();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { setPaletteOpen } = v;

  const commands = useMemo<Command[]>(() => {
    const q = query.trim().toLowerCase();
    const out: Command[] = [];

    const matched = sortItems(
      filterItems(v.items, v.decrypted, {
        vaultId: null,
        filter: "all",
        tag: null,
        query,
        reviewIds: null,
        favorites: v.favorites,
      }),
      v.decrypted,
      q ? "name" : "updated",
    ).slice(0, MAX_ITEMS);
    for (const item of matched) {
      const plain = v.decrypted.get(item.id);
      if (!plain) continue;
      const quick = primaryCopy(plain);
      out.push({
        id: `item-${item.id}`,
        group: "Items",
        label: plain.name,
        detail: TYPE_SINGULAR[item.itemType],
        leading: () => <ItemIcon type={item.itemType} name={plain.name} />,
        copyValue: quick ? { noun: quick.noun, value: quick.value } : undefined,
        run: () => v.openItem(item.id),
      });
    }

    const actions: Command[] = [];
    const sel = v.selectedEntry;
    if (sel) {
      const plain = sel.plaintext;
      const quick = primaryCopy(plain);
      if (quick) {
        actions.push({ id: "act-copy", group: "Actions", label: quick.label, detail: plain.name, run: () => v.copyWithStatus(quick.value, quick.noun) });
      }
      if (plain.type === "login") {
        const login = plain as LoginItem;
        if (login.username && quick?.noun !== "Username") {
          actions.push({ id: "act-user", group: "Actions", label: "Copy username", detail: plain.name, run: () => v.copyWithStatus(login.username, "Username") });
        }
        if (login.totp) {
          actions.push({
            id: "act-totp",
            group: "Actions",
            label: "Copy one-time code",
            detail: plain.name,
            run: async () => {
              const r = await computeTotp(login.totp!);
              if (r) await v.copyWithStatus(r.code, "One-time code");
            },
          });
        }
        const url = safeHttpUrl(login.urls?.[0]);
        if (url) {
          actions.push({ id: "act-url", group: "Actions", label: "Open URL", detail: url, run: () => void window.open(url, "_blank", "noopener,noreferrer") });
        }
      }
      actions.push({ id: "act-share", group: "Actions", label: "Share", detail: plain.name, run: () => v.setShareOpen(true) });
      actions.push({ id: "act-edit", group: "Actions", label: "Edit", detail: plain.name, run: () => { v.openItem(sel.item.id); v.startEdit(); } });
    }
    for (const t of NEW_TYPES) {
      actions.push({ id: `new-${t}`, group: "Actions", label: `New ${TYPE_SINGULAR[t].toLowerCase()}`, run: () => v.startCreate(t) });
    }
    actions.push({ id: "act-lock", group: "Actions", label: "Lock vault", detail: "⌘L", run: v.lockVault });

    const nav: Command[] = NAV.map((n) => ({
      id: `nav-${n.label}`,
      group: "Navigation" as const,
      label: n.label,
      run: () => (n.filter ? v.applyFilter(n.filter) : router.push(n.href!)),
    }));

    const textMatch = (c: Command) => !q || c.label.toLowerCase().includes(q) || (c.detail ?? "").toLowerCase().includes(q);
    return [...out, ...actions.filter(textMatch), ...nav.filter(textMatch)];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, v.items, v.decrypted, v.favorites, v.selectedEntry]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => previous?.focus?.();
  }, []);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  function close() {
    setPaletteOpen(false);
  }

  function run(c: Command | undefined) {
    if (!c) return;
    close();
    void c.run();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (commands.length === 0 ? 0 : (i + 1) % commands.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (commands.length === 0 ? 0 : (i - 1 + commands.length) % commands.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      run(commands[active]);
    } else if (e.key === "Tab") {
      e.preventDefault();
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "c") {
      const input = inputRef.current;
      const hasTextSelection = input !== null && input.selectionStart !== input.selectionEnd;
      const target = commands[active]?.copyValue;
      if (!hasTextSelection && target) {
        e.preventDefault();
        close();
        void v.copyWithStatus(target.value, target.noun);
      }
    }
  }

  const groups: Array<Command["group"]> = ["Items", "Actions", "Navigation"];

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-overlay p-4 pt-[12vh] animate-fade-in"
      onMouseDown={close}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
        className="flex max-h-[70vh] w-full max-w-[560px] flex-col overflow-hidden rounded-lg border border-divider bg-surface shadow-overlay animate-overlay-in"
      >
        <div className="flex items-center gap-2 border-b border-divider px-4">
          <Search aria-hidden className="size-4 shrink-0 text-icon" />
          <input
            ref={inputRef}
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={commands[active] ? `palette-opt-${commands[active]!.id}` : undefined}
            aria-label="Search items, actions and pages"
            placeholder="Search items, actions and pages"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            className="h-12 min-w-0 flex-1 bg-transparent text-body text-fg placeholder:text-faint focus:outline-none"
          />
        </div>

        <div ref={listRef} id="palette-list" role="listbox" className="min-h-0 flex-1 overflow-y-auto p-2">
          {commands.length === 0 && <p className="px-3 py-6 text-ui text-muted">No results for “{query}”.</p>}
          {groups.map((g) => {
            const rows = commands.map((c, index) => ({ c, index })).filter(({ c }) => c.group === g);
            if (rows.length === 0) return null;
            return (
              <div key={g} role="group" aria-label={g}>
                <p className="px-3 pb-1 pt-2 text-meta font-medium text-muted">{g}</p>
                {rows.map(({ c, index }) => {
                  const Leading = c.leading;
                  return (
                    <div
                      key={c.id}
                      id={`palette-opt-${c.id}`}
                      role="option"
                      aria-selected={index === active}
                      data-index={index}
                      onMouseMove={() => setActive(index)}
                      onClick={() => run(c)}
                      className={cx(
                        "flex h-9 cursor-pointer items-center gap-2.5 rounded px-3 text-ui",
                        index === active ? "bg-accent-subtle text-fg" : "text-fg",
                      )}
                    >
                      {Leading && <Leading />}
                      <span className="min-w-0 truncate font-medium">{c.label}</span>
                      {c.detail && <span className="ml-auto truncate pl-3 text-meta text-muted">{c.detail}</span>}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-4 border-t border-divider px-4 py-2 text-meta text-muted">
          <span className="flex items-center gap-1.5"><Kbd>↵</Kbd> Open</span>
          <span className="flex items-center gap-1.5"><Kbd>⌘C</Kbd> Copy</span>
          <span className="flex items-center gap-1.5"><Kbd>esc</Kbd> Close</span>
        </div>
      </div>
    </div>
  );
}
