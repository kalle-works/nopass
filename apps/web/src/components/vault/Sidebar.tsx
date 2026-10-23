"use client";

import { useEffect, useRef, useState, type ComponentType, type ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  ChevronsUpDown,
  Check,
  HeartPulse,
  Layers,
  Link2,
  Monitor,
  Plus,
  Receipt,
  LifeBuoy,
  Settings,
  Star,
  Upload,
  Users,
  type LucideProps,
} from "lucide-react";
import { Button, Dialog, Field, Kbd, cx, useThemePreference, type ThemePreference } from "@nopass/ui";
import { useVault } from "./vault-context";
import { TYPE_ICON } from "./ItemIcon";
import { TYPE_ORDER, TYPE_PLURAL, type Filter } from "./vault-model";

type IconType = ComponentType<LucideProps>;

const ROW =
  "flex h-8 w-full items-center gap-2.5 rounded px-2.5 text-left text-ui transition-colors duration-[120ms]";

function rowClass(active: boolean) {
  return cx(ROW, active ? "bg-surface-active font-medium text-fg" : "text-muted hover:bg-surface-hover hover:text-fg");
}

function RowContent({ icon: Icon, label, count }: { icon?: IconType | undefined; label: ReactNode; count?: number | undefined }) {
  return (
    <>
      {Icon && <Icon aria-hidden className="size-4 shrink-0 text-icon" strokeWidth={1.5} />}
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {count !== undefined && <span className="shrink-0 text-meta tabular-nums text-muted">{count}</span>}
    </>
  );
}

function FilterRow({
  icon,
  label,
  count,
  active,
  onClick,
}: {
  icon?: IconType | undefined;
  label: string;
  count?: number | undefined;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" onClick={onClick} aria-current={active ? "true" : undefined} className={rowClass(active)}>
      <RowContent icon={icon} label={label} count={count} />
    </button>
  );
}

function RouteRow({ href, icon, label }: { href: string; icon: IconType; label: string }) {
  const pathname = usePathname();
  const active = pathname === href;
  return (
    <Link href={href} aria-current={active ? "page" : undefined} className={rowClass(active)}>
      <RowContent icon={icon} label={label} />
    </Link>
  );
}

function GroupLabel({ children }: { children: ReactNode }) {
  return <p className="px-2.5 pb-1 pt-3 text-meta font-medium text-muted">{children}</p>;
}

function VaultSwitcher() {
  const { vaults, vaultNames, activeVaultId, setActiveVaultId, items, email, createVault } = useVault();
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const activeName = activeVaultId ? (vaultNames.get(activeVaultId) ?? "…") : "All vaults";
  const countFor = (vaultId: string) => items.filter((i) => i.vaultId === vaultId).length;

  function choose(id: string | null) {
    setActiveVaultId(id);
    setOpen(false);
  }

  async function submitNewVault() {
    const trimmed = name.trim();
    if (!trimmed) return;
    setCreating(false);
    setName("");
    await createVault(trimmed);
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex w-full items-center gap-2 rounded px-2.5 py-2 text-left transition-colors duration-[120ms] hover:bg-surface-hover"
      >
        <span className="min-w-0 flex-1">
          <span className="block truncate text-ui font-semibold text-fg">{activeName}</span>
          <span className="block truncate text-meta text-muted" title={email ?? ""}>
            {email}
          </span>
        </span>
        <ChevronsUpDown aria-hidden className="size-4 shrink-0 text-icon" strokeWidth={1.5} />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Vaults"
          className="absolute inset-x-0 top-full z-30 mt-1 rounded-lg border border-divider bg-surface p-1 shadow-overlay animate-overlay-in"
        >
          <button role="menuitemradio" aria-checked={activeVaultId === null} onClick={() => choose(null)} className={rowClass(false)}>
            <RowContent label="All vaults" count={items.length} />
            {activeVaultId === null && <Check aria-hidden className="size-4 shrink-0 text-icon" />}
          </button>
          {vaults.map((v) => (
            <button
              key={v.id}
              role="menuitemradio"
              aria-checked={activeVaultId === v.id}
              onClick={() => choose(activeVaultId === v.id ? null : v.id)}
              className={rowClass(false)}
            >
              <RowContent label={vaultNames.get(v.id) ?? "…"} count={countFor(v.id)} />
              {activeVaultId === v.id && <Check aria-hidden className="size-4 shrink-0 text-icon" />}
            </button>
          ))}
          <div className="my-1 border-t border-divider" />
          <button
            role="menuitem"
            onClick={() => {
              setOpen(false);
              setCreating(true);
            }}
            className={rowClass(false)}
          >
            <RowContent icon={Plus} label="New vault" />
          </button>
        </div>
      )}

      <Dialog
        open={creating}
        onClose={() => {
          setCreating(false);
          setName("");
        }}
        title="New vault"
        description="The name is encrypted on this device before it is stored."
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreating(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={submitNewVault} disabled={!name.trim()}>
              Create vault
            </Button>
          </>
        }
      >
        <Field
          label="Vault name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submitNewVault();
          }}
          placeholder="Work"
          autoFocus
        />
      </Dialog>
    </div>
  );
}

const THEME_OPTIONS: Array<{ value: ThemePreference; label: string }> = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

function ThemeSelector() {
  const [pref, setPref] = useThemePreference();
  return (
    <div role="radiogroup" aria-label="Theme" className="grid grid-cols-3 gap-0.5 rounded bg-surface-hover p-0.5">
      {THEME_OPTIONS.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={pref === o.value}
          onClick={() => setPref(o.value)}
          className={cx(
            "h-7 rounded-sm text-meta transition-colors duration-[120ms]",
            pref === o.value ? "bg-surface font-medium text-fg" : "text-muted hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Sidebar({ className }: { className?: string }) {
  const { items, favorites, activeVaultId, filter, applyFilter, tagFilter, setTagFilter, tagCounts, allTags, review, lockVault } =
    useVault();
  const pathname = usePathname();
  const onList = pathname === "/vault";

  const scoped = activeVaultId ? items.filter((i) => i.vaultId === activeVaultId) : items;
  const counts: Record<Filter, number> = {
    all: scoped.length,
    favorites: scoped.filter((i) => favorites.has(i.id)).length,
    login: 0,
    note: 0,
    card: 0,
    identity: 0,
    ssh_key: 0,
  };
  for (const i of scoped) counts[i.itemType] += 1;

  const filterActive = (f: Filter) => onList && filter === f && !tagFilter && !review;

  return (
    <nav aria-label="Vault" className={cx("flex h-full w-[232px] shrink-0 flex-col border-r border-divider bg-bg-subtle", className)}>
      <div className="border-b border-divider p-2">
        <VaultSwitcher />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        <FilterRow icon={Layers} label="All items" count={counts.all} active={filterActive("all")} onClick={() => applyFilter("all")} />
        <FilterRow icon={Star} label="Favorites" count={counts.favorites} active={filterActive("favorites")} onClick={() => applyFilter("favorites")} />
        <GroupLabel>Types</GroupLabel>
        {TYPE_ORDER.map((t) => (
          <FilterRow
            key={t}
            icon={TYPE_ICON[t]}
            label={TYPE_PLURAL[t]}
            count={counts[t]}
            active={filterActive(t)}
            onClick={() => applyFilter(t)}
          />
        ))}

        {allTags.length > 0 && (
          <>
            <GroupLabel>Tags</GroupLabel>
            {allTags.map((tag) => {
              const active = onList && tagFilter?.toLowerCase() === tag.toLowerCase();
              return (
                <FilterRow
                  key={tag}
                  label={tag}
                  count={tagCounts.get(tag)}
                  active={active}
                  onClick={() => setTagFilter(active ? null : tag)}
                />
              );
            })}
          </>
        )}

        <div className="mt-3 border-t border-divider pt-2">
          <RouteRow href="/vault/health" icon={HeartPulse} label="Health" />
          <RouteRow href="/vault/shares" icon={Link2} label="Shared links" />
          <RouteRow href="/vault/activity" icon={Activity} label="Activity" />
          <RouteRow href="/vault/teams" icon={Users} label="Teams" />
        </div>

        <div className="mt-2 border-t border-divider pt-2">
          <RouteRow href="/vault/settings" icon={Settings} label="Settings" />
          <RouteRow href="/vault/devices" icon={Monitor} label="Devices" />
          <RouteRow href="/vault/import" icon={Upload} label="Import" />
          <RouteRow href="/vault/billing" icon={Receipt} label="Billing" />
          <RouteRow href="/vault/recovery" icon={LifeBuoy} label="Recovery" />
        </div>
      </div>

      <div className="space-y-2 border-t border-divider p-2">
        <ThemeSelector />
        <Button variant="ghost" size="sm" className="w-full justify-between" onClick={lockVault}>
          <span>Lock</span>
          <Kbd>⌘L</Kbd>
        </Button>
      </div>
    </nav>
  );
}
