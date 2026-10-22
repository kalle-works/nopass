/**
 * Pure helpers for the vault list: search, filtering, subtitles and the
 * "main secret" of each item type. No React, no crypto, no network.
 */
import type {
  CardItem,
  EncryptedVaultItem,
  IdentityItem,
  LoginItem,
  NoteItem,
  SshKeyItem,
  VaultItemPlaintext,
  VaultItemType,
} from "@nopass/types";

export type Filter = "all" | "favorites" | VaultItemType;

export const TYPE_ORDER: VaultItemType[] = ["login", "note", "card", "identity", "ssh_key"];

export const TYPE_PLURAL: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
  ssh_key: "SSH keys",
};

export const TYPE_SINGULAR: Record<VaultItemType, string> = {
  login: "Login",
  note: "Note",
  card: "Card",
  identity: "Identity",
  ssh_key: "SSH key",
};

/** Host of a URL, tolerating a missing scheme ("github.com/login"). */
export function hostOf(url: string | undefined): string | null {
  if (!url) return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`).hostname || null;
  } catch {
    return null;
  }
}

function notesOf(p: VaultItemPlaintext): string {
  switch (p.type) {
    case "login":
      return (p as LoginItem).notes ?? "";
    case "note":
      return (p as NoteItem).content ?? "";
    case "card":
      return (p as CardItem).notes ?? "";
    case "ssh_key":
      return (p as SshKeyItem).notes ?? "";
    default:
      return "";
  }
}

/** Fields the search box looks at: title, username, host, tags and notes. */
export function searchableText(p: VaultItemPlaintext): string[] {
  const fields = [p.name, ...(p.tags ?? []), notesOf(p)];
  if (p.type === "login") {
    const login = p as LoginItem;
    fields.push(login.username ?? "");
    for (const url of login.urls ?? []) {
      fields.push(hostOf(url) ?? url);
    }
  }
  return fields;
}

/** Every whitespace-separated term must appear in at least one searchable field. */
export function matchesQuery(p: VaultItemPlaintext, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const haystack = searchableText(p).map((f) => f.toLowerCase());
  return terms.every((term) => haystack.some((field) => field.includes(term)));
}

export interface FilterState {
  vaultId: string | null;
  filter: Filter;
  tag: string | null;
  query: string;
  /** When set, only these item ids are shown (health "Review"). */
  reviewIds: ReadonlySet<string> | null;
  favorites: ReadonlySet<string>;
}

export function filterItems(
  items: EncryptedVaultItem[],
  plaintexts: ReadonlyMap<string, VaultItemPlaintext>,
  state: FilterState,
): EncryptedVaultItem[] {
  return items.filter((item) => {
    if (state.vaultId && item.vaultId !== state.vaultId) return false;
    if (state.filter === "favorites" && !state.favorites.has(item.id)) return false;
    if (state.filter !== "all" && state.filter !== "favorites" && item.itemType !== state.filter) return false;
    if (state.reviewIds && !state.reviewIds.has(item.id)) return false;
    const plain = plaintexts.get(item.id);
    if (state.tag) {
      const wanted = state.tag.toLowerCase();
      if (!plain?.tags?.some((t) => t.toLowerCase() === wanted)) return false;
    }
    if (state.query.trim()) {
      if (!plain) return false;
      return matchesQuery(plain, state.query);
    }
    return true;
  });
}

/** Second line of an item row: username, host or key prefix. */
export function itemSubtitle(p: VaultItemPlaintext): string {
  switch (p.type) {
    case "login": {
      const login = p as LoginItem;
      return login.username || hostOf(login.urls?.[0]) || "";
    }
    case "card": {
      const digits = ((p as CardItem).number ?? "").replace(/\D/g, "");
      return digits ? `•••• ${digits.slice(-4)}` : "";
    }
    case "note":
      return ((p as NoteItem).content ?? "").split("\n")[0]?.slice(0, 60) ?? "";
    case "identity": {
      const identity = p as IdentityItem;
      return identity.email || [identity.firstName, identity.lastName].filter(Boolean).join(" ");
    }
    case "ssh_key": {
      const key = p as SshKeyItem;
      return key.comment || key.publicKey?.split(/\s+/).slice(0, 1).join("") || "";
    }
    default:
      return "";
  }
}

export interface QuickCopy {
  /** Accessible name of the row button, e.g. "Copy password". */
  label: string;
  /** Noun used in the confirmation, e.g. "Password". */
  noun: string;
  value: string;
}

/** The one secret that `c` and the row's quick action copy for each type. */
export function primaryCopy(p: VaultItemPlaintext): QuickCopy | null {
  switch (p.type) {
    case "login": {
      const login = p as LoginItem;
      if (login.password) return { label: "Copy password", noun: "Password", value: login.password };
      if (login.username) return { label: "Copy username", noun: "Username", value: login.username };
      return null;
    }
    case "card": {
      const number = (p as CardItem).number;
      return number ? { label: "Copy card number", noun: "Card number", value: number } : null;
    }
    case "ssh_key": {
      const key = (p as SshKeyItem).publicKey;
      return key ? { label: "Copy public key", noun: "Public key", value: key } : null;
    }
    case "identity": {
      const email = (p as IdentityItem).email;
      return email ? { label: "Copy email", noun: "Email", value: email } : null;
    }
    default:
      return null;
  }
}

/** Number of items sharing each non-empty login password. */
export function passwordUseCounts(plaintexts: Iterable<VaultItemPlaintext>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const p of plaintexts) {
    if (p.type !== "login") continue;
    const pw = (p as LoginItem).password;
    if (pw) counts.set(pw, (counts.get(pw) ?? 0) + 1);
  }
  return counts;
}

export type SortKey = "name" | "updated" | "created";

export const SORT_LABELS: Record<SortKey, string> = {
  name: "Name",
  updated: "Recently updated",
  created: "Recently added",
};

export function sortItems(
  items: EncryptedVaultItem[],
  plaintexts: ReadonlyMap<string, VaultItemPlaintext>,
  sort: SortKey,
): EncryptedVaultItem[] {
  const copy = [...items];
  if (sort === "name") {
    const nameOf = (i: EncryptedVaultItem) => plaintexts.get(i.id)?.name ?? "";
    return copy.sort((a, b) => nameOf(a).localeCompare(nameOf(b), undefined, { sensitivity: "base" }));
  }
  const key = sort === "updated" ? "updatedAt" : "createdAt";
  return copy.sort((a, b) => b[key].localeCompare(a[key]));
}
