"use client";

/**
 * Vault session state shared by the shell, the item list/detail page and the
 * settings pages: loading + decrypting items, filters, selection, editing,
 * and every mutation that talks to the API.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  useNopassStore,
  ConflictError,
  OwnKeyMismatchError,
  ensureIdentityPublished,
  openRevisionStore,
  publishV2Only,
} from "@nopass/ui";
import {
  ItemRollbackError,
  LegacyItemRejectedError,
  type MemoryRevisionStore,
  bindingForItem,
  decryptBytes,
  decryptVaultItem,
  encryptBytes,
  encryptVaultItem,
  upgradeLegacyItems,
} from "@nopass/crypto";
import type { EncryptedVaultItem, VaultInfo, VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { api } from "@/lib/api";
import { filterItems, passwordUseCounts, sortItems, type Filter, type SortKey } from "./vault-model";

export interface DecryptedEntry {
  item: EncryptedVaultItem;
  plaintext: VaultItemPlaintext;
}

export interface ReviewFilter {
  label: string;
  ids: ReadonlySet<string>;
}

const IDLE_LOCK_MS = 15 * 60 * 1000;
const NOTICE_MS = 2500;

interface VaultContextValue {
  email: string | null;
  isLoading: boolean;
  items: EncryptedVaultItem[];
  decrypted: ReadonlyMap<string, VaultItemPlaintext>;
  vaults: VaultInfo[];
  vaultNames: ReadonlyMap<string, string>;
  favorites: ReadonlySet<string>;
  passwordUses: ReadonlyMap<string, number>;
  breaches: ReadonlyMap<string, number>;
  setBreaches: (breaches: Map<string, number>) => void;

  // Filters
  activeVaultId: string | null;
  setActiveVaultId: (id: string | null) => void;
  filter: Filter;
  applyFilter: (filter: Filter) => void;
  tagFilter: string | null;
  setTagFilter: (tag: string | null) => void;
  tagCounts: ReadonlyMap<string, number>;
  allTags: string[];
  search: string;
  setSearch: (q: string) => void;
  sort: SortKey;
  setSort: (sort: SortKey) => void;
  review: ReviewFilter | null;
  setReview: (review: ReviewFilter | null) => void;
  clearFilters: () => void;
  hasActiveFilters: boolean;
  filteredItems: EncryptedVaultItem[];
  /** Callback ref for the list's search input. */
  registerSearchInput: (el: HTMLInputElement | null) => void;
  focusSearch: () => void;
  isSearchInput: (el: EventTarget | null) => boolean;

  // Selection and editing
  selectedId: string | null;
  selectedEntry: DecryptedEntry | null;
  detailOpen: boolean;
  openItem: (id: string) => void;
  moveCursor: (id: string) => void;
  closeDetail: () => void;
  deselect: () => void;
  creating: VaultItemType | null;
  editing: boolean;
  startCreate: (type: VaultItemType) => void;
  startEdit: () => void;
  cancelEdit: () => void;
  saving: boolean;
  saveItem: (plaintext: VaultItemPlaintext) => Promise<void>;
  deleteItem: (item: EncryptedVaultItem) => Promise<void>;
  moveItem: (item: EncryptedVaultItem, toVaultId: string) => Promise<void>;
  toggleFavorite: (id: string) => void;
  createVault: (name: string) => Promise<void>;

  // Feedback
  copy: (text: string) => Promise<boolean>;
  copyWithStatus: (text: string, noun: string) => Promise<void>;
  copyStatus: string | null;
  notice: string | null;
  showNotice: (message: string) => void;
  error: string | null;
  setError: (message: string | null) => void;

  // Chrome
  shareOpen: boolean;
  setShareOpen: (open: boolean) => void;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  drawerOpen: boolean;
  setDrawerOpen: (open: boolean) => void;
  lockVault: () => void;
}

const VaultContext = createContext<VaultContextValue | null>(null);

export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used inside <VaultProvider>");
  return ctx;
}

export function VaultProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const {
    isUnlocked,
    sessionToken,
    defaultVaultId,
    vaultEncKey,
    vaultMacKey,
    items: allItems,
    isLoading,
    email,
    setItems,
    upsertItem,
    markDeleted,
    setLoading,
    lock,
    toggleFavorite,
    favorites,
    userId,
    stretchedMasterKey,
    protectedPrivateKey,
    protectedPrivateKeyIv,
  } = useNopassStore();

  const [decrypted, setDecrypted] = useState<Map<string, VaultItemPlaintext>>(new Map());
  // Keyed by the account key (not a server-supplied id) and primed with the
  // account's v2-only marker; null until both are loaded.
  const [revisions, setRevisions] = useState<MemoryRevisionStore | null>(null);
  const legacyUpgradeStarted = useRef(false);
  const [vaults, setVaults] = useState<VaultInfo[]>([]);
  const [vaultNames, setVaultNames] = useState<Map<string, string>>(new Map());
  const [breaches, setBreaches] = useState<Map<string, number>>(new Map());

  const [activeVaultId, setActiveVaultId] = useState<string | null>(null);
  const [filter, setFilterState] = useState<Filter>("all");
  const [tagState, setTagFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("name");
  const [review, setReview] = useState<ReviewFilter | null>(null);
  const searchEl = useRef<HTMLInputElement | null>(null);
  const registerSearchInput = useCallback((el: HTMLInputElement | null) => {
    searchEl.current = el;
  }, []);
  const focusSearch = useCallback(() => searchEl.current?.focus(), []);
  const isSearchInput = useCallback((el: EventTarget | null) => el !== null && el === searchEl.current, []);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [creating, setCreating] = useState<VaultItemType | null>(null);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);

  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [shareFor, setShareFor] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  // The drawer is bound to the view it was opened on, so navigating or
  // picking a filter closes it without an effect.
  const [drawerView, setDrawerView] = useState<string | null>(null);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const noticeTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const unlocked = isUnlocked();

  // --- Session guards -------------------------------------------------------

  useEffect(() => {
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

  useEffect(() => {
    if (!isUnlocked()) return;
    let timer: ReturnType<typeof setTimeout>;

    function resetTimer() {
      clearTimeout(timer);
      timer = setTimeout(() => {
        lock();
        router.replace("/login");
      }, IDLE_LOCK_MS);
    }

    const events = ["mousedown", "mousemove", "keydown", "touchstart", "scroll", "click"] as const;
    for (const ev of events) window.addEventListener(ev, resetTimer, { passive: true });
    resetTimer();

    return () => {
      clearTimeout(timer);
      for (const ev of events) window.removeEventListener(ev, resetTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isUnlocked]);

  useEffect(
    () => () => {
      clearTimeout(copyTimer.current);
      clearTimeout(noticeTimer.current);
    },
    [],
  );

  // Accounts created before identity keys existed publish one on first unlock;
  // every unlock also checks the server still serves our own keys unchanged.
  useEffect(() => {
    if (!sessionToken || !userId || !stretchedMasterKey || !protectedPrivateKey || !protectedPrivateKeyIv) return;
    ensureIdentityPublished(api, sessionToken, {
      userId,
      protectedPrivateKey,
      protectedPrivateKeyIv,
      stretchedMasterKey,
    }).catch((err) => {
      // Anything else (offline, server hiccup) is retried on the next unlock
      if (err instanceof OwnKeyMismatchError) setError(err.message);
    });
  }, [sessionToken, userId, stretchedMasterKey, protectedPrivateKey, protectedPrivateKeyIv]);

  // --- Loading --------------------------------------------------------------

  useEffect(() => {
    if (!isUnlocked() || !sessionToken || !defaultVaultId) return;
    setLoading(true);
    (async () => {
      try {
        const vaultList = await api.vault.list(sessionToken);
        setVaults(vaultList);
        const perVault = await Promise.all(vaultList.map((v) => api.vault.items(v.id, sessionToken)));
        setItems(perVault.flat());
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load vault");
      } finally {
        setLoading(false);
      }
    })();
  }, [isUnlocked, sessionToken, defaultVaultId, setItems, setLoading]);

  // Vault names are encrypted client-side; the registration default carries a
  // plaintext placeholder that fails decryption, so label it "Personal".
  useEffect(() => {
    if (!vaultEncKey || vaults.length === 0) return;
    let cancelled = false;
    (async () => {
      const names = new Map<string, string>();
      for (const v of vaults) {
        try {
          const bytes = await decryptBytes({ blob: v.nameBlob, blobIv: v.nameIv, blobMac: "" }, vaultEncKey);
          names.set(v.id, new TextDecoder().decode(bytes));
        } catch {
          names.set(v.id, v.id === defaultVaultId ? "Personal" : "Vault");
        }
      }
      if (!cancelled) setVaultNames(names);
    })();
    return () => {
      cancelled = true;
    };
  }, [vaults, vaultEncKey, defaultVaultId]);

  const activeItems = useMemo(() => allItems.filter((i) => i.deletedAt === null), [allItems]);

  useEffect(() => {
    if (!vaultEncKey || !vaultMacKey || !revisions) return;
    let cancelled = false;
    const keys = { vaultEncKey, vaultMacKey };
    let rolledBack = 0;
    let failed = 0;

    Promise.all(
      activeItems.map(async (item) => {
        try {
          const { plaintext } = await decryptVaultItem(item, bindingForItem(item), keys, revisions);
          return [item.id, plaintext] as const;
        } catch (err) {
          if (err instanceof ItemRollbackError || err instanceof LegacyItemRejectedError) rolledBack++;
          else failed++;
          return null;
        }
      }),
    ).then((results) => {
      if (cancelled) return;
      const map = new Map<string, VaultItemPlaintext>();
      for (const r of results) {
        if (r) map.set(r[0], r[1]);
      }
      setDecrypted(map);
      if (rolledBack > 0) {
        setError(
          `${rolledBack} item${rolledBack === 1 ? " was" : "s were"} served in an older version than this device has already seen, so ${rolledBack === 1 ? "it is" : "they are"} hidden. The server may be replaying old data.`,
        );
      } else if (failed > 0) {
        setError(
          `${failed} item${failed === 1 ? "" : "s"} could not be decrypted and ${failed === 1 ? "is" : "are"} hidden. ${failed === 1 ? "It" : "They"} may be damaged or tampered with.`,
        );
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeItems, vaultEncKey, vaultMacKey, revisions]);

  useEffect(() => {
    if (!vaultMacKey || !sessionToken) return;
    let cancelled = false;
    openRevisionStore(vaultMacKey, api, sessionToken, { vaultId: defaultVaultId, userId }).then((store) => {
      if (!cancelled) setRevisions(store);
    });
    return () => {
      cancelled = true;
    };
  }, [vaultMacKey, sessionToken, defaultVaultId, userId]);

  // One background pass per unlock re-encrypts items still in the v1 format,
  // trash included, so they gain id/type/revision binding without waiting for
  // an edit. Only when no v1 blob of any kind is left is the account marked
  // v2-only, after which no device accepts a v1 blob again.
  useEffect(() => {
    if (legacyUpgradeStarted.current || isLoading || !sessionToken || !vaultEncKey || !vaultMacKey || !revisions) return;
    if (revisions.v2Only) return;
    legacyUpgradeStarted.current = true;
    void (async () => {
      const { legacyLeft } = await upgradeLegacyItems(
        allItems,
        { vaultEncKey, vaultMacKey },
        revisions,
        async (item, encrypted) => {
          const { version, updatedAt } = await api.vault.update(
            item.vaultId,
            item.id,
            { ...encrypted, version: item.version },
            sessionToken,
          );
          upsertItem({ ...item, ...encrypted, version, updatedAt });
        },
      );
      if (legacyLeft === 0) await publishV2Only(vaultMacKey, revisions, api, sessionToken).catch(() => undefined);
    })();
  }, [allItems, isLoading, sessionToken, vaultEncKey, vaultMacKey, revisions, upsertItem]);

  // --- Derived data ---------------------------------------------------------

  // Tag counts come from decrypted plaintexts: tags are zero-knowledge data.
  const tagCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of activeItems) {
      for (const tag of decrypted.get(item.id)?.tags ?? []) {
        counts.set(tag, (counts.get(tag) ?? 0) + 1);
      }
    }
    return counts;
  }, [activeItems, decrypted]);
  const allTags = useMemo(() => [...tagCounts.keys()].sort((a, b) => a.localeCompare(b)), [tagCounts]);

  // Dropping the last item with the active tag would leave an inexplicably
  // empty list, so the filter goes away with its tag.
  const tagFilter =
    tagState && allTags.some((t) => t.toLowerCase() === tagState.toLowerCase()) ? tagState : null;

  const passwordUses = useMemo(() => passwordUseCounts(decrypted.values()), [decrypted]);

  const filteredItems = useMemo(
    () =>
      sortItems(
        filterItems(activeItems, decrypted, {
          vaultId: activeVaultId,
          filter,
          tag: tagFilter,
          query: search,
          reviewIds: review?.ids ?? null,
          favorites,
        }),
        decrypted,
        sort,
      ),
    [activeItems, decrypted, activeVaultId, filter, tagFilter, search, sort, review, favorites],
  );

  const selectedEntry = useMemo<DecryptedEntry | null>(() => {
    if (!selectedId) return null;
    const item = activeItems.find((i) => i.id === selectedId);
    const plaintext = item ? decrypted.get(item.id) : undefined;
    return item && plaintext ? { item, plaintext } : null;
  }, [selectedId, activeItems, decrypted]);

  const hasActiveFilters =
    filter !== "all" || tagFilter !== null || activeVaultId !== null || review !== null || search.trim() !== "";

  // --- Feedback -------------------------------------------------------------

  const showNotice = useCallback((message: string) => {
    setNotice(message);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(null), NOTICE_MS);
  }, []);

  const copy = useCallback((text: string) => useNopassStore.getState().copyWithAutoClear(text), []);

  const copyWithStatus = useCallback(async (text: string, noun: string) => {
    const ok = await useNopassStore.getState().copyWithAutoClear(text);
    setCopyStatus(ok ? `${noun} copied.` : "Couldn't access the clipboard.");
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopyStatus(null), NOTICE_MS);
  }, []);

  // --- Selection and filters ------------------------------------------------

  const goToVault = useCallback(() => {
    if (pathname !== "/vault") router.push("/vault");
  }, [pathname, router]);

  const leaveEditing = useCallback(() => {
    setCreating(null);
    setEditing(false);
  }, []);


  const openItem = useCallback(
    (id: string) => {
      leaveEditing();
      setSelectedId(id);
      setDetailOpen(true);
      goToVault();
    },
    [goToVault, leaveEditing],
  );

  const moveCursor = useCallback(
    (id: string) => {
      leaveEditing();
      setSelectedId(id);
    },
    [leaveEditing],
  );

  const closeDetail = useCallback(() => {
    leaveEditing();
    setDetailOpen(false);
  }, [leaveEditing]);

  const deselect = useCallback(() => {
    leaveEditing();
    setSelectedId(null);
    setDetailOpen(false);
  }, [leaveEditing]);

  const startCreate = useCallback(
    (type: VaultItemType) => {
      setEditing(false);
      setCreating(type);
      setSelectedId(null);
      setDetailOpen(true);
      goToVault();
    },
    [goToVault],
  );

  const startEdit = useCallback(() => {
    setCreating(null);
    setEditing(true);
    setDetailOpen(true);
  }, []);

  const applyFilter = useCallback(
    (next: Filter) => {
      setFilterState(next);
      setTagFilter(null);
      setReview(null);
      setDetailOpen(false);
      goToVault();
    },
    [goToVault],
  );

  const clearFilters = useCallback(() => {
    setFilterState("all");
    setTagFilter(null);
    setActiveVaultId(null);
    setReview(null);
    setSearch("");
  }, []);

  const selectTag = useCallback(
    (tag: string | null) => {
      setTagFilter(tag);
      if (tag) goToVault();
    },
    [goToVault],
  );

  // --- Mutations ------------------------------------------------------------

  const createVault = useCallback(
    async (name: string) => {
      if (!sessionToken || !vaultEncKey || !name.trim()) return;
      try {
        const blob = await encryptBytes(new TextEncoder().encode(name.trim()), vaultEncKey);
        const created = await api.vault.createVault({ nameBlob: blob.blob, nameIv: blob.blobIv }, sessionToken);
        setVaults((v) => [...v, created]);
        setActiveVaultId(created.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to create vault");
      }
    },
    [sessionToken, vaultEncKey],
  );

  const moveItem = useCallback(
    async (item: EncryptedVaultItem, toVaultId: string) => {
      if (!sessionToken) return;
      try {
        await api.vault.moveItem(item.vaultId, item.id, { toVaultId }, sessionToken);
        upsertItem({ ...item, vaultId: toVaultId, version: item.version + 1 });
        // Close the pane: the item may have just left the vault being viewed
        deselect();
        showNotice("Item moved");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to move item");
      }
    },
    [sessionToken, upsertItem, deselect, showNotice],
  );

  const saveItem = useCallback(
    async (plaintext: VaultItemPlaintext) => {
      if (!sessionToken || !defaultVaultId || !vaultEncKey || !revisions) return;
      setSaving(true);
      setError(null);
      try {
        if (creating) {
          // activeVaultId can go stale if the vault was deleted in another tab
          const targetVault =
            activeVaultId && vaults.some((v) => v.id === activeVaultId) ? activeVaultId : defaultVaultId;
          const id = crypto.randomUUID();
          const { encrypted, revision } = await encryptVaultItem(
            plaintext,
            { scope: { kind: "personal" }, itemId: id, itemType: plaintext.type },
            vaultEncKey,
            revisions,
            null,
          );
          const created = await api.vault.create(targetVault, { id, itemType: plaintext.type, ...encrypted }, sessionToken);
          revisions.record(id, revision);
          upsertItem(created);
          setSelectedId(created.id);
          showNotice("Item saved");
        } else if (editing && selectedEntry) {
          const { item } = selectedEntry;
          if (plaintext.type !== item.itemType) throw new Error("An item's type cannot change");
          if (!vaultMacKey) return;
          // Decrypt the blob being replaced so the new revision beats it
          const binding = bindingForItem(item);
          const current = await decryptVaultItem(item, binding, { vaultEncKey, vaultMacKey }, revisions);
          const { encrypted, revision } = await encryptVaultItem(plaintext, binding, vaultEncKey, revisions, current);
          await api.vault.update(item.vaultId, item.id, { ...encrypted, version: item.version }, sessionToken);
          revisions.record(item.id, revision);
          upsertItem({
            ...item,
            blob: encrypted.blob,
            blobIv: encrypted.blobIv,
            blobMac: encrypted.blobMac,
            version: item.version + 1,
          });
          showNotice("Changes saved");
        }
        leaveEditing();
      } catch (err) {
        if (err instanceof ConflictError) {
          setError("This item changed somewhere else (another tab or device). Reload before saving.");
        } else {
          setError(err instanceof Error ? err.message : "Save failed");
        }
      } finally {
        setSaving(false);
      }
    },
    [
      creating,
      editing,
      selectedEntry,
      sessionToken,
      defaultVaultId,
      activeVaultId,
      vaults,
      vaultEncKey,
      vaultMacKey,
      revisions,
      upsertItem,
      showNotice,
      leaveEditing,
    ],
  );

  const deleteItem = useCallback(
    async (target: EncryptedVaultItem) => {
      if (!sessionToken) return;
      try {
        await api.vault.delete(target.vaultId, target.id, sessionToken);
        markDeleted(target.id);
        deselect();
        showNotice("Item deleted");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Delete failed");
      }
    },
    [sessionToken, markDeleted, deselect, showNotice],
  );

  const lockVault = useCallback(() => {
    lock();
    router.replace("/login");
  }, [lock, router]);

  const viewSignature = `${pathname}|${filter}|${tagFilter}|${activeVaultId}`;
  const drawerOpen = drawerView === viewSignature;
  const setDrawerOpen = useCallback(
    (open: boolean) => setDrawerView(open ? viewSignature : null),
    [viewSignature],
  );
  const shareOpen = shareFor !== null && shareFor === selectedId;
  const setShareOpen = useCallback((open: boolean) => setShareFor(open ? selectedId : null), [selectedId]);

  const value = useMemo<VaultContextValue>(
    () => ({
      email,
      isLoading,
      items: activeItems,
      decrypted,
      vaults,
      vaultNames,
      favorites,
      passwordUses,
      breaches,
      setBreaches,
      activeVaultId,
      setActiveVaultId,
      filter,
      applyFilter,
      tagFilter,
      setTagFilter: selectTag,
      tagCounts,
      allTags,
      search,
      setSearch,
      sort,
      setSort,
      review,
      setReview,
      clearFilters,
      hasActiveFilters,
      filteredItems,
      registerSearchInput,
      focusSearch,
      isSearchInput,
      selectedId,
      selectedEntry,
      detailOpen,
      openItem,
      moveCursor,
      closeDetail,
      deselect,
      creating,
      editing,
      startCreate,
      startEdit,
      cancelEdit: leaveEditing,
      saving,
      saveItem,
      deleteItem,
      moveItem,
      toggleFavorite,
      createVault,
      copy,
      copyWithStatus,
      copyStatus,
      notice,
      showNotice,
      error,
      setError,
      shareOpen,
      setShareOpen,
      paletteOpen,
      setPaletteOpen,
      drawerOpen,
      setDrawerOpen,
      lockVault,
    }),
    [
      email, isLoading, activeItems, decrypted, vaults, vaultNames, favorites, passwordUses, breaches,
      activeVaultId, filter, applyFilter, tagFilter, selectTag, tagCounts, allTags, search, sort, review,
      clearFilters, hasActiveFilters, filteredItems, registerSearchInput, focusSearch, isSearchInput, selectedId, selectedEntry, detailOpen, openItem,
      moveCursor, closeDetail, deselect, creating, editing, startCreate, startEdit, leaveEditing, saving,
      saveItem, deleteItem, moveItem, toggleFavorite, createVault, copy, copyWithStatus, copyStatus,
      notice, showNotice, error, shareOpen, setShareOpen, paletteOpen, drawerOpen, setDrawerOpen, lockVault,
    ],
  );

  if (!unlocked) return null;

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}
