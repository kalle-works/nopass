import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { ExternalLink, Plus, Search } from "lucide-react";
import { loginWithPassword, unlockAccount, zeroAccount } from "@nopass/crypto";
import { Banner, Button, EmptyState, Field, Kbd, Spinner, createApiClient } from "@nopass/ui";
import { extensionAccountState } from "../lib/account-state";
import { bytesToBase64 } from "../lib/base64";
import { siteHostname, webVaultUrl } from "../lib/web-url";
import { AUTO_LOCK_CHOICES, AUTO_LOCK_SETTING, parseAutoLockMinutes } from "../lib/auto-lock";
import { EntryRow, type VaultEntry } from "./EntryRow";
import { EntryDetail } from "./EntryDetail";
import { UnlockForm } from "./UnlockForm";

// Injected at build time (vite define) — falls back to the dev API server
const API_BASE: string =
  typeof __API_BASE__ !== "undefined" ? __API_BASE__ : "http://localhost:3001";
const api = createApiClient(API_BASE);
const WEB_VAULT_URL = webVaultUrl(API_BASE);

// ─── Types ────────────────────────────────────────────────────────────────────

type Screen = "loading" | "locked" | "unlocked";

interface State {
  screen: Screen;
  /** Logins matching the active tab's URL */
  siteEntries: VaultEntry[];
  /** All logins, or the search results while a query is typed */
  entries: VaultEntry[];
  query: string;
  tabUrl: string;
  error: string | null;
  fillError: string | null;
  unlocking: boolean;
  selected: VaultEntry | null;
  /** A fill into a page the item is not saved for, waiting for the user's yes */
  pendingFill: { entry: VaultEntry; origin: string } | null;
}

type Action =
  | { type: "SET_SCREEN"; screen: Screen }
  | { type: "SET_LISTS"; siteEntries: VaultEntry[]; entries: VaultEntry[] }
  | { type: "SET_QUERY"; query: string }
  | { type: "SET_TAB_URL"; url: string }
  | { type: "SET_ERROR"; error: string | null }
  | { type: "SET_FILL_ERROR"; error: string | null }
  | { type: "SET_UNLOCKING"; value: boolean }
  | { type: "SELECT"; entry: VaultEntry | null }
  | { type: "SET_PENDING_FILL"; pending: State["pendingFill"] };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "SET_SCREEN": return { ...state, screen: action.screen };
    case "SET_LISTS": return { ...state, siteEntries: action.siteEntries, entries: action.entries };
    case "SET_QUERY": return { ...state, query: action.query };
    case "SET_TAB_URL": return { ...state, tabUrl: action.url };
    case "SET_ERROR": return { ...state, error: action.error };
    case "SET_FILL_ERROR": return { ...state, fillError: action.error };
    case "SET_UNLOCKING": return { ...state, unlocking: action.value };
    case "SELECT": return { ...state, selected: action.entry, fillError: null, pendingFill: null };
    case "SET_PENDING_FILL": return { ...state, pendingFill: action.pending };
  }
}

const initial: State = {
  screen: "loading",
  siteEntries: [],
  entries: [],
  query: "",
  tabUrl: "",
  error: null,
  fillError: null,
  unlocking: false,
  selected: null,
  pendingFill: null,
};

const NO_FORM_MESSAGE = "Couldn't find a login form on this page.";

function originMismatchMessage(origin: string): string {
  return `This login isn't saved for ${origin}, and that form is embedded from another site. nopwd won't fill it.`;
}

// ─── Messaging helpers ────────────────────────────────────────────────────────

function sendMessage<T>(msg: object): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp: T) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(resp);
    });
  });
}

function openUrl(url: string) {
  if (typeof chrome !== "undefined" && chrome.tabs?.create) void chrome.tabs.create({ url });
  else window.open(url, "_blank", "noopener");
}

const isMac = typeof navigator !== "undefined" && /mac/i.test(navigator.platform);
const SEARCH_SHORTCUT = isMac ? "⌘K" : "Ctrl K";

// ─── App ──────────────────────────────────────────────────────────────────────

export function App() {
  const [state, dispatch] = useReducer(reducer, initial);
  const [lastEmail, setLastEmail] = useState("");
  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(parseAutoLockMinutes(undefined));
  const searchRef = useRef<HTMLInputElement>(null);
  // Discards responses from searches that were superseded while in flight
  const searchSeq = useRef(0);
  const host = siteHostname(state.tabUrl);

  async function refreshSearch(query: string, url: string) {
    const seq = ++searchSeq.current;
    const [site, all] = await Promise.all([
      query || !url
        ? Promise.resolve<{ results?: VaultEntry[] }>({ results: [] })
        : sendMessage<{ results?: VaultEntry[]; error?: string }>({ type: "SEARCH_ITEMS", query: "", url }),
      sendMessage<{ results?: VaultEntry[]; error?: string }>({ type: "SEARCH_ITEMS", query }),
    ]);
    if (seq !== searchSeq.current) return;
    dispatch({ type: "SET_LISTS", siteEntries: site.results ?? [], entries: all.results ?? [] });
  }

  // Check if SW is already unlocked on popup open
  useEffect(() => {
    async function init() {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      dispatch({ type: "SET_TAB_URL", url: tab?.url ?? "" });

      // Resolve the remembered email before showing any screen so the unlock
      // form always mounts prefilled (also after an in-popup Lock) and focus
      // lands on the password field
      const stored = await chrome.storage.local.get(["lastEmail", AUTO_LOCK_SETTING]);
      setLastEmail(typeof stored["lastEmail"] === "string" ? stored["lastEmail"] : "");
      setAutoLockMinutes(parseAutoLockMinutes(stored[AUTO_LOCK_SETTING]));

      const resp = await sendMessage<{ unlocked: boolean }>({ type: "IS_UNLOCKED" });
      if (resp.unlocked) {
        dispatch({ type: "SET_SCREEN", screen: "unlocked" });
        await refreshSearch("", tab?.url ?? "");
      } else {
        dispatch({ type: "SET_SCREEN", screen: "locked" });
      }
    }
    init().catch((e) => {
      dispatch({ type: "SET_ERROR", error: String(e) });
      dispatch({ type: "SET_SCREEN", screen: "locked" });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const focusSearch = useCallback(() => {
    dispatch({ type: "SELECT", entry: null });
    // The search field remounts when leaving the detail view
    requestAnimationFrame(() => searchRef.current?.focus());
  }, []);

  // Cmd/Ctrl+K focuses search; Escape leaves the detail view
  useEffect(() => {
    if (state.screen !== "unlocked") return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        focusSearch();
      } else if (e.key === "Escape" && state.selected) {
        dispatch({ type: "SELECT", entry: null });
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [state.screen, state.selected, focusSearch]);

  async function handleSearch(query: string) {
    dispatch({ type: "SET_QUERY", query });
    await refreshSearch(query, state.tabUrl);
  }

  async function handleLock() {
    await sendMessage({ type: "LOCK" });
    dispatch({ type: "SET_SCREEN", screen: "locked" });
    dispatch({ type: "SET_LISTS", siteEntries: [], entries: [] });
    dispatch({ type: "SELECT", entry: null });
  }

  const loadCredentials = useCallback(async (itemId: string) => {
    const resp = await sendMessage<{ username?: string; password?: string; error?: string }>({
      type: "GET_CREDENTIALS",
      itemId,
    });
    if (resp.username === undefined || resp.password === undefined) return null;
    return { username: resp.username, password: resp.password };
  }, []);

  async function handleFill(entry: VaultEntry, confirmedOrigin?: string) {
    dispatch({ type: "SET_FILL_ERROR", error: null });
    dispatch({ type: "SET_PENDING_FILL", pending: null });
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) {
      dispatch({ type: "SET_FILL_ERROR", error: NO_FORM_MESSAGE });
      return;
    }
    try {
      const resp = await sendMessage<{ ok?: boolean; error?: string; origin?: string; confirmable?: boolean }>({
        type: "AUTOFILL",
        itemId: entry.id,
        tabId: tab.id,
        ...(confirmedOrigin ? { confirmedOrigin } : {}),
      });
      if (resp.ok) {
        window.close();
        return;
      }
      if (resp.error === "origin_mismatch" && resp.origin) {
        if (resp.confirmable) {
          dispatch({ type: "SET_PENDING_FILL", pending: { entry, origin: resp.origin } });
        } else {
          dispatch({ type: "SET_FILL_ERROR", error: originMismatchMessage(resp.origin) });
        }
        return;
      }
    } catch {
      // Fall through to the failure message
    }
    dispatch({ type: "SET_FILL_ERROR", error: NO_FORM_MESSAGE });
  }

  async function handleAutoLockChange(minutes: number) {
    setAutoLockMinutes(minutes);
    // The background re-arms its alarm on this storage change
    await chrome.storage.local.set({ [AUTO_LOCK_SETTING]: minutes });
  }

  async function handleUnlock(email: string, password: string) {
    dispatch({ type: "SET_ERROR", error: null });
    dispatch({ type: "SET_UNLOCKING", value: true });
    try {
      const accountState = extensionAccountState();
      const auth = await loginWithPassword(api.auth, { email, password, accountState });
      const account = await unlockAccount(api.auth, { email, password, session: auth, accountState });
      const { encKeyBytes, macKeyBytes } = account;

      const resp = await sendMessage<{ ok?: boolean; error?: string }>({
        type: "UNLOCK",
        sessionToken: auth.sessionToken,
        defaultVaultId: auth.defaultVaultId,
        vaultEncKeyB64: bytesToBase64(encKeyBytes),
        vaultMacKeyB64: bytesToBase64(macKeyBytes),
      });

      // Zero key material
      zeroAccount(account);

      if (resp.error) throw new Error(resp.error);

      await chrome.storage.local.set({ lastEmail: email });
      setLastEmail(email);
      dispatch({ type: "SET_SCREEN", screen: "unlocked" });
      await refreshSearch("", state.tabUrl);
    } catch (e) {
      dispatch({ type: "SET_ERROR", error: e instanceof Error ? e.message : "Login failed" });
    } finally {
      dispatch({ type: "SET_UNLOCKING", value: false });
    }
  }

  if (state.screen === "loading") {
    return (
      <div role="status" className="flex h-32 items-center justify-center gap-2 text-ui text-muted">
        <Spinner /> Loading…
      </div>
    );
  }

  if (state.screen === "locked") {
    return (
      <UnlockForm
        error={state.error}
        unlocking={state.unlocking}
        initialEmail={lastEmail}
        onUnlock={handleUnlock}
      />
    );
  }

  const searching = state.query.trim() !== "";
  const noSiteMatch = host !== "" && !searching && state.siteEntries.length === 0;

  return (
    <div className="flex max-h-[580px] min-h-[320px] flex-col">
      <header className="flex items-center gap-2 border-b border-divider px-4 py-2">
        <span className="text-h3 font-semibold text-fg">nopwd</span>
        <span className="min-w-0 flex-1 truncate text-meta text-muted" title={lastEmail}>
          {lastEmail}
        </span>
        <Button variant="ghost" size="sm" aria-label="Search all items" onClick={focusSearch} icon={<Search aria-hidden className="size-4" />}>
          <Kbd>{SEARCH_SHORTCUT}</Kbd>
        </Button>
        <Button variant="ghost" size="sm" onClick={handleLock}>
          Lock
        </Button>
      </header>

      {state.fillError && (
        <Banner tone="warning" className="m-3 mb-0 rounded">
          {state.fillError}
        </Banner>
      )}

      {state.pendingFill && (
        <Banner
          tone="warning"
          className="m-3 mb-0 rounded"
          title={`${state.pendingFill.entry.name} isn't saved for this site`}
          action={
            <div className="flex shrink-0 flex-col gap-1">
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleFill(state.pendingFill!.entry, state.pendingFill!.origin)}
              >
                Fill anyway
              </Button>
              <Button variant="ghost" size="sm" onClick={() => dispatch({ type: "SET_PENDING_FILL", pending: null })}>
                Cancel
              </Button>
            </div>
          }
        >
          The page is <span className="break-all font-mono text-mono-sm text-fg">{state.pendingFill.origin}</span>.
          Only fill it if you trust this site with these credentials.
        </Banner>
      )}

      {state.selected ? (
        <EntryDetail
          key={state.selected.id}
          entry={state.selected}
          loadCredentials={loadCredentials}
          onBack={() => dispatch({ type: "SELECT", entry: null })}
          onFill={handleFill}
        />
      ) : (
        <>
          <div className="px-4 py-3">
            <Field
              ref={searchRef}
              label="Search"
              type="search"
              placeholder="Title, username or website"
              value={state.query}
              onChange={(e) => handleSearch(e.target.value)}
              autoFocus
              className="[&>div:first-child]:sr-only"
            />
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto border-t border-divider">
            {!searching && host !== "" && (
              <section aria-labelledby="site-heading">
                <h2 id="site-heading" className="flex items-baseline gap-2 bg-bg-subtle px-4 py-2 text-meta font-medium text-muted">
                  For this site
                  <span className="min-w-0 truncate font-mono text-mono-sm text-fg">{host}</span>
                </h2>
                {noSiteMatch ? (
                  <EmptyState
                    className="px-4 py-5"
                    title={`No logins for ${host}`}
                    action={
                      <Button variant="primary" size="sm" onClick={() => openUrl(WEB_VAULT_URL)}>
                        Save a login
                      </Button>
                    }
                    secondary={
                      <Button variant="ghost" size="sm" onClick={focusSearch}>
                        Search all items
                      </Button>
                    }
                  />
                ) : (
                  <ul>
                    {state.siteEntries.map((entry) => (
                      <EntryRow
                        key={entry.id}
                        entry={entry}
                        onOpen={(e) => dispatch({ type: "SELECT", entry: e })}
                        onFill={handleFill}
                      />
                    ))}
                  </ul>
                )}
              </section>
            )}

            <section aria-labelledby="all-heading">
              <h2 id="all-heading" className="bg-bg-subtle px-4 py-2 text-meta font-medium text-muted">
                {searching ? "Results" : "All items"}
              </h2>
              {state.entries.length === 0 ? (
                <p className="px-4 py-6 text-ui text-muted">
                  {searching ? `No items match "${state.query}".` : "Your vault has no logins yet."}
                </p>
              ) : (
                <ul>
                  {state.entries.map((entry) => (
                    <EntryRow
                      key={entry.id}
                      entry={entry}
                      onOpen={(e) => dispatch({ type: "SELECT", entry: e })}
                      onFill={handleFill}
                    />
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}

      <footer className="flex items-center justify-between border-t border-divider px-3 py-2">
        <Button size="sm" icon={<Plus aria-hidden className="size-4" />} onClick={() => openUrl(WEB_VAULT_URL)}>
          New
        </Button>
        <label className="flex items-center gap-1 text-meta text-muted">
          Auto-lock
          <select
            value={autoLockMinutes}
            onChange={(e) => handleAutoLockChange(Number(e.target.value))}
            className="rounded border border-divider bg-bg px-1 py-0.5 text-meta text-fg"
          >
            {AUTO_LOCK_CHOICES.map((m) => (
              <option key={m} value={m}>
                {m < 60 ? `${m} min` : `${m / 60} h`}
              </option>
            ))}
          </select>
        </label>
        <Button variant="ghost" size="sm" icon={<ExternalLink aria-hidden className="size-4" />} onClick={() => openUrl(WEB_VAULT_URL)}>
          Open vault
        </Button>
      </footer>
    </div>
  );
}
