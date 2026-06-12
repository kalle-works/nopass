import { useEffect, useReducer, useRef, useState } from "react";
import { deriveMasterKey, stretchMasterKeyRaw, srpStep1, srpStep2, computeEmailHash } from "@nopass/crypto";
import { createApiClient } from "@nopass/ui";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { bytesToBase64 } from "../lib/base64";

const API_BASE = "http://localhost:3001";
const api = createApiClient(API_BASE);

// ─── Types ────────────────────────────────────────────────────────────────────

interface VaultEntry {
  id: string;
  name: string;
  username: string;
  urls: string[];
  hasPasskey?: boolean;
}

type Screen = "loading" | "locked" | "unlocked";

interface State {
  screen: Screen;
  entries: VaultEntry[];
  query: string;
  tabUrl: string;
  copied: string | null; // "username:id" | "password:id"
  error: string | null;
  unlocking: boolean;
}

type Action =
  | { type: "SET_SCREEN"; screen: Screen }
  | { type: "SET_ENTRIES"; entries: VaultEntry[] }
  | { type: "SET_QUERY"; query: string }
  | { type: "SET_TAB_URL"; url: string }
  | { type: "SET_COPIED"; key: string | null }
  | { type: "SET_ERROR"; error: string | null }
  | { type: "SET_UNLOCKING"; value: boolean };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "SET_SCREEN": return { ...state, screen: action.screen };
    case "SET_ENTRIES": return { ...state, entries: action.entries };
    case "SET_QUERY": return { ...state, query: action.query };
    case "SET_TAB_URL": return { ...state, tabUrl: action.url };
    case "SET_COPIED": return { ...state, copied: action.key };
    case "SET_ERROR": return { ...state, error: action.error };
    case "SET_UNLOCKING": return { ...state, unlocking: action.value };
  }
}

const initial: State = {
  screen: "loading",
  entries: [],
  query: "",
  tabUrl: "",
  copied: null,
  error: null,
  unlocking: false,
};

// ─── Messaging helpers ────────────────────────────────────────────────────────

function sendMessage<T>(msg: object): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp: T) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(resp);
    });
  });
}

// ─── App ──────────────────────────────────────────────────────────────────────

export function App() {
  const [state, dispatch] = useReducer(reducer, initial);

  // Check if SW is already unlocked on popup open
  useEffect(() => {
    async function init() {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      dispatch({ type: "SET_TAB_URL", url: tab?.url ?? "" });

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

  async function refreshSearch(query: string, url: string) {
    const resp = await sendMessage<{ results?: VaultEntry[]; error?: string }>({
      type: "SEARCH_ITEMS",
      query,
      url,
    });
    if (resp.results) dispatch({ type: "SET_ENTRIES", entries: resp.results });
  }

  async function handleSearch(query: string) {
    dispatch({ type: "SET_QUERY", query });
    await refreshSearch(query, state.tabUrl);
  }

  async function handleLock() {
    await sendMessage({ type: "LOCK" });
    dispatch({ type: "SET_SCREEN", screen: "locked" });
    dispatch({ type: "SET_ENTRIES", entries: [] });
  }

  async function handleCopy(text: string, key: string) {
    await navigator.clipboard.writeText(text);
    dispatch({ type: "SET_COPIED", key });
    setTimeout(() => dispatch({ type: "SET_COPIED", key: null }), 1500);
  }

  async function handleCopyPassword(itemId: string) {
    const resp = await sendMessage<{ username?: string; password?: string; error?: string }>({
      type: "GET_CREDENTIALS",
      itemId,
    });
    if (resp.password) {
      await handleCopy(resp.password, `password:${itemId}`);
    }
  }

  async function handleAutofill(entry: VaultEntry) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    await sendMessage({ type: "AUTOFILL", itemId: entry.id, tabId: tab.id });
    window.close();
  }

  if (state.screen === "loading") {
    return (
      <div className="flex items-center justify-center h-32 bg-ink">
        <div className="text-faded text-sm font-brand">Loading…</div>
      </div>
    );
  }

  if (state.screen === "locked") {
    return (
      <UnlockForm
        error={state.error}
        unlocking={state.unlocking}
        onUnlock={async (email, password) => {
          dispatch({ type: "SET_ERROR", error: null });
          dispatch({ type: "SET_UNLOCKING", value: true });
          try {
            const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
            const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, email);

            const emailHash = computeEmailHash(email);
            const step1 = srpStep1();
            const initResp = await api.auth.srpInit({ emailHash, clientPublicA: step1.clientPublicA });
            const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
            const verifyResp = await api.auth.srpVerify({
              sessionId: initResp.sessionId,
              clientProofM1: step2.clientProofM1,
            });
            step2.verifyServerProof(verifyResp.serverProofM2);

            const resp = await sendMessage<{ ok?: boolean; error?: string }>({
              type: "UNLOCK",
              sessionToken: verifyResp.sessionToken,
              defaultVaultId: verifyResp.defaultVaultId,
              vaultEncKeyB64: bytesToBase64(encKeyBytes),
              vaultMacKeyB64: bytesToBase64(macKeyBytes),
            });

            // Zero key material
            encKeyBytes.fill(0);
            macKeyBytes.fill(0);

            if (resp.error) throw new Error(resp.error);

            dispatch({ type: "SET_SCREEN", screen: "unlocked" });
            await refreshSearch("", state.tabUrl);
          } catch (e) {
            dispatch({ type: "SET_ERROR", error: e instanceof Error ? e.message : "Login failed" });
          } finally {
            dispatch({ type: "SET_UNLOCKING", value: false });
          }
        }}
      />
    );
  }

  return (
    <div className="flex flex-col h-full min-h-[480px] bg-ink text-cream font-body">
      <header className="flex items-center justify-between px-4 py-3 border-b border-edge bg-surface">
        <span className="font-brand font-semibold text-cream text-sm">nopwd</span>
        <button
          onClick={handleLock}
          className="font-brand text-xs text-faded border border-edge px-2 py-1 hover:border-cream hover:text-cream"
        >
          Lock
        </button>
      </header>

      <div className="px-4 py-3 border-b border-edge">
        <input
          type="search"
          placeholder="Search vault…"
          value={state.query}
          onChange={(e) => handleSearch(e.target.value)}
          autoFocus
          className="w-full text-sm px-3 py-2 bg-surface border border-edge text-cream placeholder:text-faded focus:outline-none focus:border-cream"
        />
      </div>

      <div className="flex-1 overflow-y-auto">
        {state.entries.length === 0 ? (
          <div className="text-center text-faded text-sm py-8">
            {state.query ? "No matches" : "No logins for this site"}
          </div>
        ) : (
          <ul className="divide-y divide-edge">
            {state.entries.map((entry) => (
              <EntryRow
                key={entry.id}
                entry={entry}
                copied={state.copied}
                onCopy={handleCopy}
                onCopyPassword={handleCopyPassword}
                onAutofill={handleAutofill}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ─── UnlockForm ───────────────────────────────────────────────────────────────

interface UnlockFormProps {
  error: string | null;
  unlocking: boolean;
  onUnlock: (email: string, password: string) => void;
}

function UnlockForm({ error, unlocking, onUnlock }: UnlockFormProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <div className="min-h-[480px] bg-ink text-cream font-body p-4 pt-8">
      <p className="font-brand text-[11px] uppercase tracking-[0.1em] text-faded mb-2">nopwd</p>
      <h1 className="font-brand font-semibold text-cream text-base mb-6">Unlock vault</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onUnlock(email, password);
        }}
        className="space-y-3"
      >
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          className="w-full text-sm h-11 px-3 bg-surface border border-edge text-cream placeholder:text-faded focus:outline-none focus:border-cream"
        />
        <input
          type="password"
          placeholder="Master password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          className="w-full text-sm h-11 px-3 bg-surface border border-edge text-cream placeholder:text-faded focus:outline-none focus:border-cream"
        />
        {error && <p className="text-xs text-danger">{error}</p>}
        <button
          type="submit"
          disabled={unlocking}
          className="w-full h-11 bg-accent hover:bg-accent-hover disabled:opacity-50 text-ink text-sm font-brand font-semibold"
        >
          {unlocking ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </div>
  );
}

// ─── EntryRow ─────────────────────────────────────────────────────────────────

interface EntryRowProps {
  entry: VaultEntry;
  copied: string | null;
  onCopy: (text: string, key: string) => void;
  onCopyPassword: (itemId: string) => void;
  onAutofill: (entry: VaultEntry) => void;
}

function EntryRow({ entry, copied, onCopy, onCopyPassword, onAutofill }: EntryRowProps) {
  const userKey = `username:${entry.id}`;
  const passKey = `password:${entry.id}`;
  const initial = entry.name.charAt(0).toUpperCase();

  return (
    <li className="px-4 py-3">
      <div className="flex items-start gap-3">
        <div className="w-7 h-7 bg-elevated border border-edge text-accent flex items-center justify-center text-xs font-brand font-semibold shrink-0 mt-0.5">
          {initial}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-cream truncate">
            {entry.name}
            {entry.hasPasskey && (
              <span className="ml-2 font-brand text-[10px] font-semibold uppercase tracking-[0.1em] text-accent align-middle">
                passkey
              </span>
            )}
          </p>
          <p className="text-xs text-faded truncate">{entry.username}</p>
        </div>
      </div>
      <div className="flex gap-1.5 mt-2">
        <CopyButton label="Username" copied={copied === userKey} onClick={() => onCopy(entry.username, userKey)} />
        <CopyButton label="Password" copied={copied === passKey} onClick={() => onCopyPassword(entry.id)} />
        <button
          onClick={() => onAutofill(entry)}
          className="text-[11px] px-2 py-1.5 whitespace-nowrap bg-accent hover:bg-accent-hover text-ink font-brand font-semibold"
        >
          Autofill
        </button>
      </div>
    </li>
  );
}

function CopyButton({ label, copied, onClick }: { label: string; copied: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`text-[11px] px-2 py-1.5 whitespace-nowrap font-brand border transition-colors ${
        copied
          ? "border-success text-success"
          : "border-edge text-faded hover:border-cream hover:text-cream"
      }`}
    >
      {copied ? "Copied!" : `Copy ${label}`}
    </button>
  );
}
