import { vi, type Mock } from "vitest";
import { encryptItem } from "@nopass/crypto";
import type { EncryptedVaultItem, LoginItem } from "@nopass/types";

/**
 * Shared chrome.* mock for background service worker tests. An SW restart is
 * simulated by re-importing the module with fresh state while the storage
 * mocks persist.
 */

export const EXTENSION_ID = "test-extension-id";

type Listener = (
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (resp: unknown) => void,
) => boolean;

export const env = {
  listeners: [] as Listener[],
  sessionStore: {} as Record<string, unknown>,
  localStore: {} as Record<string, unknown>,
  alarmListeners: [] as Array<(alarm: { name: string }) => void>,
  idleListeners: [] as Array<(state: string) => void>,
  windowRemovedListeners: [] as Array<(windowId: number) => void>,
  itemsResponse: async (): Promise<Response> => new Response(JSON.stringify([]), { status: 200 }),
};

let currentChrome: ChromeMock;

/** The chrome mock installed for the current test. */
interface ChromeMock {
  runtime: Record<string, unknown>;
  alarms: { create: Mock; clear: Mock; [key: string]: unknown };
  tabs: { sendMessage: Mock; get: Mock };
  windows: { create: Mock; remove: Mock; [key: string]: unknown };
  [key: string]: unknown;
}

export function chromeMock(): ChromeMock {
  return currentChrome;
}

function makeStorageArea(store: () => Record<string, unknown>) {
  return {
    get: async (key: string) => (key in store() ? { [key]: store()[key] } : {}),
    set: async (items: Record<string, unknown>) => Object.assign(store(), items),
    remove: async (key: string) => {
      delete store()[key];
    },
  };
}

function makeChromeMock(): ChromeMock {
  return {
    runtime: {
      id: EXTENSION_ID,
      getURL: (path: string) => `chrome-extension://${EXTENSION_ID}/${path}`,
      onMessage: { addListener: (fn: Listener) => env.listeners.push(fn) },
    },
    storage: {
      session: makeStorageArea(() => env.sessionStore),
      local: makeStorageArea(() => env.localStore),
      onChanged: { addListener: vi.fn() },
    },
    alarms: {
      create: vi.fn(async () => {}),
      clear: vi.fn(async () => true),
      onAlarm: { addListener: (fn: (alarm: { name: string }) => void) => env.alarmListeners.push(fn) },
    },
    idle: {
      setDetectionInterval: vi.fn(),
      onStateChanged: { addListener: (fn: (state: string) => void) => env.idleListeners.push(fn) },
    },
    windows: {
      create: vi.fn(async () => ({ id: 99 })),
      remove: vi.fn(async () => {}),
      onRemoved: {
        addListener: (fn: (windowId: number) => void) => env.windowRemovedListeners.push(fn),
        removeListener: (fn: (windowId: number) => void) => {
          env.windowRemovedListeners = env.windowRemovedListeners.filter((l) => l !== fn);
        },
      },
    },
    tabs: {
      sendMessage: vi.fn(),
      get: vi.fn(async (tabId: number) => ({ id: tabId, url: "https://top.example/login" })),
    },
  };
}

/** Sender shape of the real action popup: extension url, no tab. */
export const POPUP_SENDER: chrome.runtime.MessageSender = {
  id: EXTENSION_ID,
  url: `chrome-extension://${EXTENSION_ID}/src/popup/index.html`,
};

/** Content script running in the given frame of tab 1. */
export function contentSender(
  url: string,
  frameId = 0,
  documentId = `doc-${frameId}`,
  origin = new URL(url).origin,
): chrome.runtime.MessageSender {
  return {
    id: EXTENSION_ID,
    url,
    origin,
    frameId,
    documentId,
    tab: { id: 1 } as chrome.tabs.Tab,
  };
}

export function send(message: unknown, sender: chrome.runtime.MessageSender = POPUP_SENDER) {
  return new Promise<any>((resolve) => {
    env.listeners[env.listeners.length - 1]!(message, sender, resolve);
  });
}

/** Imports the background module fresh — equivalent to Chrome restarting the SW. */
export async function startServiceWorker() {
  vi.resetModules();
  env.listeners = [];
  env.alarmListeners = [];
  env.idleListeners = [];
  env.windowRemovedListeners = [];
  await import("../background/index");
}

export async function resetEnvironment() {
  env.sessionStore = {};
  env.localStore = {};
  env.itemsResponse = async () => new Response(JSON.stringify([]), { status: 200 });
  currentChrome = makeChromeMock();
  vi.stubGlobal("chrome", currentChrome);
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (String(url).includes("/items")) return env.itemsResponse();
    throw new Error(`unexpected fetch: ${url}`);
  }));
  await startServiceWorker();
}

const KEY_BYTES = new Uint8Array(32).fill(7);
export const KEY_B64 = btoa(String.fromCharCode(...KEY_BYTES));
export const UNLOCK_MSG = {
  type: "UNLOCK",
  sessionToken: "token-1",
  defaultVaultId: "vault-1",
  vaultEncKeyB64: KEY_B64,
  vaultMacKeyB64: KEY_B64,
};

/** Encrypts login items with the UNLOCK_MSG keys and serves them from the items endpoint. */
export async function serveLogins(logins: Array<{ id: string } & Partial<LoginItem>>) {
  const [encKey, macKey] = await Promise.all([
    crypto.subtle.importKey("raw", KEY_BYTES, { name: "AES-GCM", length: 256 }, false, ["encrypt"]),
    crypto.subtle.importKey("raw", KEY_BYTES, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
  ]);
  const items: EncryptedVaultItem[] = await Promise.all(
    logins.map(async ({ id, ...fields }) => {
      const plain: LoginItem = {
        type: "login",
        name: id,
        username: "alice",
        password: "s3cret",
        urls: [],
        customFields: [],
        ...fields,
      };
      return {
        id,
        vaultId: "vault-1",
        userId: "user-1",
        itemType: "login",
        ...(await encryptItem(plain, encKey, macKey)),
        version: 1,
        deletedAt: null,
        createdAt: "2026-01-01T00:00:00Z",
        updatedAt: "2026-01-01T00:00:00Z",
      };
    }),
  );
  env.itemsResponse = async () => new Response(JSON.stringify(items), { status: 200 });
}

/** Waits until the background has opened a consent window; returns its request id. */
export async function consentRequestId(): Promise<string> {
  for (let i = 0; i < 100; i++) {
    const call = currentChrome.windows.create.mock.calls.at(-1) as [{ url: string }] | undefined;
    if (call) return new URL(call[0].url).searchParams.get("id")!;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("no consent window opened");
}

/** Sender shape of the extension-owned consent window. */
export function consentSender(requestId: string): chrome.runtime.MessageSender {
  return {
    id: EXTENSION_ID,
    url: `chrome-extension://${EXTENSION_ID}/src/consent/index.html?id=${requestId}`,
    tab: { id: 50 } as chrome.tabs.Tab,
  };
}
