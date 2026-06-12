// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from "vitest";

/**
 * The MV3 service worker is torn down after ~30s idle. These tests verify the
 * unlocked session survives that teardown via chrome.storage.session, and that
 * an explicit LOCK or a server-rejected session leaves the vault locked.
 * An SW restart is simulated by re-importing the module with fresh state
 * while the storage mock persists.
 */

const EXTENSION_ID = "test-extension-id";

type Listener = (
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (resp: unknown) => void,
) => boolean;

let listeners: Listener[];
let sessionStore: Record<string, unknown>;

function makeChromeMock() {
  return {
    runtime: {
      id: EXTENSION_ID,
      onMessage: { addListener: (fn: Listener) => listeners.push(fn) },
    },
    storage: {
      session: {
        get: async (key: string) => (key in sessionStore ? { [key]: sessionStore[key] } : {}),
        set: async (items: Record<string, unknown>) => Object.assign(sessionStore, items),
        remove: async (key: string) => {
          delete sessionStore[key];
        },
      },
    },
    tabs: { sendMessage: vi.fn() },
  };
}

function send(message: unknown, sender: chrome.runtime.MessageSender = { id: EXTENSION_ID }) {
  return new Promise<any>((resolve) => {
    listeners[listeners.length - 1]!(message, sender, resolve);
  });
}

/** Imports the background module fresh — equivalent to Chrome restarting the SW. */
async function startServiceWorker() {
  vi.resetModules();
  await import("../background/index");
}

const KEY_B64 = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));
const UNLOCK_MSG = {
  type: "UNLOCK",
  sessionToken: "token-1",
  defaultVaultId: "vault-1",
  vaultEncKeyB64: KEY_B64,
  vaultMacKeyB64: KEY_B64,
};

let itemsResponse: () => Response;

beforeEach(async () => {
  listeners = [];
  sessionStore = {};
  itemsResponse = () => new Response(JSON.stringify([]), { status: 200 });
  vi.stubGlobal("chrome", makeChromeMock());
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (String(url).includes("/items")) return itemsResponse();
    throw new Error(`unexpected fetch: ${url}`);
  }));
  await startServiceWorker();
});

describe("vault session persistence across SW restarts", () => {
  it("reports locked before any unlock", async () => {
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("stays unlocked after the service worker restarts", async () => {
    expect(await send(UNLOCK_MSG)).toEqual({ ok: true });
    expect(sessionStore["vaultSession"]).toMatchObject({ sessionToken: "token-1" });

    await startServiceWorker();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: true });
  });

  it("LOCK wipes the persisted session — restart stays locked", async () => {
    await send(UNLOCK_MSG);
    expect(await send({ type: "LOCK" })).toEqual({ ok: true });
    expect(sessionStore["vaultSession"]).toBeUndefined();

    await startServiceWorker();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("drops the persisted session when the server rejects it", async () => {
    await send(UNLOCK_MSG);
    await startServiceWorker();
    itemsResponse = () => new Response("unauthorized", { status: 401 });

    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
    expect(sessionStore["vaultSession"]).toBeUndefined();
  });

  it("never lets a content script unlock or read the persisted session", async () => {
    await send(UNLOCK_MSG);
    const contentScriptSender = {
      id: EXTENSION_ID,
      tab: { id: 1 } as chrome.tabs.Tab,
      url: "https://evil.example/",
    };
    expect(await send(UNLOCK_MSG, contentScriptSender)).toEqual({ error: "unauthorized" });
    expect(await send({ type: "LOCK" }, contentScriptSender)).toEqual({ error: "unauthorized" });
  });
});
