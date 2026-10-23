// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from "vitest";

/**
 * The MV3 service worker is torn down after ~30s idle. These tests verify the
 * unlocked session survives that teardown via chrome.storage.session, and that
 * an explicit LOCK or a server-rejected session leaves the vault locked.
 */

import {
  EXTENSION_ID,
  UNLOCK_MSG,
  env,
  resetEnvironment,
  send,
  startServiceWorker,
} from "./background-harness";

/** Extension page opened in a tab: extension url, tab present. */
const EXTENSION_TAB_SENDER: chrome.runtime.MessageSender = {
  id: EXTENSION_ID,
  url: `chrome-extension://${EXTENSION_ID}/src/popup/index.html`,
  tab: { id: 7 } as chrome.tabs.Tab,
};

/** Content script: web page url, tab present. */
const CONTENT_SCRIPT_SENDER: chrome.runtime.MessageSender = {
  id: EXTENSION_ID,
  url: "https://evil.example/",
  tab: { id: 1 } as chrome.tabs.Tab,
};

beforeEach(resetEnvironment);

describe("vault session persistence across SW restarts", () => {
  it("reports locked before any unlock", async () => {
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("stays unlocked after the service worker restarts", async () => {
    expect(await send(UNLOCK_MSG)).toEqual({ ok: true });
    expect(env.sessionStore["vaultSession"]).toMatchObject({ sessionToken: "token-1" });

    await startServiceWorker();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: true });
  });

  it("LOCK wipes the persisted session — restart stays locked", async () => {
    await send(UNLOCK_MSG);
    expect(await send({ type: "LOCK" })).toEqual({ ok: true });
    expect(env.sessionStore["vaultSession"]).toBeUndefined();

    await startServiceWorker();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("drops the persisted session when the server rejects it", async () => {
    await send(UNLOCK_MSG);
    await startServiceWorker();
    env.itemsResponse = async () => new Response("unauthorized", { status: 401 });

    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
    expect(env.sessionStore["vaultSession"]).toBeUndefined();
  });

  it("a LOCK during an in-flight restore wins — the vault stays locked", async () => {
    await send(UNLOCK_MSG);
    await startServiceWorker();

    // Make the restore's items fetch hang until we release it
    let releaseFetch!: () => void;
    const gate = new Promise<void>((r) => { releaseFetch = r; });
    env.itemsResponse = async () => {
      await gate;
      return new Response(JSON.stringify([]), { status: 200 });
    };

    const restoreTriggered = send({ type: "IS_UNLOCKED" }); // restore starts
    await new Promise((r) => setTimeout(r, 10)); // let it reach the fetch
    expect(await send({ type: "LOCK" })).toEqual({ ok: true });
    releaseFetch();

    expect(await restoreTriggered).toEqual({ unlocked: false });
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
    expect(env.sessionStore["vaultSession"]).toBeUndefined();
  });

  it("never lets a content script unlock, lock, or read vault data", async () => {
    await send(UNLOCK_MSG);
    expect(await send(UNLOCK_MSG, CONTENT_SCRIPT_SENDER)).toEqual({ error: "unauthorized" });
    expect(await send({ type: "LOCK" }, CONTENT_SCRIPT_SENDER)).toEqual({ error: "unauthorized" });
    expect(await send({ type: "IS_UNLOCKED" }, CONTENT_SCRIPT_SENDER)).toEqual({ unlocked: false });
    expect(await send({ type: "GET_ITEMS" }, CONTENT_SCRIPT_SENDER)).toEqual({ error: "unauthorized" });
    expect(await send({ type: "SEARCH_ITEMS", query: "" }, CONTENT_SCRIPT_SENDER)).toEqual({
      error: "unauthorized",
    });
    expect(await send({ type: "GET_CREDENTIALS", itemId: "x" }, CONTENT_SCRIPT_SENDER)).toEqual({
      error: "unauthorized",
    });
  });

  it("extension pages hosted in a tab may read but not mutate or get plaintext credentials", async () => {
    await send(UNLOCK_MSG);
    expect(await send({ type: "IS_UNLOCKED" }, EXTENSION_TAB_SENDER)).toEqual({ unlocked: true });
    expect(await send({ type: "SEARCH_ITEMS", query: "" }, EXTENSION_TAB_SENDER)).toEqual({
      results: [],
    });
    // LOCK and GET_CREDENTIALS require the popup (no sender.tab) — extension
    // tabs are read-only and must not receive plaintext credentials.
    expect(await send({ type: "LOCK" }, EXTENSION_TAB_SENDER)).toEqual({ error: "unauthorized" });
    expect(await send({ type: "GET_CREDENTIALS", itemId: "x" }, EXTENSION_TAB_SENDER)).toEqual({
      error: "unauthorized",
    });
  });
});
