// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from "vitest";
import {
  UNLOCK_MSG,
  contentSender,
  env,
  resetEnvironment,
  send,
  serveLogins,
  startServiceWorker,
} from "./background-harness";

/**
 * Requirements: credentials go to exactly one frame, the one the user is
 * interacting with, and only if that frame's origin matches the item. A
 * mismatch needs a confirmation naming the origin, never for a subframe.
 * Keys and the session token are wiped after inactivity or a system lock.
 */

beforeEach(resetEnvironment);

async function unlockWith(logins: Parameters<typeof serveLogins>[0]) {
  await serveLogins(logins);
  expect(await send(UNLOCK_MSG)).toEqual({ ok: true });
  env.chrome.tabs.sendMessage.mockResolvedValue({ filled: true });
}

describe("AUTOFILL frame targeting", () => {
  it("refuses a recorded cross-origin frame that does not match the item, even when confirmed", async () => {
    await unlockWith([{ id: "bank", urls: ["https://bank.example"] }]);
    await send({ type: "FILL_TARGET" }, contentSender("https://ads.example/frame", 4));

    const resp = await send({ type: "AUTOFILL", itemId: "bank", tabId: 1, confirmedOrigin: "https://ads.example" });

    expect(resp).toEqual({ error: "origin_mismatch", origin: "https://ads.example", confirmable: false });
    expect(env.chrome.tabs.sendMessage).not.toHaveBeenCalled();
  });

  it("sends credentials only to the recorded frame when its origin matches", async () => {
    await unlockWith([{ id: "bank", urls: ["https://bank.example"] }]);
    await send({ type: "FILL_TARGET" }, contentSender("https://login.bank.example/sso", 3, "doc-sso"));

    expect(await send({ type: "AUTOFILL", itemId: "bank", tabId: 1 })).toEqual({ ok: true });

    expect(env.chrome.tabs.sendMessage).toHaveBeenCalledTimes(1);
    expect(env.chrome.tabs.sendMessage).toHaveBeenCalledWith(
      1,
      expect.objectContaining({ type: "FILL_CREDENTIALS", origin: "https://login.bank.example" }),
      { frameId: 3, documentId: "doc-sso" },
    );
  });

  it("fills a non-matching top frame only after the user confirms that exact origin", async () => {
    await unlockWith([{ id: "bank", urls: ["https://bank.example"] }]);
    // No recorded frame: the top frame of tab 1 is https://top.example

    expect(await send({ type: "AUTOFILL", itemId: "bank", tabId: 1 })).toEqual({
      error: "origin_mismatch",
      origin: "https://top.example",
      confirmable: true,
    });
    expect(
      await send({ type: "AUTOFILL", itemId: "bank", tabId: 1, confirmedOrigin: "https://other.example" }),
    ).toMatchObject({ error: "origin_mismatch" });
    expect(env.chrome.tabs.sendMessage).not.toHaveBeenCalled();

    expect(
      await send({ type: "AUTOFILL", itemId: "bank", tabId: 1, confirmedOrigin: "https://top.example" }),
    ).toEqual({ ok: true });
    expect(env.chrome.tabs.sendMessage).toHaveBeenCalledWith(1, expect.anything(), { frameId: 0 });
  });
});

describe("WEBAUTHN_HAS_CREDENTIAL", () => {
  it("does not reveal passkeys for an rpId the asking page does not own", async () => {
    await unlockWith([
      {
        id: "pk",
        urls: ["https://bank.example"],
        passkey: {
          credentialIdB64u: "cred",
          rpId: "bank.example",
          userHandleB64u: "dXNlcg",
          userName: "alice",
          privateKeyPkcs8B64: "",
          signCount: 0,
          createdAt: "2026-01-01T00:00:00Z",
        },
      },
    ]);
    const probe = { type: "WEBAUTHN_HAS_CREDENTIAL", rpId: "bank.example", allowCredentialIdsB64u: [] };

    expect(await send(probe, contentSender("https://evil.example/"))).toEqual({ matches: false });
    expect(await send(probe, contentSender("https://bank.example/"))).toEqual({ matches: true });
  });
});

describe("auto-lock", () => {
  it("wipes keys and session token when the inactivity alarm fires", async () => {
    await unlockWith([]);
    expect(env.chrome.alarms.create).toHaveBeenCalledWith("autoLock", { delayInMinutes: 15 });

    for (const fn of env.alarmListeners) fn({ name: "autoLock" });
    await new Promise((r) => setTimeout(r, 0));

    expect(env.sessionStore["vaultSession"]).toBeUndefined();
    await startServiceWorker();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("locks as soon as the OS reports the screen locked", async () => {
    await unlockWith([]);

    for (const fn of env.idleListeners) fn("locked");
    await new Promise((r) => setTimeout(r, 0));

    expect(env.sessionStore["vaultSession"]).toBeUndefined();
    expect(await send({ type: "IS_UNLOCKED" })).toEqual({ unlocked: false });
  });

  it("uses the configured timeout", async () => {
    env.localStore["autoLockMinutes"] = 5;
    await unlockWith([]);
    expect(env.chrome.alarms.create).toHaveBeenCalledWith("autoLock", { delayInMinutes: 5 });
  });
});
