// @vitest-environment happy-dom
import { describe, it, expect, beforeEach } from "vitest";
import { chromeMock, contentSender, env, resetEnvironment, send, serveLogins, UNLOCK_MSG } from "./background-harness";

/**
 * Contract between the isolated-world relay and the background: with the
 * vault unlocked and a passkey for the page's own rpId, a WebAuthn request
 * must reach the consent overlay instead of falling back to the browser.
 * The relay runs against the real background listener, with the sender a
 * content script in this page.
 */

const PAGE_URL = `${window.location.origin}/`;
const RP_ID = window.location.hostname;

beforeEach(async () => {
  await resetEnvironment();
  document.body.innerHTML = "";
  chromeMock().runtime = {
    ...(chromeMock().runtime as object),
    sendMessage: (msg: unknown) => send(msg, contentSender(PAGE_URL)),
  };
  const { initWebauthnRelay } = await import("../webauthn/relay");
  initWebauthnRelay();
});

/** Posts a request as the MAIN-world interceptor would; resolves with the relay's response, if any. */
function request(kind: "create" | "get", payload: Record<string, unknown>) {
  const reqId = `req-${Math.random()}`;
  const response = new Promise<Record<string, unknown>>((resolve) => {
    window.addEventListener("message", (e) => {
      if (e.data?.dir === "response" && e.data.reqId === reqId) resolve(e.data);
    });
  });
  // Dispatched directly: happy-dom's postMessage does not set event.source,
  // which the relay checks to reject messages from other windows
  window.dispatchEvent(
    new MessageEvent("message", {
      data: { __nopwd: true, dir: "request", kind, reqId, payload },
      source: window,
      origin: window.location.origin,
    }),
  );
  return response;
}

async function consentShown(): Promise<boolean> {
  for (let i = 0; i < 50; i++) {
    if (document.body.children.length > 0) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return false;
}

describe("WebAuthn relay pre-checks", () => {
  it("offers the vault's passkey when unlocked", async () => {
    await serveLogins([
      {
        id: "pk",
        passkey: {
          credentialIdB64u: "cred",
          rpId: RP_ID,
          userHandleB64u: "dXNlcg",
          userName: "alice",
          privateKeyPkcs8B64: "",
          signCount: 0,
          createdAt: "2026-01-01T00:00:00Z",
        },
      },
    ]);
    await send(UNLOCK_MSG);

    void request("get", { rpId: RP_ID, clientDataJSONB64u: "", allowCredentialIdsB64u: [] });
    expect(await consentShown()).toBe(true);
  });

  it("offers to save a passkey when unlocked", async () => {
    await send(UNLOCK_MSG);

    void request("create", { rpId: RP_ID });
    expect(await consentShown()).toBe(true);
  });

  it("falls back to the browser without an overlay when locked", async () => {
    expect(await request("create", { rpId: RP_ID })).toMatchObject({ ok: false, fallback: true });
    expect(document.body.children.length).toBe(0);
  });

  it("falls back for an rpId the page does not own", async () => {
    await send(UNLOCK_MSG);
    expect(await request("create", { rpId: "bank.example" })).toMatchObject({ ok: false, fallback: true });
    expect(env.sessionStore["vaultSession"]).toBeDefined();
    expect(document.body.children.length).toBe(0);
  });
});
