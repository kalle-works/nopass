// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from "vitest";
import { b64uToBytes, bytesToB64u, generateCredential } from "@nopass/crypto";
import {
  UNLOCK_MSG,
  chromeMock,
  consentRequestId,
  consentSender,
  contentSender,
  env,
  resetEnvironment,
  send,
  serveLogins,
} from "./background-harness";

/**
 * Requirements:
 * - What a passkey signs is client data the background built from the
 *   browser-set sender origin; the page supplies only the challenge.
 * - Nothing is signed without a yes in the extension-owned consent window;
 *   a page cannot answer for it, and closing it declines.
 * - Locking revokes the session on the server, and still locks offline.
 */

const PAGE = "https://bank.example/login";
const CHALLENGE = bytesToB64u(new Uint8Array(32).fill(9));

let publicKeySpki: Uint8Array<ArrayBuffer>;
const ITEM_ID = "6f1c2b9e-1d1a-4f3e-9c55-7b2d4c8a9e01";

beforeEach(async () => {
  await resetEnvironment();
  const cred = await generateCredential();
  publicKeySpki = new Uint8Array(cred.publicKeySpki);
  await serveLogins([
    {
      id: ITEM_ID,
      passkey: {
        credentialIdB64u: "cred",
        rpId: "bank.example",
        userHandleB64u: "dXNlcg",
        userName: "alice",
        privateKeyPkcs8B64: btoa(String.fromCharCode(...cred.privateKeyPkcs8)),
        signCount: 0,
        createdAt: "2026-01-01T00:00:00Z",
      },
    },
  ]);
  expect(await send(UNLOCK_MSG)).toEqual({ ok: true });
  // The signCount update after signing
  const fetchMock = vi.mocked(fetch);
  const base = fetchMock.getMockImplementation()!;
  fetchMock.mockImplementation(async (url, init) =>
    init?.method === "PUT" || String(url).endsWith(`/items/${ITEM_ID}`)
      ? new Response(JSON.stringify({ version: 2, updatedAt: "2026-01-02T00:00:00Z" }), { status: 200 })
      : base(url, init),
  );
});

function getAssertion(extra: Record<string, unknown> = {}) {
  return send(
    { type: "WEBAUTHN_GET", rpId: "bank.example", challengeB64u: CHALLENGE, allowCredentialIdsB64u: [], ...extra },
    contentSender(PAGE),
  );
}

/** DER ECDSA signature → raw r||s, as WebCrypto verifies it. */
function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const rLen = der[3]!;
  const r = der.slice(4, 4 + rLen);
  const s = der.slice(6 + rLen);
  const pad = (n: Uint8Array) => {
    const out = new Uint8Array(32);
    const trimmed = n.slice(Math.max(0, n.length - 32));
    out.set(trimmed, 32 - trimmed.length);
    return out;
  };
  return new Uint8Array([...pad(r), ...pad(s)]);
}

describe("passkey assertion", () => {
  it("signs client data built from the sender origin, ignoring page-supplied client data", async () => {
    const forged = bytesToB64u(
      new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: CHALLENGE, origin: "https://evil.example" })),
    );
    const pending = getAssertion({ clientDataJSONB64u: forged });
    await send({ type: "CONSENT_RESULT", requestId: await consentRequestId(), approved: true }, consentSender(await consentRequestId()));
    const { data } = await pending;

    const clientDataJSON = b64uToBytes(data.clientDataJSONB64u);
    expect(JSON.parse(new TextDecoder().decode(clientDataJSON))).toEqual({
      type: "webauthn.get",
      challenge: CHALLENGE,
      origin: "https://bank.example",
      crossOrigin: false,
    });

    const key = await crypto.subtle.importKey("spki", publicKeySpki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const authData = b64uToBytes(data.authDataB64u);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
    const signed = new Uint8Array([...authData, ...hash]);
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      derToRaw(b64uToBytes(data.signatureB64u)),
      signed,
    );
    expect(valid).toBe(true);
  });

  it("refuses a challenge shorter than 16 bytes without asking the user", async () => {
    expect(await getAssertion({ challengeB64u: bytesToB64u(new Uint8Array(8)) })).toEqual({ error: "invalid challenge" });
    expect(chromeMock().windows.create).not.toHaveBeenCalled();
  });
});

describe("passkey consent", () => {
  it("cannot be answered by a content script", async () => {
    const pending = getAssertion();
    const requestId = await consentRequestId();

    expect(
      await send({ type: "CONSENT_RESULT", requestId, approved: true }, contentSender(PAGE)),
    ).toEqual({ error: "unauthorized" });

    // Still waiting for the real window; closing it declines
    for (const fn of env.windowRemovedListeners) fn(99);
    expect(await pending).toEqual({ error: "declined" });
  });
});

describe("lock", () => {
  it("revokes the session server-side, and still locks when that request fails", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async () => {
      throw new TypeError("Failed to fetch"); // offline
    });

    expect(await send({ type: "LOCK" })).toEqual({ ok: true });
    expect(env.sessionStore["vaultSession"]).toBeUndefined();

    const logout = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/auth/logout"));
    expect(logout).toBeDefined();
    expect(new Headers(logout![1]?.headers).get("Authorization")).toBe("Bearer token-1");
  });
});
