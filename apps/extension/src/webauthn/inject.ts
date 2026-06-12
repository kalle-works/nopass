/**
 * MAIN-world script — wraps navigator.credentials.create/get so nopwd can act
 * as a platform authenticator for passkeys.
 *
 * Runs in the page's own JS world (no chrome.* access). Talks to the isolated
 * content script via window.postMessage; the content script shows the consent
 * overlay and relays to the background service worker, which holds the vault.
 *
 * Anything we can't or shouldn't handle (no publicKey options, conditional
 * mediation, locked vault, user decline, unsupported algorithms) falls back
 * to the browser's native implementation.
 */

interface RelayResponse {
  ok: boolean;
  /** true → silently use the native authenticator instead */
  fallback?: boolean;
  data?: Record<string, string>;
}

(() => {
  const nativeCreate = navigator.credentials.create.bind(navigator.credentials);
  const nativeGet = navigator.credentials.get.bind(navigator.credentials);

  // ── helpers ──
  const toB64u = (buf: ArrayBuffer | ArrayBufferView): string => {
    const bytes = ArrayBuffer.isView(buf)
      ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
      : new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const fromB64u = (b64u: string): ArrayBuffer => {
    const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const s = atob(padded);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out.buffer;
  };

  let nextReqId = 0;
  function relay(
    kind: "create" | "get",
    payload: unknown,
    signal?: AbortSignal | null,
  ): Promise<RelayResponse> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new DOMException("The operation was aborted.", "AbortError"));
        return;
      }
      const reqId = `nopwd-${Date.now()}-${nextReqId++}`;

      const cleanup = () => {
        window.clearTimeout(timeout);
        window.removeEventListener("message", onMessage);
        signal?.removeEventListener("abort", onAbort);
      };

      const timeout = window.setTimeout(() => {
        cleanup();
        resolve({ ok: false, fallback: true });
      }, 120_000);

      // Spec: an aborted WebAuthn call rejects with AbortError, no fallback
      const onAbort = () => {
        cleanup();
        reject(new DOMException("The operation was aborted.", "AbortError"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });

      function onMessage(e: MessageEvent) {
        const d = e.data;
        if (e.source !== window || !d || d.__nopwd !== true || d.dir !== "response" || d.reqId !== reqId) {
          return;
        }
        cleanup();
        resolve(d as RelayResponse);
      }

      window.addEventListener("message", onMessage);
      window.postMessage({ __nopwd: true, dir: "request", kind, reqId, payload }, window.location.origin);
    });
  }

  function clientDataJson(type: "webauthn.create" | "webauthn.get", challenge: BufferSource): string {
    return JSON.stringify({
      type,
      challenge: toB64u(challenge as ArrayBuffer),
      origin: window.location.origin,
      crossOrigin: false,
    });
  }

  function makeCredential(
    fields: Record<string, string>,
    cdj: string,
    kind: "create" | "get",
  ): Credential {
    const rawId = fromB64u(fields["credentialIdB64u"]!);
    const clientDataJSON = new TextEncoder().encode(cdj).buffer as ArrayBuffer;

    const base = {
      authenticatorAttachment: "platform" as const,
      id: fields["credentialIdB64u"]!,
      rawId,
      type: "public-key" as const,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };

    if (kind === "create") {
      const attestationObject = fromB64u(fields["attestationObjectB64u"]!);
      const authenticatorData = fromB64u(fields["authDataB64u"]!);
      const publicKey = fromB64u(fields["publicKeySpkiB64u"]!);
      const cred = {
        ...base,
        response: {
          clientDataJSON,
          attestationObject,
          getAuthenticatorData: () => authenticatorData,
          getPublicKey: () => publicKey,
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => ["hybrid", "internal"],
        },
        toJSON: () => ({
          id: base.id,
          rawId: base.id,
          type: "public-key",
          authenticatorAttachment: "platform",
          clientExtensionResults: { credProps: { rk: true } },
          response: {
            clientDataJSON: toB64u(clientDataJSON),
            attestationObject: fields["attestationObjectB64u"],
            authenticatorData: fields["authDataB64u"],
            publicKey: fields["publicKeySpkiB64u"],
            publicKeyAlgorithm: -7,
            transports: ["hybrid", "internal"],
          },
        }),
      };
      return cred as unknown as Credential;
    }

    const authenticatorData = fromB64u(fields["authDataB64u"]!);
    const signature = fromB64u(fields["signatureB64u"]!);
    const userHandle = fields["userHandleB64u"] ? fromB64u(fields["userHandleB64u"]) : null;
    const cred = {
      ...base,
      response: { clientDataJSON, authenticatorData, signature, userHandle },
      toJSON: () => ({
        id: base.id,
        rawId: base.id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          clientDataJSON: toB64u(clientDataJSON),
          authenticatorData: fields["authDataB64u"],
          signature: fields["signatureB64u"],
          userHandle: fields["userHandleB64u"] || null,
        },
      }),
    };
    return cred as unknown as Credential;
  }

  // ── create ──
  navigator.credentials.create = async function (
    options?: CredentialCreationOptions,
  ): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) return nativeCreate(options);

    // Only ES256 — if the RP doesn't accept it, let the platform handle it
    const algOk =
      !pk.pubKeyCredParams?.length || pk.pubKeyCredParams.some((p) => p.alg === -7);
    if (!algOk) return nativeCreate(options);

    try {
      const resp = await relay(
        "create",
        {
          rpId: pk.rp.id ?? window.location.hostname,
          rpName: pk.rp.name ?? "",
          userName: pk.user.name ?? "",
          userDisplayName: pk.user.displayName ?? "",
          userHandleB64u: toB64u(pk.user.id as ArrayBuffer),
          excludeCredentialIdsB64u: (pk.excludeCredentials ?? []).map((c) =>
            toB64u(c.id as ArrayBuffer),
          ),
        },
        options?.signal,
      );
      if (!resp.ok || !resp.data) return nativeCreate(options);
      return makeCredential(resp.data, clientDataJson("webauthn.create", pk.challenge), "create");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") throw err;
      return nativeCreate(options);
    }
  };

  // ── get ──
  navigator.credentials.get = async function (
    options?: CredentialRequestOptions,
  ): Promise<Credential | null> {
    const pk = options?.publicKey;
    // Conditional mediation drives the browser's own autofill UI — pass through
    if (!pk || options?.mediation === "conditional") return nativeGet(options);

    const cdj = clientDataJson("webauthn.get", pk.challenge);
    try {
      const resp = await relay(
        "get",
        {
          rpId: pk.rpId ?? window.location.hostname,
          clientDataJSONB64u: toB64u(new TextEncoder().encode(cdj)),
          allowCredentialIdsB64u: (pk.allowCredentials ?? []).map((c) =>
            toB64u(c.id as ArrayBuffer),
          ),
        },
        options?.signal,
      );
      if (!resp.ok || !resp.data) return nativeGet(options);
      return makeCredential(resp.data, cdj, "get");
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") throw err;
      return nativeGet(options);
    }
  };
})();
