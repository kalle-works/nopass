/**
 * Isolated-world relay between the MAIN-world WebAuthn interceptor and the
 * background service worker. The background asks for consent in its own
 * window: credential creation and assertions never happen without a click on
 * UI the page cannot reach.
 */

interface RelayRequest {
  __nopwd: true;
  dir: "request";
  kind: "create" | "get";
  reqId: string;
  payload: Record<string, unknown>;
}

function respond(reqId: string, body: Record<string, unknown>): void {
  window.postMessage({ __nopwd: true, dir: "response", reqId, ...body }, window.location.origin);
}

// One request at a time per frame — a hostile page could otherwise spam
// postMessage and stack consent windows
let requestInFlight = false;

export function initWebauthnRelay(): void {
  window.addEventListener("message", async (e: MessageEvent) => {
    const d = e.data as RelayRequest;
    if (e.source !== window || !d || d.__nopwd !== true || d.dir !== "request") return;

    if (requestInFlight) {
      respond(d.reqId, { ok: false, fallback: true });
      return;
    }
    requestInFlight = true;
    try {
      // Skip the consent window entirely unless the vault is unlocked and can serve
      // this rpId. (IS_UNLOCKED is no use here: it reports locked to web pages.)
      const usable =
        d.kind === "get"
          ? (
              await chrome.runtime.sendMessage({
                type: "WEBAUTHN_HAS_CREDENTIAL",
                rpId: d.payload["rpId"],
                allowCredentialIdsB64u: d.payload["allowCredentialIdsB64u"],
              })
            )?.matches === true
          : (await chrome.runtime.sendMessage({ type: "WEBAUTHN_AVAILABLE", rpId: d.payload["rpId"] }))
              ?.available === true;
      if (!usable) {
        respond(d.reqId, { ok: false, fallback: true });
        return;
      }

      // Consent happens in an extension-owned window opened by the
      // background, out of reach of this page's DOM and styles
      const result = await chrome.runtime.sendMessage({
        type: d.kind === "create" ? "WEBAUTHN_CREATE" : "WEBAUTHN_GET",
        ...d.payload,
      });

      if (result?.error || !result?.data) {
        respond(d.reqId, { ok: false, fallback: true });
      } else {
        respond(d.reqId, { ok: true, data: result.data });
      }
    } catch {
      respond(d.reqId, { ok: false, fallback: true });
    } finally {
      requestInFlight = false;
    }
  });
}
