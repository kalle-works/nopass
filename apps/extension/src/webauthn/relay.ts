/**
 * Isolated-world relay between the MAIN-world WebAuthn interceptor and the
 * background service worker. Shows the consent overlay — credential creation
 * and assertions never happen without a trusted user gesture on our UI.
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

/** Trusted-click consent overlay. Resolves true only on a real user click. */
function askConsent(title: string, detail: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.style.cssText =
      "position:fixed;inset:0;z-index:2147483647;display:flex;align-items:flex-start;justify-content:center;pointer-events:none";
    const shadow = host.attachShadow({ mode: "closed" });

    const card = document.createElement("div");
    card.style.cssText = [
      "pointer-events:auto",
      "margin-top:24px",
      "background:#11110F",
      "border:1px solid #2B2923",
      "padding:16px 20px",
      "max-width:360px",
      "font-family:ui-monospace,Menlo,monospace",
      "box-shadow:0 8px 32px rgba(0,0,0,.5)",
    ].join(";");

    const h = document.createElement("p");
    h.textContent = title;
    h.style.cssText = "margin:0 0 4px;font-size:13px;font-weight:600;color:#F4F1E8";
    const p = document.createElement("p");
    p.textContent = detail;
    p.style.cssText = "margin:0 0 12px;font-size:12px;color:#9C988D";

    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;justify-content:flex-end";

    const no = document.createElement("button");
    no.textContent = "Not now";
    no.style.cssText =
      "padding:6px 12px;font-size:12px;background:transparent;border:1px solid #2B2923;color:#9C988D;cursor:pointer;font-family:inherit";
    const yes = document.createElement("button");
    yes.textContent = "Continue";
    yes.style.cssText =
      "padding:6px 12px;font-size:12px;background:#D6FF3F;border:none;color:#070706;font-weight:600;cursor:pointer;font-family:inherit";

    const done = (result: boolean) => {
      host.remove();
      resolve(result);
    };
    // isTrusted gate: page JS can dispatch synthetic clicks but cannot forge
    // a trusted event — consent requires a real user gesture
    yes.addEventListener("click", (e) => { if (e.isTrusted) done(true); });
    no.addEventListener("click", (e) => { if (e.isTrusted) done(false); });

    row.append(no, yes);
    card.append(h, p, row);

    const brand = document.createElement("p");
    brand.textContent = "nopwd";
    brand.style.cssText = "margin:10px 0 0;font-size:10px;letter-spacing:.1em;color:#9C988D";
    card.append(brand);

    shadow.append(card);
    (document.body ?? document.documentElement).append(host);

    // Auto-dismiss with the request timeout horizon
    window.setTimeout(() => { if (host.isConnected) done(false); }, 115_000);
  });
}

export function initWebauthnRelay(): void {
  window.addEventListener("message", async (e: MessageEvent) => {
    const d = e.data as RelayRequest;
    if (e.source !== window || !d || d.__nopwd !== true || d.dir !== "request") return;

    const host = window.location.hostname;
    try {
      // Cheap pre-check: skip the overlay entirely when the vault is locked
      const status = await chrome.runtime.sendMessage({ type: "IS_UNLOCKED" });
      if (!status?.unlocked) {
        respond(d.reqId, { ok: false, fallback: true });
        return;
      }

      if (d.kind === "get") {
        // Ask the background whether we even hold a matching credential
        // before bothering the user
        const probe = await chrome.runtime.sendMessage({
          type: "WEBAUTHN_HAS_CREDENTIAL",
          rpId: d.payload["rpId"],
          allowCredentialIdsB64u: d.payload["allowCredentialIdsB64u"],
        });
        if (!probe?.matches) {
          respond(d.reqId, { ok: false, fallback: true });
          return;
        }
      }

      const approved = await askConsent(
        d.kind === "create" ? `Save a passkey for ${host}?` : `Sign in to ${host}?`,
        d.kind === "create"
          ? "nopwd will create and store a passkey in your vault."
          : `Use the passkey in your nopwd vault${d.kind === "get" ? "" : ""}.`,
      );
      if (!approved) {
        respond(d.reqId, { ok: false, fallback: true });
        return;
      }

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
    }
  });
}
