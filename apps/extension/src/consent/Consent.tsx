import { useEffect, useState } from "react";
import { Button, Spinner } from "@nopass/ui";
import type { ConsentRequest } from "../background/index";

/**
 * Passkey consent, shown in an extension-owned window the requesting page
 * cannot style or cover. What the user approves (site and action) comes from
 * the background, not from the URL that opened this window.
 */
export function Consent({ requestId }: { requestId: string }) {
  const [request, setRequest] = useState<ConsentRequest | null>(null);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    chrome.runtime
      .sendMessage({ type: "CONSENT_DETAILS", requestId })
      .then((resp: { request?: ConsentRequest }) => {
        if (resp?.request) setRequest(resp.request);
        else setExpired(true);
      })
      .catch(() => setExpired(true));
  }, [requestId]);

  async function answer(approved: boolean) {
    await chrome.runtime.sendMessage({ type: "CONSENT_RESULT", requestId, approved }).catch(() => {});
    window.close();
  }

  if (expired) {
    return <p className="p-4 text-ui text-muted">This request has expired. You can close this window.</p>;
  }
  if (!request) {
    return (
      <div role="status" className="flex h-32 items-center justify-center gap-2 text-ui text-muted">
        <Spinner /> Loading…
      </div>
    );
  }

  return (
    <main className="flex flex-col gap-3 p-4">
      <h1 className="text-h3 font-semibold text-fg">
        {request.kind === "create" ? "Save a passkey?" : "Sign in with a passkey?"}
      </h1>
      <p className="text-ui text-muted">
        {request.kind === "create"
          ? "nopwd will create a passkey for this site and store it in your vault."
          : "nopwd will sign in to this site with the passkey in your vault."}
      </p>
      <p className="break-all font-mono text-mono-sm text-fg">{request.origin}</p>
      <div className="flex justify-end gap-2">
        <Button variant="ghost" size="sm" onClick={() => answer(false)}>
          Not now
        </Button>
        <Button variant="primary" size="sm" autoFocus onClick={() => answer(true)}>
          Continue
        </Button>
      </div>
    </main>
  );
}
