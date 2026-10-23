"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { importShareKey, decryptSharePayload } from "@nopass/crypto";
import type { VaultItemPlaintext } from "@nopass/types";
import { AuthShell, Banner, Button, Spinner, SecretRow } from "@nopass/ui";
import { api } from "@/lib/api";
import { takeShareKey } from "@/lib/share-key";
import { AuthFooter } from "@/components/auth/auth-footer";
import { copySecret } from "@/components/auth/clipboard";

type State =
  | { status: "gate" }
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; item: VaultItemPlaintext; remainingViews: number };

function Row({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  if (!value) return null;
  return (
    <SecretRow
      label={label}
      value={value}
      concealed={secret}
      mono={secret || label === "URL"}
      copy={copySecret}
      {...(!secret && {
        renderValue: (v: string) => <span className="whitespace-pre-wrap break-words">{v}</span>,
      })}
    />
  );
}

function ItemFields({ item }: { item: VaultItemPlaintext }) {
  switch (item.type) {
    case "login":
      return (
        <>
          <Row label="Username" value={item.username} />
          <Row label="Password" value={item.password} secret />
          {item.urls[0] && <Row label="URL" value={item.urls[0]} />}
          {item.notes && <Row label="Notes" value={item.notes} />}
        </>
      );
    case "note":
      return <Row label="Content" value={item.content} />;
    case "card":
      return (
        <>
          <Row label="Cardholder" value={item.cardholderName} />
          <Row label="Number" value={item.number} secret />
          <Row label="Expiry" value={`${item.expMonth}/${item.expYear}`} />
          <Row label="CVV" value={item.cvv} secret />
          {item.notes && <Row label="Notes" value={item.notes} />}
        </>
      );
    case "identity":
      return (
        <>
          <Row label="Name" value={`${item.firstName} ${item.lastName}`.trim()} />
          <Row label="Email" value={item.email} />
          <Row label="Phone" value={item.phone} />
          <Row label="Address" value={[item.address, item.city, item.country].filter(Boolean).join(", ")} />
          {item.notes && <Row label="Notes" value={item.notes} />}
        </>
      );
    case "ssh_key":
      return (
        <>
          <Row label="Private key" value={item.privateKey} secret />
          {item.publicKey && <Row label="Public key" value={item.publicKey} />}
          {item.passphrase && <Row label="Passphrase" value={item.passphrase} secret />}
          {item.notes && <Row label="Notes" value={item.notes} />}
        </>
      );
  }
}

export default function ShareViewPage() {
  const params = useParams<{ id: string }>();
  // Nothing is fetched until the recipient clicks: link scanners and chat
  // unfurlers that render the page must not burn one of the share's views.
  const [state, setState] = useState<State>({ status: "gate" });

  // The key leaves the address bar as soon as the page has it; it is kept
  // here for the reveal click and for a retry after a network error
  const keyRef = useRef<string | null>(null);

  // A different fragment (e.g. a second share link opened in the same tab)
  // means a different key, so go back to the gate instead of reusing state
  useEffect(() => {
    keyRef.current ??= takeShareKey(window);
    const onHashChange = () => {
      keyRef.current = takeShareKey(window);
      setState({ status: "gate" });
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  async function reveal() {
    setState({ status: "loading" });
    try {
      const keyB64url = keyRef.current;
      if (!keyB64url) {
        throw new Error("This link is missing its decryption key. Make sure you copied the whole URL.");
      }
      const key = await importShareKey(keyB64url);
      const resp = await api.shares.view(params.id);
      // blobMac is unused for shares — AES-GCM's own auth tag covers
      // integrity; the separate HMAC only exists for vault items
      const item = await decryptSharePayload(
        { blob: resp.blob, blobIv: resp.blobIv, blobMac: "" },
        key,
      );
      setState({ status: "ready", item, remainingViews: resp.remainingViews });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setState({
        status: "error",
        message: msg.includes("404") || msg.toLowerCase().includes("not found")
          ? "This share doesn't exist anymore. It may have expired, been viewed already, or been revoked."
          : msg.toLowerCase().includes("operation") || msg.toLowerCase().includes("decrypt")
            ? "The link's decryption key doesn't match, and this attempt used one of the link's views. Ask the sender to check the URL or share again."
            : msg,
      });
    }
  }

  return (
    <AuthShell homeHref="/" footer={<AuthFooter />}>
      {state.status === "gate" && (
        <>
          <h1 className="text-h1 font-semibold text-fg">Someone shared a secret with you</h1>
          <p className="mt-2 text-body text-muted">
            Revealing it uses one of the link&apos;s limited views. Open it only when you are ready to copy what you need.
          </p>
          <Button className="mt-6" onClick={reveal}>
            Reveal secret
          </Button>
        </>
      )}

      {state.status === "loading" && (
        <div role="status" className="flex items-center gap-3 text-body text-muted">
          <Spinner />
          Decrypting on this device…
        </div>
      )}

      {state.status === "error" && (
        <>
          <h1 className="text-h1 font-semibold text-fg">This link doesn&apos;t work</h1>
          <Banner tone="danger" className="mt-6">
            {state.message}
          </Banner>
        </>
      )}

      {state.status === "ready" && (
        <>
          <h1 className="break-words text-h1 font-semibold text-fg">{state.item.name}</h1>
          <p className="mt-2 text-body text-muted">
            Shared with you through nopwd.{" "}
            {state.remainingViews === 0
              ? "This was the last view. The link no longer works."
              : `The link works ${state.remainingViews} more time${state.remainingViews === 1 ? "" : "s"}.`}
          </p>
          <div className="mt-6 overflow-hidden rounded-lg border border-divider bg-surface">
            <ItemFields item={state.item} />
          </div>
          <p className="mt-6 text-ui text-muted">
            Copy what you need now. To keep it, save it in{" "}
            <a href="/register" className="rounded-sm text-accent-text underline-offset-2 hover:underline">
              your own vault
            </a>
            . The key for this link is in the part of the URL after the #, which your browser never sends to the server.
          </p>
        </>
      )}
    </AuthShell>
  );
}
