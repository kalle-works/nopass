"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { importShareKey, decryptSharePayload } from "@nopass/crypto";
import type { VaultItemPlaintext } from "@nopass/types";
import { AuthShell, Banner, Spinner, SecretRow } from "@nopass/ui";
import { api } from "@/lib/api";
import { AuthFooter } from "@/components/auth/auth-footer";
import { copySecret } from "@/components/auth/clipboard";

type State =
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
  const [state, setState] = useState<State>({ status: "loading" });
  // Re-read the fragment when it changes (e.g. a second share link opened in
  // the same tab) — parsing only on mount would decrypt with a stale key
  const [hash, setHash] = useState<string | null>(null);

  useEffect(() => {
    const update = () => setHash(window.location.hash);
    update();
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);

  useEffect(() => {
    if (hash === null) return;
    let cancelled = false;
    (async () => {
      try {
        const keyB64url = new URLSearchParams(hash.slice(1)).get("k");
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
        if (!cancelled) {
          setState({ status: "ready", item, remainingViews: resp.remainingViews });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (!cancelled) {
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
    })();
    return () => {
      cancelled = true;
    };
  }, [params.id, hash]);

  return (
    <AuthShell homeHref="/" footer={<AuthFooter />}>
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
