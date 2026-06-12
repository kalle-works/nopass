"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { importShareKey, decryptSharePayload } from "@nopass/crypto";
import type { VaultItemPlaintext } from "@nopass/types";
import { api } from "@/lib/api";

type State =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; item: VaultItemPlaintext; remainingViews: number };

function SecretRow({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  const [revealed, setRevealed] = useState(!secret);
  const [copied, setCopied] = useState(false);

  if (!value) return null;

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div>
      <p className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <p className="flex-1 font-mono text-sm text-[#F4F1E8] break-all">
          {revealed ? value : "••••••••••••"}
        </p>
        {secret && (
          <button
            onClick={() => setRevealed((r) => !r)}
            className="px-2 py-1 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] border border-[#2B2923] transition-colors shrink-0"
          >
            {revealed ? "Hide" : "Show"}
          </button>
        )}
        <button
          onClick={copy}
          className="px-2 py-1 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] border border-[#2B2923] transition-colors shrink-0"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function ItemFields({ item }: { item: VaultItemPlaintext }) {
  switch (item.type) {
    case "login":
      return (
        <>
          <SecretRow label="Username" value={item.username} />
          <SecretRow label="Password" value={item.password} secret />
          {item.urls[0] && <SecretRow label="URL" value={item.urls[0]} />}
          {item.notes && <SecretRow label="Notes" value={item.notes} />}
        </>
      );
    case "note":
      return <SecretRow label="Content" value={item.content} />;
    case "card":
      return (
        <>
          <SecretRow label="Cardholder" value={item.cardholderName} />
          <SecretRow label="Number" value={item.number} secret />
          <SecretRow label="Expiry" value={`${item.expMonth}/${item.expYear}`} />
          <SecretRow label="CVV" value={item.cvv} secret />
          {item.notes && <SecretRow label="Notes" value={item.notes} />}
        </>
      );
    case "identity":
      return (
        <>
          <SecretRow label="Name" value={`${item.firstName} ${item.lastName}`.trim()} />
          <SecretRow label="Email" value={item.email} />
          <SecretRow label="Phone" value={item.phone} />
          <SecretRow label="Address" value={[item.address, item.city, item.country].filter(Boolean).join(", ")} />
          {item.notes && <SecretRow label="Notes" value={item.notes} />}
        </>
      );
    case "ssh_key":
      return (
        <>
          <SecretRow label="Private key" value={item.privateKey} secret />
          {item.publicKey && <SecretRow label="Public key" value={item.publicKey} />}
          {item.passphrase && <SecretRow label="Passphrase" value={item.passphrase} secret />}
          {item.notes && <SecretRow label="Notes" value={item.notes} />}
        </>
      );
  }
}

export default function ShareViewPage() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const keyB64url = new URLSearchParams(window.location.hash.slice(1)).get("k");
        if (!keyB64url) {
          throw new Error("This link is missing its decryption key — make sure you copied the whole URL.");
        }
        const key = await importShareKey(keyB64url);
        const resp = await api.shares.view(params.id);
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
              ? "This share doesn't exist anymore — it may have expired, been viewed already, or been revoked."
              : msg.toLowerCase().includes("operation") || msg.toLowerCase().includes("decrypt")
                ? "The link's decryption key doesn't match. Make sure you copied the whole URL."
                : msg,
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [params.id]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#070706] px-4 py-12">
      <div className="mb-8">
        <span className="font-mono text-sm font-semibold text-[#F4F1E8] tracking-tight">nopwd</span>
      </div>

      <div className="w-full max-w-md">
        <div className="bg-[#11110F] border border-[#2B2923] p-8">
          {state.status === "loading" && (
            <div className="flex flex-col items-center gap-4 py-8">
              <div className="w-8 h-8 border-2 border-[#2B2923] border-t-[#D6FF3F] animate-spin" />
              <p className="font-mono text-xs text-[#9C988D]">Decrypting on this device…</p>
            </div>
          )}

          {state.status === "error" && (
            <>
              <h1 className="font-mono text-lg font-semibold text-[#F4F1E8] mb-2">Nothing here</h1>
              <p className="text-sm text-[#9C988D]">{state.message}</p>
            </>
          )}

          {state.status === "ready" && (
            <>
              <h1 className="font-mono text-lg font-semibold text-[#F4F1E8] mb-1">
                {state.item.name}
              </h1>
              <p className="text-xs text-[#9C988D] mb-6">
                Someone shared this with you via nopwd.
                {state.remainingViews === 0
                  ? " This was the last view — the link is now dead."
                  : ` The link works ${state.remainingViews} more time${state.remainingViews === 1 ? "" : "s"}.`}
              </p>
              <div className="space-y-4">
                <ItemFields item={state.item} />
              </div>
              <p className="mt-6 pt-4 border-t border-[#2B2923] text-xs text-[#9C988D]">
                Copy what you need now and store it somewhere safe — like a{" "}
                <a href="/register" className="text-[#D6FF3F] hover:underline underline-offset-2">
                  free nopwd vault
                </a>
                .
              </p>
            </>
          )}
        </div>

        <div className="mt-4 flex items-center justify-center gap-1.5 text-xs text-[#9C988D]">
          <span className="font-mono">Decrypted in your browser · the server never sees the key</span>
        </div>
      </div>
    </div>
  );
}
