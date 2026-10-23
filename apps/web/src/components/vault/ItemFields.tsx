"use client";

import { useEffect, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import type { CardItem, IdentityItem, LoginItem, NoteItem, SshKeyItem, VaultItemPlaintext } from "@nopass/types";
import { IconButton, SecretRow, computeTotp, cx, useCopyFeedback } from "@nopass/ui";
import { safeHttpUrl } from "@/lib/safe-url";

type CopyFn = (text: string) => Promise<boolean>;

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cx("overflow-hidden rounded-lg border border-divider bg-surface", className)}>{children}</div>
  );
}

/** A labelled value without copy controls (passkey status, notes). */
function InfoRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-divider px-4 py-3 last:border-b-0">
      <span className="text-meta text-muted">{label}</span>
      <div className="text-ui text-fg">{children}</div>
    </div>
  );
}

function LinkRow({ urls, copy }: { urls: string[]; copy: CopyFn }) {
  const { copied, copy: doCopy } = useCopyFeedback(copy);
  return (
    <div className="flex flex-col gap-1 border-b border-divider px-4 py-3 last:border-b-0">
      <span className="text-meta text-muted">Website</span>
      {urls.map((url, i) => {
        const href = safeHttpUrl(url);
        return (
          <div key={url} className="flex min-h-8 items-center gap-2">
            {href ? (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="min-w-0 flex-1 break-all text-ui text-accent-text hover:underline"
              >
                {url}
              </a>
            ) : (
              <span className="min-w-0 flex-1 break-all text-ui text-fg">{url}</span>
            )}
            {i === 0 && (
              <IconButton label={copied ? "Copied" : "Copy Website"} onClick={() => doCopy(url)}>
                {copied ? <Check aria-hidden className="size-4 text-success" /> : <Copy aria-hidden className="size-4" />}
              </IconButton>
            )}
          </div>
        );
      })}
    </div>
  );
}

function TotpRow({ uri, copy }: { uri: string; copy: CopyFn }) {
  const [result, setResult] = useState<{ code: string; remainingSeconds: number; period: number } | null>(null);

  useEffect(() => {
    let cancelled = false;
    let intervalId: ReturnType<typeof setInterval> | null = null;

    async function tick() {
      const r = await computeTotp(uri);
      if (!cancelled) setResult(r);
    }

    tick();
    // Align ticks to wall-clock seconds so the countdown matches the authenticator
    const timeoutId = setTimeout(() => {
      tick();
      intervalId = setInterval(tick, 1000);
    }, 1000 - (Date.now() % 1000));

    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
      if (intervalId !== null) clearInterval(intervalId);
    };
  }, [uri]);

  if (!result) return null;

  const { code, remainingSeconds, period } = result;
  const urgent = remainingSeconds <= 5;
  const radius = 9;
  const circumference = 2 * Math.PI * radius;

  return (
    <SecretRow
      label="One-time code"
      value={code}
      copy={copy}
      renderValue={(c) => (
        <span className="font-mono text-h3 tabular-nums tracking-wide text-fg">
          {c.slice(0, 3)} {c.slice(3)}
        </span>
      )}
      trailing={
        <span className="mr-1 flex items-center gap-1.5">
          <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden className="shrink-0">
            <circle cx="12" cy="12" r={radius} fill="none" stroke="currentColor" strokeWidth="2" className="text-divider" />
            <circle
              cx="12"
              cy="12"
              r={radius}
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - remainingSeconds / period)}
              strokeLinecap="round"
              transform="rotate(-90 12 12)"
              className={cx("transition-[stroke-dashoffset] duration-1000 ease-linear", urgent ? "text-danger" : "text-icon")}
            />
          </svg>
          <span className={cx("w-7 text-mono-sm tabular-nums", urgent ? "text-danger" : "text-muted")}>
            {remainingSeconds}s
          </span>
        </span>
      }
    />
  );
}

function LoginFields({
  login,
  copy,
  reusedElsewhere,
  breachCount,
}: {
  login: LoginItem;
  copy: CopyFn;
  reusedElsewhere: number;
  breachCount: number;
}) {
  const warnings: string[] = [];
  if (reusedElsewhere > 0) warnings.push(`Reused on ${reusedElsewhere} other ${reusedElsewhere === 1 ? "item" : "items"}`);
  if (breachCount > 0) warnings.push(`Found in ${breachCount.toLocaleString()} known data breaches`);

  return (
    <Panel>
      {login.username && <SecretRow label="Username" value={login.username} copy={copy} />}
      {login.password && (
        <SecretRow
          label="Password"
          value={login.password}
          concealed
          copy={copy}
          warning={warnings.length > 0 ? warnings.join(". ") + "." : undefined}
        />
      )}
      {login.totp && <TotpRow uri={login.totp} copy={copy} />}
      {login.passkey && (
        <InfoRow label="Passkey">
          Saved for <span className="font-mono">{login.passkey.rpId}</span>
          <span className="block text-meta text-muted">
            {login.passkey.userName && `${login.passkey.userName} · `}
            created {new Date(login.passkey.createdAt).toLocaleDateString()} · sign in through the browser extension
          </span>
        </InfoRow>
      )}
      {login.urls && login.urls.length > 0 && <LinkRow urls={login.urls} copy={copy} />}
      {login.customFields?.map((field, i) => (
        <SecretRow
          key={i}
          label={field.name || `Field ${i + 1}`}
          value={field.value}
          concealed={field.fieldType === "hidden"}
          copy={copy}
        />
      ))}
      {login.notes && (
        <InfoRow label="Notes">
          <span className="whitespace-pre-wrap break-words">{login.notes}</span>
        </InfoRow>
      )}
    </Panel>
  );
}

function NoteFields({ note, copy }: { note: NoteItem; copy: CopyFn }) {
  return (
    <Panel>
      <SecretRow
        label="Content"
        value={note.content}
        copy={copy}
        renderValue={(c) => <span className="block whitespace-pre-wrap break-words leading-relaxed">{c}</span>}
      />
    </Panel>
  );
}

function CardFields({ card, copy }: { card: CardItem; copy: CopyFn }) {
  return (
    <Panel>
      {card.cardholderName && <SecretRow label="Cardholder" value={card.cardholderName} copy={copy} />}
      {card.number && <SecretRow label="Card number" value={card.number} concealed copy={copy} />}
      {(card.expMonth || card.expYear) && (
        <SecretRow label="Expiry" value={`${card.expMonth}/${card.expYear}`} mono copy={copy} />
      )}
      {card.cvv && <SecretRow label="CVV" value={card.cvv} concealed copy={copy} />}
      {card.notes && (
        <InfoRow label="Notes">
          <span className="whitespace-pre-wrap break-words">{card.notes}</span>
        </InfoRow>
      )}
    </Panel>
  );
}

function IdentityFields({ identity, copy }: { identity: IdentityItem; copy: CopyFn }) {
  const fields: Array<[string, string | undefined]> = [
    ["First name", identity.firstName],
    ["Last name", identity.lastName],
    ["Email", identity.email],
    ["Phone", identity.phone],
    ["Address", identity.address],
    ["City", identity.city],
    ["Country", identity.country],
  ];
  return (
    <Panel>
      {fields
        .filter(([, v]) => v)
        .map(([label, value]) => (
          <SecretRow key={label} label={label} value={value!} copy={copy} />
        ))}
    </Panel>
  );
}

function SshKeyFields({ sshKey, copy }: { sshKey: SshKeyItem; copy: CopyFn }) {
  return (
    <Panel>
      {sshKey.publicKey && <SecretRow label="Public key" value={sshKey.publicKey} mono copy={copy} />}
      <SecretRow label="Private key" value={sshKey.privateKey} concealed copy={copy} />
      {sshKey.passphrase && <SecretRow label="Passphrase" value={sshKey.passphrase} concealed copy={copy} />}
      {sshKey.comment && <SecretRow label="Comment" value={sshKey.comment} mono copy={copy} />}
      {sshKey.notes && (
        <InfoRow label="Notes">
          <span className="whitespace-pre-wrap break-words">{sshKey.notes}</span>
        </InfoRow>
      )}
    </Panel>
  );
}

export function ItemFields({
  plaintext,
  copy,
  reusedElsewhere,
  breachCount,
}: {
  plaintext: VaultItemPlaintext;
  copy: CopyFn;
  reusedElsewhere: number;
  breachCount: number;
}) {
  switch (plaintext.type) {
    case "login":
      return (
        <LoginFields
          login={plaintext as LoginItem}
          copy={copy}
          reusedElsewhere={reusedElsewhere}
          breachCount={breachCount}
        />
      );
    case "note":
      return <NoteFields note={plaintext as NoteItem} copy={copy} />;
    case "card":
      return <CardFields card={plaintext as CardItem} copy={copy} />;
    case "identity":
      return <IdentityFields identity={plaintext as IdentityItem} copy={copy} />;
    case "ssh_key":
      return <SshKeyFields sshKey={plaintext as SshKeyItem} copy={copy} />;
    default:
      return null;
  }
}
