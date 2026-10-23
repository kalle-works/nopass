import { Section } from "./container";

interface Row {
  term: string;
  detail: string;
}

const STAYS_ON_DEVICE: Row[] = [
  { term: "Master password", detail: "Used locally to derive keys and to prove you know it. It is never sent." },
  {
    term: "Master key and vault keys",
    detail: "Derived with Argon2id (64 MiB, 3 passes, 4 lanes), then split with HKDF-SHA256.",
  },
  { term: "Decrypted items", detail: "Logins, API keys, TOTP seeds and notes exist in plaintext only in memory here." },
  { term: "Recovery code", detail: "160 random bits shown once. It lives on your paper kit." },
  { term: "Share link key", detail: "Sits after the # in the URL. Browsers don't send the fragment to servers." },
];

const SERVER_STORES: Row[] = [
  { term: "Encrypted items", detail: "AES-256-GCM ciphertext, one blob per item, with an HMAC-SHA256 tag." },
  { term: "Wrapped vault key", detail: "Your vault key, encrypted under a key derived from your master password." },
  {
    term: "OPAQUE registration record",
    detail:
      "Lets the server check an OPAQUE (RFC 9807) login without learning the password. A copy of it is no help for guessing the password.",
  },
  {
    term: "Email hash",
    detail: "A SHA-256 hash of your email, keyed again with a server secret, is the account lookup key.",
  },
  {
    term: "Recovery blob",
    detail: "Vault keys encrypted under the recovery code, and a hash of the code's auth key.",
  },
];

function Panel({ title, caption, rows }: { title: string; caption: string; rows: Row[] }) {
  return (
    <div className="min-w-0">
      <h3 className="text-h2 font-semibold text-fg">{title}</h3>
      <p className="mt-1 text-ui text-muted">{caption}</p>
      <dl className="mt-6 divide-y divide-divider border-y border-divider">
        {rows.map((r) => (
          <div key={r.term} className="py-3">
            <dt className="font-mono text-ui text-fg">{r.term}</dt>
            <dd className="mt-0.5 text-ui text-muted">{r.detail}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function Security() {
  return (
    <Section
      id="security"
      title="What the server stores, and what stays on your device"
      intro="Keys are derived and used in your browser, extension or CLI. The server holds what it needs to sync and to check a login."
    >
      <div className="grid gap-10 md:grid-cols-[1fr_auto_1fr] md:gap-8">
        <Panel title="On your device" caption="Never leaves it" rows={STAYS_ON_DEVICE} />
        <div className="flex items-center gap-3 md:flex-col md:justify-center" aria-hidden>
          <span className="h-px flex-1 bg-divider md:h-auto md:w-px" />
          <span className="font-mono text-mono-sm text-muted md:[writing-mode:vertical-rl]">ciphertext only</span>
          <span className="h-px flex-1 bg-divider md:h-auto md:w-px" />
        </div>
        <Panel title="On the server" caption="Useless without your master password" rows={SERVER_STORES} />
      </div>

      <div className="mt-12 grid gap-8 border-t border-divider pt-8 md:grid-cols-3 md:gap-12">
        <div>
          <h3 className="text-h3 font-semibold text-fg">If your device is compromised</h3>
          <p className="mt-1 text-ui text-muted">
            Malware that can read your screen or memory sees what you see. Encryption doesn&apos;t help there.
          </p>
        </div>
        <div>
          <h3 className="text-h3 font-semibold text-fg">If your master password is weak</h3>
          <p className="mt-1 text-ui text-muted">
            Someone with a copy of the database who knows your email can test guesses against your wrapped vault
            key. Each guess costs a full Argon2id run, which slows them down but doesn&apos;t stop them. Registration
            requires a password rated Strong.
          </p>
        </div>
        <div>
          <h3 className="text-h3 font-semibold text-fg">If you forget the password</h3>
          <p className="mt-1 text-ui text-muted">
            We can&apos;t reset it. The recovery kit you save at sign-up is the only way back in.
          </p>
        </div>
      </div>
      <p className="mt-8 text-ui text-muted">
        The client and server code is{" "}
        <a
          href="https://github.com/kalle-works/nopass"
          target="_blank"
          rel="noreferrer"
          className="rounded-sm text-accent-text underline-offset-2 hover:underline"
        >
          open source under the MIT license
        </a>
        , so you can check all of this.
      </p>
    </Section>
  );
}
