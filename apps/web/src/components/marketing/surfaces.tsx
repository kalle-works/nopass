"use client";

import type { ReactNode } from "react";
import { Globe } from "lucide-react";
import { Badge, Button, CodeBlock } from "@nopass/ui";
import { Section } from "./container";

function Surface({ name, children, capture }: { name: string; children: ReactNode; capture: ReactNode }) {
  return (
    <div className="grid items-center gap-6 border-b border-divider py-8 first:pt-0 last:border-b-0 last:pb-0 md:grid-cols-2 md:gap-16 md:py-12 md:first:pt-0">
      <div className="max-w-[460px]">
        <h3 className="text-h2 font-semibold text-fg">{name}</h3>
        <div className="mt-2 space-y-3 text-body text-muted">{children}</div>
      </div>
      <div className="min-w-0">{capture}</div>
    </div>
  );
}

function ShareCapture() {
  return (
    <div className="rounded-lg border border-divider bg-surface">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-divider px-4 py-3">
        <p className="text-h3 font-semibold text-fg">Stripe live key</p>
        <div className="flex gap-1.5">
          <Badge>0/1 views</Badge>
          <Badge>23h left</Badge>
        </div>
      </div>
      <div className="px-4 py-3">
        <p className="text-meta text-muted">Share link</p>
        <p className="mt-1 break-all font-mono text-ui text-fg">
          nopwd.dev/s/Qm3xVt9aLk<span className="text-faint">#k=Yx2r…</span>
        </p>
        <p className="mt-2 text-meta text-muted">The part after # stays in the browser and is never sent to the server.</p>
      </div>
    </div>
  );
}

function ExtensionCapture() {
  return (
    <div className="w-full max-w-[380px] overflow-hidden rounded-lg border border-border bg-surface">
      <div className="flex h-11 items-center justify-between border-b border-divider px-3">
        <span className="font-mono text-ui font-semibold text-fg">nopwd</span>
        <span className="truncate text-meta text-muted">kalle@example.com</span>
      </div>
      <p className="px-3 pb-1 pt-3 text-meta text-muted">For github.com</p>
      <div className="flex h-[52px] items-center gap-2.5 px-3">
        <Globe aria-hidden className="size-4 shrink-0 text-icon" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-ui font-medium text-fg">GitHub</p>
          <p className="truncate text-meta text-muted">kalle@example.com</p>
        </div>
        <Badge>TOTP</Badge>
        <Button size="sm" variant="secondary" tabIndex={-1}>
          Fill
        </Button>
      </div>
    </div>
  );
}

function CliCapture() {
  return (
    <CodeBlock
      lines={[
        { kind: "cmd", text: 'nopwd get "OpenAI API key"' },
        { kind: "out", text: "sk-proj-7f3aJ2c9…" },
        { kind: "cmd", text: 'nopwd list --tag work' },
      ]}
    />
  );
}

export function Surfaces() {
  return (
    <Section
      id="product"
      title="One vault, three ways in"
      intro="Every surface opens the same encrypted vault. Nothing is synced in the clear between them."
    >
      <div>
        <Surface name="Web" capture={<ShareCapture />}>
          <p>Search and edit items, import from 1Password, check passwords against known breaches and set up your recovery kit.</p>
          <p>Send a credential as a one-time link that expires after a set number of views.</p>
        </Surface>
        <Surface name="Browser extension" capture={<ExtensionCapture />}>
          <p>Fills logins on the site you are on and shows the TOTP code next to the password.</p>
          <p>It also works as a passkey authenticator, so passkeys live in your vault.</p>
        </Surface>
        <Surface name="CLI" capture={<CliCapture />}>
          <p>Read a secret in a script, or run a command with your items set as environment variables.</p>
          <p>It signs in with the same master password and decrypts on your machine.</p>
        </Surface>
      </div>
    </Section>
  );
}
