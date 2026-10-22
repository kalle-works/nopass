"use client";

import { CodeBlock } from "@nopass/ui";
import { Section } from "./container";

const TABS = [
  {
    label: "Read a secret",
    lines: [
      { kind: "cmd" as const, text: "nopwd login" },
      { kind: "cmd" as const, text: 'nopwd get "GitHub token"' },
      { kind: "out" as const, text: "ghp_8Kd2…" },
      { kind: "comment" as const, text: "# other fields: nopwd get Postgres --field username" },
      { kind: "cmd" as const, text: "nopwd list --json" },
    ],
  },
  {
    label: "Run with env vars",
    lines: [
      { kind: "cmd" as const, text: 'nopwd run --item "Postgres,Stripe" -- node server.js' },
      { kind: "comment" as const, text: "# POSTGRES and STRIPE are set for node server.js only" },
      { kind: "cmd" as const, text: "export DATABASE_PASSWORD=nopwd://postgres/password" },
      { kind: "cmd" as const, text: "nopwd run -- ./deploy.sh" },
      { kind: "comment" as const, text: "# nopwd:// references are resolved before the command starts" },
    ],
  },
  {
    label: "Unix socket",
    lines: [
      { kind: "cmd" as const, text: "nopwd run --via-socket -- ./app" },
      { kind: "comment" as const, text: "# secrets are served on request, not placed in the environment" },
      { kind: "cmd" as const, text: 'curl --unix-socket "$NOPWD_SOCKET" http://localhost/secret/stripe/password' },
    ],
  },
];

export function CliSection() {
  return (
    <Section
      id="cli"
      title="Secrets for scripts and CI"
      intro="The CLI decrypts on your machine with the same master password. Pick the form that fits how your code reads secrets."
    >
      <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-16">
        <div className="space-y-4 text-body text-muted">
          <p>
            <span className="font-mono text-ui text-fg">nopwd get</span> prints one field. Use it in a pipeline or a
            shell function.
          </p>
          <p>
            <span className="font-mono text-ui text-fg">nopwd run</span> starts your command with items injected as
            environment variables, or with <span className="font-mono text-ui text-fg">nopwd://</span> references
            swapped for real values.
          </p>
          <p>
            With <span className="font-mono text-ui text-fg">--via-socket</span> the process asks for a secret when it
            needs it, so it doesn&apos;t sit in the environment where <span className="font-mono text-ui text-fg">ps</span>{" "}
            can show it.
          </p>
        </div>
        <CodeBlock tabs={TABS} />
      </div>
    </Section>
  );
}
