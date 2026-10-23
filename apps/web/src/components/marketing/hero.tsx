"use client";

import { useState } from "react";
import Link from "next/link";
import { Button, CodeBlock } from "@nopass/ui";
import { CONTAINER } from "./container";
import { linkButton } from "./link-button";
import { VaultMock } from "./vault-mock";

export const CLI_INSTALL_LINES = [
  { kind: "cmd" as const, text: "git clone https://github.com/kalle-works/nopass && cd nopass" },
  { kind: "cmd" as const, text: "pnpm install && pnpm --filter @nopass/cli build" },
  { kind: "comment" as const, text: "# the binary is apps/cli/dist/index.js; link it onto your PATH as nopwd" },
];

export function Hero() {
  const [showInstall, setShowInstall] = useState(false);

  return (
    <section className="py-12 md:py-24">
      <div className={`${CONTAINER} grid items-start gap-12 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-16`}>
        <div>
          <h1 className="text-[2.25rem]/10 font-semibold tracking-[-0.03em] text-fg md:text-display">
            Your passwords and API keys, encrypted before they leave your device.
          </h1>
          <p className="mt-6 max-w-[480px] text-body text-muted">
            nopwd is a vault for logins, API keys, TOTP codes and notes, for developers and small technical teams. Use
            it from the browser, the extension or the command line. The server only ever stores ciphertext.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="/register" className={linkButton("primary", "lg")}>
              Create your vault
            </Link>
            <Button
              size="lg"
              aria-expanded={showInstall}
              aria-controls="cli-install"
              onClick={() => setShowInstall((s) => !s)}
            >
              Install the CLI
            </Button>
          </div>
          <div id="cli-install" hidden={!showInstall} className="mt-4 max-w-[560px]">
            {showInstall && <CodeBlock lines={CLI_INSTALL_LINES} />}
          </div>
        </div>
        <VaultMock />
      </div>
    </section>
  );
}
