import Link from "next/link";
import { CONTAINER } from "./container";
import { linkButton } from "./link-button";

const NAV_LINK = "rounded-sm px-2 py-1 text-ui text-muted transition-colors duration-[120ms] hover:text-fg";

export function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-divider bg-bg">
      <div className={`${CONTAINER} flex h-14 items-center justify-between gap-4`}>
        <div className="flex items-center gap-8">
          <Link href="/" className="font-mono text-h3 font-semibold tracking-tight text-fg">
            nopwd
          </Link>
          <nav aria-label="Main" className="hidden items-center gap-2 md:flex">
            <Link href="#security" className={NAV_LINK}>
              Security
            </Link>
            <a href="https://github.com/kalle-works/nopass#readme" target="_blank" rel="noreferrer" className={NAV_LINK}>
              Docs
            </a>
            <Link href="#pricing" className={NAV_LINK}>
              Pricing
            </Link>
            <a href="https://github.com/kalle-works/nopass" target="_blank" rel="noreferrer" className={NAV_LINK}>
              GitHub
            </a>
          </nav>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/login" className={linkButton("ghost")}>
            Log in
          </Link>
          <Link href="/register" className={linkButton("primary")}>
            Create vault
          </Link>
        </div>
      </div>
    </header>
  );
}
