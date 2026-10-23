import Link from "next/link";
import { CONTAINER } from "./container";
import { ThemeToggle } from "./theme-toggle";

const LINK = "rounded-sm text-ui text-muted hover:text-fg hover:underline underline-offset-2";

export function Footer() {
  return (
    <footer className="border-t border-divider py-12">
      <div className={`${CONTAINER} flex flex-col gap-8 md:flex-row md:items-start md:justify-between`}>
        <div>
          <p className="font-mono text-h3 font-semibold tracking-tight text-fg">nopwd</p>
          <p className="mt-2 text-meta text-muted">&copy; {new Date().getFullYear()} nopwd. MIT licensed.</p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap gap-x-8 gap-y-3">
          <a href="https://github.com/kalle-works/nopass/releases" target="_blank" rel="noreferrer" className={LINK}>
            Changelog
          </a>
          <a href="https://github.com/kalle-works/nopass" target="_blank" rel="noreferrer" className={LINK}>
            Source
          </a>
          <Link href="#security" className={LINK}>
            Security
          </Link>
          <Link href="#pricing" className={LINK}>
            Pricing
          </Link>
          <Link href="/login" className={LINK}>
            Log in
          </Link>
        </nav>
        <ThemeToggle />
      </div>
    </footer>
  );
}
