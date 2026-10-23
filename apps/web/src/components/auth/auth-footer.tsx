import Link from "next/link";

const LINK = "rounded-sm hover:text-fg hover:underline underline-offset-2";

export function AuthFooter() {
  return (
    <nav aria-label="Footer" className="flex flex-wrap gap-x-5 gap-y-1">
      <Link href="/" className={LINK}>
        Home
      </Link>
      <Link href="/#security" className={LINK}>
        Security
      </Link>
      <a href="https://github.com/kalle-works/nopass" target="_blank" rel="noreferrer" className={LINK}>
        Source
      </a>
    </nav>
  );
}
