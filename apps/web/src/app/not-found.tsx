import Link from "next/link";
import { linkButton } from "@/components/marketing/link-button";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col bg-bg text-fg">
      <header className="px-6 py-5">
        <Link href="/" className="font-mono text-h3 font-semibold tracking-tight text-fg">
          nopwd
        </Link>
      </header>
      <main className="mx-auto flex w-full max-w-[432px] flex-1 flex-col justify-center px-4 pb-16">
        <p className="font-mono text-meta text-muted">404</p>
        <h1 className="mt-2 text-h1 font-semibold text-fg">Page not found</h1>
        <p className="mt-2 text-body text-muted">
          This address doesn&apos;t lead anywhere. It may have moved, or the link may have a typo.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link href="/" className={linkButton("primary", "lg")}>
            Back to home
          </Link>
          <Link href="/login" className={linkButton("secondary", "lg")}>
            Log in
          </Link>
        </div>
      </main>
    </div>
  );
}
