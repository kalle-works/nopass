import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#070706] flex items-center justify-center px-6">
      <div className="max-w-md w-full">
        <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-4">404</p>
        <h1 className="font-mono text-4xl font-bold text-[#F4F1E8] mb-3 leading-tight">
          Page not found.
        </h1>
        <p className="text-[#9C988D] text-sm leading-relaxed mb-8">
          The URL you requested does not exist. It may have been moved or never existed.
        </p>
        <div className="flex items-center gap-3">
          <Link
            href="/"
            className="font-mono text-sm px-5 py-2.5 bg-[#D6FF3F] text-[#070706] font-semibold hover:bg-[#c8ef3a] transition-colors"
          >
            Back to home
          </Link>
          <a
            href="https://github.com/kalle-works/nopass"
            target="_blank"
            rel="noreferrer"
            className="font-mono text-sm px-5 py-2.5 border border-[#2B2923] text-[#9C988D] hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors"
          >
            GitHub ↗
          </a>
        </div>
        <div className="mt-10 pt-8 border-t border-[#2B2923]">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest">nopwd</p>
        </div>
      </div>
    </div>
  );
}
