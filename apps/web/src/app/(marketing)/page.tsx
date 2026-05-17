import Link from "next/link";

function Nav() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 bg-[#0a0a0a]/90 backdrop-blur-sm border-b border-white/[0.06]">
      <div className="mx-auto max-w-6xl px-6 h-14 flex items-center justify-between">
        <Link href="/" className="text-white font-semibold tracking-tight text-sm">
          nopwd
        </Link>
        <div className="flex items-center gap-6">
          <a
            href="https://github.com/kalle-works/nopass"
            target="_blank"
            rel="noreferrer"
            className="text-sm text-white/40 hover:text-white/70 transition-colors"
          >
            GitHub
          </a>
          <Link href="/login" className="text-sm text-white/40 hover:text-white/70 transition-colors">
            Sign in
          </Link>
          <Link
            href="/register"
            className="text-sm font-medium px-3.5 py-1.5 rounded-md bg-white text-black hover:bg-white/90 transition-colors"
          >
            Get started
          </Link>
        </div>
      </div>
    </header>
  );
}

function BrowserFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl overflow-hidden border border-white/10 shadow-2xl shadow-black/60 bg-white">
      <div className="flex items-center gap-1.5 px-3 py-2.5 bg-[#f0f0f0] border-b border-black/8">
        <div className="w-3 h-3 rounded-full bg-[#ff5f57]" />
        <div className="w-3 h-3 rounded-full bg-[#febc2e]" />
        <div className="w-3 h-3 rounded-full bg-[#28c840]" />
        <div className="flex-1 mx-3 bg-white/70 rounded h-5 flex items-center px-2.5">
          <span className="text-[10px] text-black/30 font-mono">nopwd.dev/vault</span>
        </div>
      </div>
      {children}
    </div>
  );
}

function VaultPreview() {
  const items = [
    { name: "GitHub", sub: "kalle@kalle.works", type: "Login" },
    { name: "Figma", sub: "kalle@kalle.works", type: "Login" },
    { name: "Vercel", sub: "kalle@kalle.works", type: "Login" },
    { name: "SSH key passphrase", sub: "", type: "Note" },
  ];

  return (
    <BrowserFrame>
      <div className="flex h-[340px] text-sm">
        {/* Sidebar */}
        <div className="w-44 border-r border-black/8 bg-[#f9f9f9] flex flex-col shrink-0">
          <div className="px-4 pt-4 pb-2">
            <p className="text-[11px] font-semibold text-black/30 uppercase tracking-wider mb-2">nopwd</p>
          </div>
          {[
            { label: "All items", count: 4, active: true },
            { label: "Logins", count: 3, active: false },
            { label: "Notes", count: 1, active: false },
            { label: "Cards", count: 0, active: false },
          ].map((item) => (
            <div
              key={item.label}
              className={`mx-2 mb-0.5 px-2 py-1.5 rounded-md text-[12px] flex items-center justify-between ${
                item.active
                  ? "bg-[#3b82f6] text-white font-medium"
                  : "text-black/50 hover:bg-black/5"
              }`}
            >
              <span>{item.label}</span>
              <span className={item.active ? "text-white/70" : "text-black/30"}>{item.count}</span>
            </div>
          ))}
          <div className="mt-auto px-4 pb-4">
            <button className="text-[11px] text-black/30 hover:text-black/50 transition-colors">
              Lock vault
            </button>
          </div>
        </div>

        {/* Main */}
        <div className="flex-1 flex flex-col">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-black/8">
            <div className="flex-1 h-7 rounded-md border border-black/10 bg-white flex items-center px-2.5 gap-1.5">
              <svg className="w-3 h-3 text-black/25" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
              </svg>
              <span className="text-[11px] text-black/25">Search…</span>
            </div>
            <div className="h-7 px-3 rounded-md bg-[#3b82f6] text-white text-[11px] font-medium flex items-center">
              New item
            </div>
          </div>

          <div className="flex-1 overflow-hidden divide-y divide-black/[0.06]">
            {items.map((item) => (
              <div key={item.name} className="flex items-center justify-between px-4 py-2.5 hover:bg-black/[0.02] transition-colors">
                <div>
                  <p className="text-[13px] font-medium text-black/80">{item.name}</p>
                  {item.sub && <p className="text-[11px] text-black/35 mt-0.5">{item.sub}</p>}
                </div>
                <span className="text-[10px] text-black/25 bg-black/[0.04] px-2 py-0.5 rounded">{item.type}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </BrowserFrame>
  );
}

function Hero() {
  return (
    <section className="pt-28 pb-20 md:pt-36 md:pb-28">
      <div className="mx-auto max-w-6xl px-6">
        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Left */}
          <div>
            <p className="text-xs font-medium text-white/30 uppercase tracking-widest mb-5">
              Open source · Zero-knowledge
            </p>
            <h1 className="text-5xl md:text-[3.75rem] font-bold tracking-tight leading-[1.08] text-white mb-6">
              The password manager that can&apos;t read your passwords.
            </h1>
            <p className="text-white/45 text-lg leading-relaxed mb-8 max-w-md">
              Every item is encrypted on your device before it leaves.
              We store ciphertext — not your secrets.
            </p>
            <div className="flex items-center gap-3">
              <Link
                href="/register"
                className="px-5 py-2.5 rounded-lg bg-white text-black font-semibold text-sm hover:bg-white/90 transition-colors"
              >
                Get started free
              </Link>
              <a
                href="https://github.com/kalle-works/nopass"
                target="_blank"
                rel="noreferrer"
                className="px-5 py-2.5 rounded-lg border border-white/10 text-white/60 font-medium text-sm hover:text-white hover:border-white/20 transition-colors"
              >
                View source ↗
              </a>
            </div>
          </div>

          {/* Right — vault screenshot */}
          <div className="relative">
            <div className="absolute -inset-8 bg-white/[0.02] rounded-3xl blur-3xl" />
            <div className="relative">
              <VaultPreview />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function ProofBar() {
  const items = [
    "AES-256-GCM",
    "Argon2id",
    "SRP-6a",
    "Open source",
    "No telemetry",
    "Free forever",
  ];

  return (
    <section className="border-y border-white/[0.06] py-5">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
          {items.map((item, i) => (
            <span key={item} className="flex items-center gap-8">
              <span className="text-sm text-white/30">{item}</span>
              {i < items.length - 1 && (
                <span className="text-white/10 hidden sm:inline">·</span>
              )}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      n: "01",
      title: "Your key, on your device",
      body: "When you log in, your master password runs through Argon2id locally — 64 MB of memory, 3 iterations. The derived key never leaves your device.",
    },
    {
      n: "02",
      title: "Authenticate without revealing",
      body: "SRP-6a lets our server verify that you know your password without you ever sending it. Not even a hash. A compromised server learns nothing.",
    },
    {
      n: "03",
      title: "Encrypted blobs, decrypted locally",
      body: "We store and sync AES-256-GCM ciphertexts. Your browser or app decrypts them with the key only you have. We cannot read them — by design.",
    },
  ];

  return (
    <section className="py-24 md:py-32">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16">
          <p className="text-xs font-medium text-white/25 uppercase tracking-widest mb-3">How it works</p>
          <h2 className="text-3xl md:text-4xl font-bold text-white tracking-tight">
            Math, not promises.
          </h2>
        </div>

        <div className="grid md:grid-cols-3 gap-12 md:gap-8">
          {steps.map((step) => (
            <div key={step.n}>
              <p className="text-4xl font-bold text-white/[0.08] tabular-nums mb-5">{step.n}</p>
              <h3 className="text-base font-semibold text-white mb-3">{step.title}</h3>
              <p className="text-sm text-white/40 leading-relaxed">{step.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function Pricing() {
  const free = [
    "Unlimited vault items",
    "Sync across all devices",
    "Browser extensions",
    "macOS desktop + Touch ID",
    "AES-256-GCM encryption",
    "Argon2id key derivation",
    "Team vault sharing",
    "Open source & auditable",
  ];

  const pro = [
    "Everything in Free",
    "Encrypted file attachments",
    "Hardware key 2FA",
    "Emergency access",
    "Priority support",
    "REST API access",
    "SSO / SAML",
    "Audit logs",
  ];

  return (
    <section id="pricing" className="py-24 md:py-32 border-t border-white/[0.06]">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-16">
          <p className="text-xs font-medium text-white/25 uppercase tracking-widest mb-3">Pricing</p>
          <h2 className="text-3xl md:text-4xl font-bold text-white tracking-tight">
            Simple. No catch.
          </h2>
        </div>

        <div className="grid md:grid-cols-2 gap-4 max-w-3xl">
          {/* Free */}
          <div className="p-8 rounded-2xl border border-white/[0.08] bg-white/[0.02]">
            <p className="text-xs font-medium text-white/30 uppercase tracking-widest mb-4">Free</p>
            <p className="text-5xl font-bold text-white mb-1">€0</p>
            <p className="text-sm text-white/25 mb-6">forever</p>
            <Link
              href="/register"
              className="block text-center py-2.5 rounded-lg border border-white/10 text-sm font-medium text-white/70 hover:text-white hover:border-white/20 transition-colors mb-8"
            >
              Get started
            </Link>
            <ul className="space-y-3">
              {free.map((item) => (
                <li key={item} className="text-sm text-white/45 flex items-start gap-2.5">
                  <svg className="w-4 h-4 text-white/20 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {/* Pro */}
          <div className="p-8 rounded-2xl border border-white/[0.08] bg-white/[0.02]">
            <div className="flex items-center gap-2.5 mb-4">
              <p className="text-xs font-medium text-white/30 uppercase tracking-widest">Pro</p>
              <span className="text-[10px] px-2 py-0.5 rounded border border-white/10 text-white/25">
                Coming soon
              </span>
            </div>
            <p className="text-5xl font-bold text-white mb-1">€4</p>
            <p className="text-sm text-white/25 mb-6">per month</p>
            <button
              disabled
              className="w-full py-2.5 rounded-lg text-sm font-medium text-white/20 border border-white/[0.06] cursor-not-allowed mb-8"
            >
              Join waitlist
            </button>
            <ul className="space-y-3">
              {pro.map((item) => (
                <li key={item} className="text-sm text-white/45 flex items-start gap-2.5">
                  <svg className="w-4 h-4 text-white/20 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-white/[0.06] py-10">
      <div className="mx-auto max-w-6xl px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <p className="text-sm text-white/20">
          &copy; {new Date().getFullYear()} nopwd — MIT license
        </p>
        <div className="flex items-center gap-6">
          <a
            href="https://github.com/kalle-works/nopass"
            target="_blank"
            rel="noreferrer"
            className="text-sm text-white/20 hover:text-white/40 transition-colors"
          >
            GitHub
          </a>
          <Link href="/login" className="text-sm text-white/20 hover:text-white/40 transition-colors">
            Sign in
          </Link>
          <Link href="/register" className="text-sm text-white/20 hover:text-white/40 transition-colors">
            Register
          </Link>
        </div>
      </div>
    </footer>
  );
}

export default function LandingPage() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <ProofBar />
        <HowItWorks />
        <Pricing />
      </main>
      <Footer />
    </>
  );
}
