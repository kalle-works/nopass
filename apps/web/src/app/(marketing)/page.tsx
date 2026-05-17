import Link from "next/link";

function Nav() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 bg-[#11110F] border-b border-[#2B2923]">
      <div className="mx-auto max-w-6xl px-6 h-12 flex items-center justify-between">
        <Link href="/" className="font-mono text-sm font-semibold text-[#F4F1E8] tracking-tight">
          nopwd
        </Link>
        <nav className="flex items-center gap-6">
          <a
            href="https://github.com/kalle-works/nopass"
            target="_blank"
            rel="noreferrer"
            className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
          >
            GitHub
          </a>
          <Link href="#how-it-works" className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors">
            Docs
          </Link>
          <Link href="/login" className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors">
            Sign in
          </Link>
          <Link
            href="/register"
            className="font-mono text-sm font-medium px-3 py-1.5 bg-[#D6FF3F] text-[#070706] hover:bg-[#c8ef3a] transition-colors"
          >
            Get started
          </Link>
        </nav>
      </div>
    </header>
  );
}

function Node({ label, tag }: { label: string; tag?: string }) {
  return (
    <div className="flex items-center gap-3 py-2.5">
      <span className="w-1.5 h-1.5 bg-[#9C988D] shrink-0" />
      <span className="font-mono text-sm text-[#F4F1E8]">{label}</span>
      {tag && <span className="font-mono text-[11px] text-[#9C988D] ml-1">{tag}</span>}
    </div>
  );
}

function AlgoStep({ label, notes }: { label: string; notes: string[] }) {
  return (
    <div className="ml-[11px] pl-4 border-l border-[#2B2923] py-3">
      <div className="font-mono text-sm text-[#D6FF3F] mb-1.5">↓&nbsp;&nbsp;{label}</div>
      {notes.map((note) => (
        <div key={note} className="font-mono text-[11px] text-[#9C988D] leading-relaxed">{note}</div>
      ))}
    </div>
  );
}

function VerifiedLine({ text, link }: { text: string; link?: string }) {
  const inner = (
    <span className="font-mono text-[11px] text-[#7CFF6B]">
      {text}{link ? " ↗" : ""}
    </span>
  );
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[11px] text-[#7CFF6B] shrink-0">✓</span>
      {link ? (
        <a href={link} target="_blank" rel="noreferrer" className="hover:underline underline-offset-2">
          {inner}
        </a>
      ) : inner}
    </div>
  );
}

function CryptoFlow() {
  return (
    <div className="border border-[#2B2923]">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#2B2923] bg-[#11110F]">
        <div className="flex gap-1.5">
          <div className="w-2 h-2 rounded-full bg-[#2B2923]" />
          <div className="w-2 h-2 rounded-full bg-[#2B2923]" />
          <div className="w-2 h-2 rounded-full bg-[#2B2923]" />
        </div>
        <span className="font-mono text-[11px] text-[#9C988D] ml-1.5">nopwd / crypto-model</span>
      </div>

      <div className="p-6 bg-[#070706]">
        <Node label="master password" />
        <AlgoStep
          label="Argon2id"
          notes={["64 MB · 3 iterations", "runs only on your device, never transmitted"]}
        />
        <Node label="client key" tag="never leaves device" />
        <AlgoStep
          label="AES-256-GCM"
          notes={["each vault item encrypted individually", "unique nonce per item"]}
        />
        <Node label="encrypted vault" tag="ciphertext only" />
        <AlgoStep
          label="SRP-6a"
          notes={["server verifies you know the password", "without ever seeing or receiving it"]}
        />
        <div className="pt-3 space-y-1.5">
          <VerifiedLine text="server holds zero plaintext" />
          <VerifiedLine text="cryptographically verified, not promised" />
          <VerifiedLine
            text="open source — read it yourself"
            link="https://github.com/kalle-works/nopass"
          />
        </div>
      </div>
    </div>
  );
}

function Hero() {
  return (
    <section className="pt-24 pb-16 md:pt-32 md:pb-20">
      <div className="mx-auto max-w-6xl px-6">
        <div className="grid lg:grid-cols-2 gap-16 items-start">
          <div className="lg:pt-2">
            <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-6">
              Zero-knowledge · Open source · Auditable
            </p>
            <h1 className="font-mono text-4xl md:text-5xl font-bold leading-[1.1] text-[#F4F1E8] mb-6">
              The password manager that can&apos;t read your passwords.
            </h1>
            <p className="text-[#9C988D] text-base leading-relaxed mb-8 max-w-xs">
              Zero-knowledge by construction.<br />
              Open source by default.
            </p>
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
              <a
                href="#how-it-works"
                className="px-5 py-2.5 bg-[#D6FF3F] text-[#070706] font-mono font-semibold text-sm hover:bg-[#c8ef3a] transition-colors"
              >
                Read the model
              </a>
              <a
                href="https://github.com/kalle-works/nopass"
                target="_blank"
                rel="noreferrer"
                className="px-5 py-2.5 border border-[#2B2923] text-[#9C988D] font-mono text-sm hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors"
              >
                View source ↗
              </a>
            </div>
          </div>

          <div>
            <CryptoFlow />
          </div>
        </div>
      </div>
    </section>
  );
}

function ProofBar() {
  const items = [
    { label: "AES-256-GCM", accent: true },
    { label: "Argon2id", accent: true },
    { label: "SRP-6a", accent: true },
    { label: "Open source", accent: false },
    { label: "No telemetry", accent: false },
    { label: "Free forever", accent: false },
  ];

  return (
    <section className="border-y border-[#2B2923] py-4">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          {items.map((item, i) => (
            <span key={item.label} className="flex items-center gap-6">
              <span className={`font-mono text-xs ${item.accent ? "text-[#D6FF3F]" : "text-[#9C988D]"}`}>
                {item.label}
              </span>
              {i < items.length - 1 && (
                <span className="text-[#2B2923] hidden sm:inline select-none">·</span>
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
    <section id="how-it-works" className="py-16 md:py-24 border-t border-[#2B2923]">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-12">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-3">How it works</p>
          <h2 className="font-mono text-3xl md:text-4xl font-bold text-[#F4F1E8] tracking-tight">
            Math, not promises.
          </h2>
        </div>

        <div className="grid md:grid-cols-3 border border-[#2B2923]">
          {steps.map((step, i) => (
            <div
              key={step.n}
              className={`p-6 bg-[#11110F] ${i < steps.length - 1 ? "border-b md:border-b-0 md:border-r border-[#2B2923]" : ""}`}
            >
              <p className="font-mono text-xs text-[#9C988D] mb-5">{step.n}</p>
              <h3 className="font-mono text-sm font-semibold text-[#F4F1E8] mb-3">{step.title}</h3>
              <p className="text-sm text-[#9C988D] leading-relaxed">{step.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ThreatModel() {
  const protects = [
    {
      claim: "Compromised server",
      detail: "Attacker gets only ciphertext. No key, no readable data.",
    },
    {
      claim: "Database breach",
      detail: "Each user has a unique derived key. A breach reveals no plaintext.",
    },
    {
      claim: "Network interception",
      detail: "SRP-6a: your password never crosses the wire, not even as a hash.",
    },
  ];

  const doesNotProtect = [
    {
      claim: "Compromised device",
      detail: "If an attacker controls your device, they can observe decryption.",
    },
    {
      claim: "Forgotten master password",
      detail: "Zero-knowledge means zero recovery. By design, not negligence.",
    },
    {
      claim: "Weak master password",
      detail: "Security is proportional to entropy. A weak key is a weak vault.",
    },
  ];

  const assumes = [
    "The client code you run matches the open-source repository (verify with reproducible builds).",
    "Your device is not compromised at the moment you unlock your vault.",
    "Your master password is unique and not reused on other services.",
  ];

  return (
    <section className="py-16 md:py-24 border-t border-[#2B2923]">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-12">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-3">Threat model</p>
          <h2 className="font-mono text-3xl md:text-4xl font-bold text-[#F4F1E8] tracking-tight">
            What nopwd cannot do.
          </h2>
          <p className="text-[#9C988D] text-sm mt-3 max-w-lg leading-relaxed">
            We state limits before features. If you want reassurance without verification, use a different product.
          </p>
        </div>

        <div className="grid md:grid-cols-2 mb-4">
          <div className="border border-[#2B2923]">
            <div className="px-5 py-3 border-b border-[#2B2923] bg-[#11110F]">
              <span className="font-mono text-xs text-[#7CFF6B] uppercase tracking-widest">
                Protects you from
              </span>
            </div>
            <div className="divide-y divide-[#2B2923]">
              {protects.map((item) => (
                <div key={item.claim} className="px-5 py-4">
                  <div className="flex items-start gap-3">
                    <span className="font-mono text-sm text-[#7CFF6B] mt-0.5 shrink-0">✓</span>
                    <div>
                      <p className="text-sm text-[#F4F1E8] font-medium mb-1">{item.claim}</p>
                      <p className="text-xs text-[#9C988D] leading-relaxed">{item.detail}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-[#2B2923] md:border-l-0 border-t-0 md:border-t">
            <div className="px-5 py-3 border-b border-[#2B2923] bg-[#11110F]">
              <span className="font-mono text-xs text-[#FF5C39] uppercase tracking-widest">
                Does not protect against
              </span>
            </div>
            <div className="divide-y divide-[#2B2923]">
              {doesNotProtect.map((item) => (
                <div key={item.claim} className="px-5 py-4">
                  <div className="flex items-start gap-3">
                    <span className="font-mono text-sm text-[#FF5C39] mt-0.5 shrink-0">✗</span>
                    <div>
                      <p className="text-sm text-[#F4F1E8] font-medium mb-1">{item.claim}</p>
                      <p className="text-xs text-[#9C988D] leading-relaxed">{item.detail}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="border border-[#2B2923] p-5">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-4">Assumes</p>
          <ul className="space-y-3">
            {assumes.map((assumption, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-[#9C988D] leading-relaxed">
                <span className="font-mono text-[#2B2923] mt-0.5 shrink-0 select-none">—</span>
                {assumption}
              </li>
            ))}
          </ul>
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
    "Team vault (up to 3 members)",
    "Open source & auditable",
  ];

  const pro = [
    "Everything in Free",
    "Encrypted file attachments",
    "Hardware key 2FA",
    "Emergency access",
    "REST API access",
    "Priority support",
  ];

  const teams = [
    "Everything in Pro",
    "Unlimited org members",
    "SSO / SAML",
    "Audit logs",
    "Dedicated support",
  ];

  return (
    <section id="pricing" className="py-16 md:py-24 border-t border-[#2B2923]">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mb-12">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-3">Pricing</p>
          <h2 className="font-mono text-3xl md:text-4xl font-bold text-[#F4F1E8] tracking-tight">
            Simple. No catch.
          </h2>
        </div>

        <div className="grid md:grid-cols-3 max-w-4xl border border-[#2B2923]">
          <div className="p-6 border-b md:border-b-0 md:border-r border-[#2B2923]">
            <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-4">Free</p>
            <p className="font-mono text-5xl font-bold text-[#F4F1E8] mb-1">€0</p>
            <p className="text-xs text-[#9C988D] mb-6">forever</p>
            <Link
              href="/register"
              className="block text-center py-2.5 border border-[#2B2923] text-[#9C988D] font-mono text-sm hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors mb-8"
            >
              Get started free
            </Link>
            <ul className="space-y-2.5">
              {free.map((item) => (
                <li key={item} className="text-sm text-[#9C988D] flex items-start gap-2.5">
                  <span className="font-mono text-[#9C988D] mt-0.5 shrink-0 text-xs select-none">—</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="p-6 border-b md:border-b-0 md:border-r border-[#2B2923] relative bg-[#11110F]">
            <span className="absolute -top-px left-1/2 -translate-x-1/2 font-mono text-[10px] px-3 py-1 bg-[#D6FF3F] text-[#070706] font-semibold uppercase tracking-widest whitespace-nowrap">
              Most popular
            </span>
            <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-4 mt-3">Pro</p>
            <div className="mb-1">
              <span className="font-mono text-5xl font-bold text-[#F4F1E8]">€4</span>
              <span className="text-sm text-[#9C988D] ml-1">/ month</span>
            </div>
            <p className="font-mono text-xs text-[#9C988D] mb-6">or €36/year · save 25%</p>
            <Link
              href="/vault/billing"
              className="block text-center py-2.5 bg-[#D6FF3F] text-[#070706] font-mono text-sm font-semibold hover:bg-[#c8ef3a] transition-colors mb-8"
            >
              Upgrade to Pro
            </Link>
            <ul className="space-y-2.5">
              {pro.map((item) => (
                <li key={item} className="text-sm text-[#9C988D] flex items-start gap-2.5">
                  <span className="font-mono text-[#D6FF3F] mt-0.5 shrink-0 text-xs">✓</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="p-6">
            <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest mb-4">Teams</p>
            <div className="mb-1">
              <span className="font-mono text-5xl font-bold text-[#F4F1E8]">€5</span>
              <span className="text-sm text-[#9C988D] ml-1">/ seat</span>
            </div>
            <p className="font-mono text-xs text-[#9C988D] mb-6">per month · min 3 seats · annual</p>
            <Link
              href="/vault/billing"
              className="block text-center py-2.5 border border-[#2B2923] text-[#9C988D] font-mono text-sm hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors mb-8"
            >
              Start Teams trial
            </Link>
            <ul className="space-y-2.5">
              {teams.map((item) => (
                <li key={item} className="text-sm text-[#9C988D] flex items-start gap-2.5">
                  <span className="font-mono text-[#9C988D] mt-0.5 shrink-0 text-xs select-none">—</span>
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
    <footer className="border-t border-[#2B2923] py-12">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col md:flex-row items-start justify-between gap-8 mb-10">
          <div>
            <p className="font-mono text-sm font-semibold text-[#F4F1E8] mb-4">nopwd</p>
            <div className="flex items-center gap-3 border border-[#2B2923] bg-[#11110F] px-4 py-2.5">
              <span className="font-mono text-xs text-[#9C988D] select-none">$</span>
              <span className="font-mono text-xs text-[#D6FF3F]">brew install nopwd</span>
            </div>
          </div>
          <nav className="flex flex-col sm:flex-row items-start sm:items-center gap-4 sm:gap-8">
            <a
              href="https://github.com/kalle-works/nopass"
              target="_blank"
              rel="noreferrer"
              className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
            >
              GitHub
            </a>
            <Link href="#how-it-works" className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors">
              Security model
            </Link>
            <Link href="#pricing" className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors">
              Pricing
            </Link>
            <Link href="/login" className="text-sm text-[#9C988D] hover:text-[#F4F1E8] transition-colors">
              Sign in
            </Link>
          </nav>
        </div>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pt-8 border-t border-[#2B2923]">
          <p className="font-mono text-xs text-[#9C988D] uppercase tracking-widest">
            MIT license · Zero-knowledge by construction · Open source by default
          </p>
          <p className="text-xs text-[#9C988D]">&copy; {new Date().getFullYear()} nopwd</p>
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
        <ThreatModel />
        <Pricing />
      </main>
      <Footer />
    </>
  );
}
