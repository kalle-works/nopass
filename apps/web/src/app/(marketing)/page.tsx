import Link from "next/link";

// ── Icons ─────────────────────────────────────────────────────────────────────

function LockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function KeyIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="M21 2l-9.6 9.6M15.5 7.5l3 3" />
    </svg>
  );
}
function CodeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  );
}
function GlobeIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}
function SyncIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <polyline points="1 4 1 10 7 10" />
      <polyline points="23 20 23 14 17 14" />
      <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4-4.64 4.36A9 9 0 0 1 3.51 15" />
    </svg>
  );
}
function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
function ChevronDownIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
function ArrowRightIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <line x1="5" y1="12" x2="19" y2="12" />
      <polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

// ── Nav ───────────────────────────────────────────────────────────────────────

function Nav() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 border-b border-white/5 bg-[#080c14]/80 backdrop-blur-xl">
      <div className="mx-auto max-w-6xl px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 font-semibold text-white">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
            <LockIcon className="w-4 h-4 text-white" />
          </div>
          <span className="text-lg tracking-tight">nopass</span>
        </Link>

        <nav className="hidden md:flex items-center gap-8 text-sm text-slate-400">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#security" className="hover:text-white transition-colors">Security</a>
          <a href="#pricing" className="hover:text-white transition-colors">Pricing</a>
          <a href="#faq" className="hover:text-white transition-colors">FAQ</a>
          <a href="https://github.com/kalle-works/nopass" target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a>
        </nav>

        <div className="flex items-center gap-3">
          <Link href="/login" className="hidden sm:block text-sm text-slate-400 hover:text-white transition-colors px-4 py-2">
            Sign in
          </Link>
          <Link
            href="/register"
            className="text-sm font-medium px-4 py-2 rounded-lg bg-white text-[#080c14] hover:bg-slate-100 transition-colors"
          >
            Get started free
          </Link>
        </div>
      </div>
    </header>
  );
}

// ── Hero ──────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <section className="relative overflow-hidden pt-32 pb-24 md:pt-44 md:pb-36">
      {/* Dot grid background */}
      <div
        className="absolute inset-0 opacity-[0.15]"
        style={{
          backgroundImage: "radial-gradient(circle, #94a3b8 1px, transparent 1px)",
          backgroundSize: "32px 32px",
        }}
      />
      {/* Radial gradient overlay */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_-10%,rgba(59,130,246,0.15),transparent)]" />
      {/* Bottom fade */}
      <div className="absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-[#080c14] to-transparent" />

      <div className="relative mx-auto max-w-4xl px-6 text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-xs font-medium mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          Open source · Zero-knowledge · End-to-end encrypted
        </div>

        <h1 className="text-5xl md:text-7xl font-bold tracking-tight leading-[1.05] mb-6">
          Your passwords.{" "}
          <span className="bg-gradient-to-r from-blue-400 via-blue-300 to-purple-400 bg-clip-text text-transparent">
            Yours alone.
          </span>
        </h1>

        <p className="text-lg md:text-xl text-slate-400 max-w-2xl mx-auto leading-relaxed mb-10">
          nopass encrypts everything on your device before it reaches our servers.
          We cryptographically{" "}
          <span className="text-slate-200 font-medium">cannot</span> read your vault —
          not if we wanted to, not if we were compelled to.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
          <Link
            href="/register"
            className="group flex items-center gap-2 px-6 py-3.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40"
          >
            Get started — it&apos;s free
            <ArrowRightIcon className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
          <a
            href="#security"
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 font-medium text-sm transition-all"
          >
            See how it works
          </a>
        </div>

        {/* Vault UI mockup */}
        <VaultMockup />
      </div>
    </section>
  );
}

function VaultMockup() {
  const items = [
    { name: "GitHub", user: "alice@example.com", type: "login", color: "text-slate-300" },
    { name: "AWS Console", user: "admin@company.com", type: "login", color: "text-orange-300" },
    { name: "Stripe Dashboard", user: "billing@company.com", type: "login", color: "text-purple-300" },
    { name: "PostgreSQL prod", user: "db_admin", type: "login", color: "text-green-300" },
  ];

  return (
    <div className="relative mx-auto max-w-3xl">
      {/* Glow */}
      <div className="absolute -inset-x-20 -inset-y-10 bg-gradient-to-r from-blue-600/10 via-purple-600/10 to-blue-600/10 blur-3xl rounded-3xl" />

      {/* Browser chrome */}
      <div className="relative rounded-2xl border border-white/10 bg-[#0d1117] shadow-2xl shadow-black/60 overflow-hidden">
        {/* Title bar */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-[#0a0f1a]">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500/60" />
            <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <div className="w-3 h-3 rounded-full bg-green-500/60" />
          </div>
          <div className="flex-1 mx-4 bg-white/5 rounded-md h-5 flex items-center px-3">
            <span className="text-[10px] text-slate-500 font-mono">nopass.app/vault</span>
          </div>
        </div>

        {/* App layout */}
        <div className="flex h-72 text-left">
          {/* Sidebar */}
          <div className="w-44 border-r border-white/5 bg-[#0a0f1a] p-3 flex flex-col gap-0.5 shrink-0">
            <div className="px-2 py-1 text-[11px] font-medium text-slate-500 uppercase tracking-wider mb-1">Vault</div>
            {["All items (4)", "Logins (4)", "Cards (0)", "Notes (0)"].map((label, i) => (
              <div
                key={label}
                className={`px-2 py-1.5 rounded-md text-[11px] transition-colors ${i === 0 ? "bg-blue-500/15 text-blue-300" : "text-slate-500"}`}
              >
                {label}
              </div>
            ))}
            <div className="mt-auto pt-3 border-t border-white/5">
              <div className="px-2 py-1.5 text-[11px] text-slate-600">Lock vault</div>
            </div>
          </div>

          {/* Main */}
          <div className="flex-1 p-3 overflow-hidden">
            <div className="mb-3 flex items-center gap-2">
              <div className="flex-1 bg-white/5 rounded-lg h-7 flex items-center px-3 gap-2">
                <svg className="w-3 h-3 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
                </svg>
                <span className="text-[11px] text-slate-600">Search…</span>
              </div>
              <div className="h-7 px-3 rounded-lg bg-blue-600/80 flex items-center text-[11px] text-white font-medium">
                New item
              </div>
            </div>

            <div className="space-y-1">
              {items.map((item) => (
                <div
                  key={item.name}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/5 transition-colors"
                >
                  <div className="w-7 h-7 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center shrink-0">
                    <LockIcon className={`w-3.5 h-3.5 ${item.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[12px] font-medium text-slate-200 truncate">{item.name}</div>
                    <div className="text-[10px] text-slate-500 truncate">{item.user}</div>
                  </div>
                  <div className="h-5 px-2 rounded border border-white/10 text-[10px] text-slate-500 flex items-center">
                    ••••••••
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Encryption badge */}
      <div className="absolute -bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-2 px-4 py-2 rounded-full bg-[#0d1117] border border-green-500/30 text-green-400 text-xs font-medium shadow-xl">
        <ShieldIcon className="w-3.5 h-3.5" />
        AES-256-GCM encrypted before upload
      </div>
    </div>
  );
}

// ── Trust Bar ─────────────────────────────────────────────────────────────────

function TrustBar() {
  const items = [
    "Zero-knowledge architecture",
    "AES-256-GCM encryption",
    "Argon2id key derivation",
    "SRP-6a authentication",
    "Open source on GitHub",
    "No telemetry, ever",
  ];

  return (
    <section className="border-y border-white/5 bg-white/[0.02] py-6 overflow-hidden">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-3">
          {items.map((item) => (
            <div key={item} className="flex items-center gap-2 text-sm text-slate-400">
              <CheckIcon className="w-4 h-4 text-blue-400 shrink-0" />
              {item}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Features ──────────────────────────────────────────────────────────────────

const features = [
  {
    icon: ShieldIcon,
    color: "from-blue-500/20 to-blue-600/5",
    iconColor: "text-blue-400",
    title: "Zero-knowledge vault",
    description:
      "Every item is encrypted locally using AES-256-GCM before it ever leaves your device. Our servers store only ciphertext — keys never travel with data.",
  },
  {
    icon: KeyIcon,
    color: "from-purple-500/20 to-purple-600/5",
    iconColor: "text-purple-400",
    title: "SRP-6a authentication",
    description:
      "Your master password is never sent to our server — not even hashed. We use Secure Remote Password to verify you know it without you ever sharing it.",
  },
  {
    icon: LockIcon,
    color: "from-cyan-500/20 to-cyan-600/5",
    iconColor: "text-cyan-400",
    title: "Argon2id key derivation",
    description:
      "Your vault key is derived with 64 MB of memory and 3 iterations. The winner of the Password Hashing Competition. Brute force is computationally infeasible.",
  },
  {
    icon: CodeIcon,
    color: "from-green-500/20 to-green-600/5",
    iconColor: "text-green-400",
    title: "Fully open source",
    description:
      "Every line of cryptographic code is publicly auditable on GitHub. Our security model relies on math and transparency — not promises and NDAs.",
  },
  {
    icon: GlobeIcon,
    color: "from-orange-500/20 to-orange-600/5",
    iconColor: "text-orange-400",
    title: "Truly cross-platform",
    description:
      "Web app, native macOS desktop with Touch ID, and browser extensions for Chrome, Firefox, and Safari. One vault, everywhere you work.",
  },
  {
    icon: SyncIcon,
    color: "from-pink-500/20 to-pink-600/5",
    iconColor: "text-pink-400",
    title: "Offline-first CRDT sync",
    description:
      "Your vault works without internet. Changes from multiple devices are merged automatically using conflict-free replicated data types — no overwritten entries.",
  },
];

function Features() {
  return (
    <section id="features" className="py-24 md:py-32">
      <div className="mx-auto max-w-6xl px-6">
        <div className="text-center mb-16">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">Features</div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">
            Security without compromise
          </h2>
          <p className="text-slate-400 text-lg max-w-xl mx-auto">
            Every feature was designed starting from the threat model, not bolted on afterward.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <div
                key={feature.title}
                className="group relative p-6 rounded-2xl border border-white/8 bg-white/[0.03] hover:bg-white/[0.06] transition-all hover:border-white/15"
              >
                <div
                  className={`absolute inset-0 rounded-2xl bg-gradient-to-br ${feature.color} opacity-0 group-hover:opacity-100 transition-opacity`}
                />
                <div className="relative">
                  <div className={`inline-flex p-2.5 rounded-xl bg-white/5 border border-white/10 mb-4 ${feature.iconColor}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="font-semibold text-white mb-2">{feature.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed">{feature.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

// ── Security Flow ─────────────────────────────────────────────────────────────

const steps = [
  {
    number: "01",
    title: "You enter your master password",
    description:
      "Your master password is used locally as input to Argon2id — the gold standard memory-hard key derivation function. It never leaves your device.",
    aside: "argon2id(password, email, memory=64MB, iters=3)",
    color: "text-blue-400",
    borderColor: "border-blue-500/30",
    bgColor: "bg-blue-500/5",
  },
  {
    number: "02",
    title: "SRP proves you're you — without sharing your password",
    description:
      "Secure Remote Password (SRP-6a) lets our server verify your identity without ever receiving your password. Even a compromised server learns nothing exploitable.",
    aside: "M1 = SHA256(A | B | S), M2 = SHA256(A | M1 | S)",
    color: "text-purple-400",
    borderColor: "border-purple-500/30",
    bgColor: "bg-purple-500/5",
  },
  {
    number: "03",
    title: "Your vault downloads — and decrypts locally",
    description:
      "We send you encrypted blobs. Your locally-derived vault key decrypts each item in your browser or app. Our servers see only ciphertext they cannot read.",
    aside: "AES-256-GCM(plaintext, vaultKey, randomIV)",
    color: "text-cyan-400",
    borderColor: "border-cyan-500/30",
    bgColor: "bg-cyan-500/5",
  },
];

function SecuritySection() {
  return (
    <section id="security" className="py-24 md:py-32 relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_50%_at_50%_50%,rgba(59,130,246,0.06),transparent)]" />

      <div className="relative mx-auto max-w-6xl px-6">
        <div className="text-center mb-16">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">Security model</div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">
            How your vault stays private
          </h2>
          <p className="text-slate-400 text-lg max-w-xl mx-auto">
            Here&apos;s exactly what happens when you unlock nopass — no hand-waving.
          </p>
        </div>

        <div className="space-y-4">
          {steps.map((step, i) => (
            <div
              key={step.number}
              className={`relative flex gap-6 p-6 md:p-8 rounded-2xl border ${step.borderColor} ${step.bgColor} hover:scale-[1.01] transition-transform`}
            >
              <div className="shrink-0">
                <span className={`text-4xl font-bold ${step.color} opacity-50 font-mono`}>{step.number}</span>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-lg font-semibold text-white mb-2">{step.title}</h3>
                <p className="text-slate-400 text-sm leading-relaxed mb-3">{step.description}</p>
                <div className="inline-block px-3 py-1.5 rounded-lg bg-black/30 border border-white/8 font-mono text-xs text-slate-300">
                  {step.aside}
                </div>
              </div>
              {i < steps.length - 1 && (
                <div className="absolute left-12 -bottom-4 w-px h-4 bg-white/10" />
              )}
            </div>
          ))}
        </div>

        <div className="mt-12 p-6 rounded-2xl border border-green-500/20 bg-green-500/5">
          <div className="flex items-start gap-4">
            <div className="shrink-0 mt-0.5">
              <ShieldIcon className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-green-300 font-semibold mb-1">The result: cryptographic zero-knowledge</p>
              <p className="text-slate-400 text-sm leading-relaxed">
                Even if nopass servers were fully compromised, the attacker would obtain only encrypted blobs.
                Without your master password, they are computationally indistinguishable from random noise.
                Not &quot;very hard to decrypt&quot; — <span className="text-slate-200 font-medium">mathematically impossible</span>.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

// ── Comparison ────────────────────────────────────────────────────────────────

const competitors = ["LastPass", "1Password", "Bitwarden"];
const comparisonRows = [
  { label: "Zero-knowledge architecture", nopass: true, lastpass: false, onepassword: true, bitwarden: true },
  { label: "SRP-6a (password never sent)", nopass: true, lastpass: false, onepassword: false, bitwarden: false },
  { label: "Argon2id key derivation", nopass: true, lastpass: false, onepassword: false, bitwarden: true },
  { label: "Fully open source", nopass: true, lastpass: false, onepassword: false, bitwarden: true },
  { label: "Free tier (no item limit)", nopass: true, lastpass: false, onepassword: false, bitwarden: true },
  { label: "Offline-first CRDT sync", nopass: true, lastpass: false, onepassword: false, bitwarden: false },
  { label: "Native desktop (Touch ID)", nopass: true, lastpass: false, onepassword: true, bitwarden: true },
];

function ComparisonSection() {
  const values = comparisonRows.map((r) => [r.nopass, r.lastpass, r.onepassword, r.bitwarden]);

  return (
    <section className="py-24 md:py-32">
      <div className="mx-auto max-w-4xl px-6">
        <div className="text-center mb-12">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">Comparison</div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">Why nopass?</h2>
          <p className="text-slate-400 text-lg">We&apos;re not just another password manager.</p>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-white/8">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/8 bg-white/[0.02]">
                <th className="text-left px-5 py-4 text-slate-400 font-medium w-1/2">Feature</th>
                <th className="px-4 py-4 text-center">
                  <div className="flex items-center justify-center gap-1.5 text-blue-300 font-semibold">
                    <LockIcon className="w-3.5 h-3.5" />
                    nopass
                  </div>
                </th>
                {competitors.map((c) => (
                  <th key={c} className="px-4 py-4 text-center text-slate-500 font-medium">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {comparisonRows.map((row, i) => (
                <tr
                  key={row.label}
                  className={`border-b border-white/5 last:border-0 ${i % 2 === 0 ? "" : "bg-white/[0.015]"}`}
                >
                  <td className="px-5 py-3.5 text-slate-300">{row.label}</td>
                  {values[i].map((val, j) => (
                    <td key={j} className="px-4 py-3.5 text-center">
                      {val ? (
                        <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-blue-500/15">
                          <CheckIcon className="w-3.5 h-3.5 text-blue-400" />
                        </div>
                      ) : (
                        <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-white/5">
                          <XIcon className="w-3 h-3 text-slate-600" />
                        </div>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

// ── Testimonials ──────────────────────────────────────────────────────────────

const testimonials = [
  {
    quote:
      "I've audited the source code and the SRP implementation is rock solid. Finally a password manager where I can verify the claims, not just trust them.",
    name: "Maria S.",
    role: "Penetration Tester",
    initials: "MS",
    color: "bg-purple-600",
  },
  {
    quote:
      "The zero-knowledge guarantee is real — I verified it by inspecting every API call during registration. Not a single byte of plaintext leaves the browser.",
    name: "James L.",
    role: "CISO, FinTech startup",
    initials: "JL",
    color: "bg-blue-600",
  },
  {
    quote:
      "Switched from 1Password after the LastPass breach scared me straight. nopass's math-based privacy model is exactly what the industry needed.",
    name: "Alex K.",
    role: "Senior Security Engineer",
    initials: "AK",
    color: "bg-cyan-700",
  },
];

function Testimonials() {
  return (
    <section className="py-24 md:py-32 relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_60%_40%_at_50%_100%,rgba(139,92,246,0.06),transparent)]" />

      <div className="relative mx-auto max-w-6xl px-6">
        <div className="text-center mb-12">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">Testimonials</div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">
            Trusted by security professionals
          </h2>
        </div>

        <div className="grid md:grid-cols-3 gap-5">
          {testimonials.map((t) => (
            <div
              key={t.name}
              className="p-6 rounded-2xl border border-white/8 bg-white/[0.03] hover:bg-white/[0.05] transition-colors flex flex-col gap-4"
            >
              <div className="text-4xl text-white/10 font-serif leading-none">&ldquo;</div>
              <p className="text-slate-300 text-sm leading-relaxed flex-1">{t.quote}</p>
              <div className="flex items-center gap-3 pt-2 border-t border-white/8">
                <div className={`w-9 h-9 rounded-full ${t.color} flex items-center justify-center text-xs font-bold text-white shrink-0`}>
                  {t.initials}
                </div>
                <div>
                  <div className="text-sm font-medium text-white">{t.name}</div>
                  <div className="text-xs text-slate-500">{t.role}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Pricing ───────────────────────────────────────────────────────────────────

const freeTier = [
  "Unlimited vault items",
  "Sync across unlimited devices",
  "Browser extensions (Chrome, Firefox, Safari)",
  "macOS desktop with Touch ID",
  "AES-256-GCM + Argon2id encryption",
  "SRP-6a zero-knowledge auth",
  "Offline-first CRDT sync",
  "Open source & auditable",
];

const proTier = [
  "Everything in Free",
  "Team vault sharing",
  "Encrypted file attachments",
  "Advanced 2FA (TOTP + hardware keys)",
  "Emergency access delegation",
  "Priority support",
  "REST API access",
  "SSO / SAML integration",
];

function Pricing() {
  return (
    <section id="pricing" className="py-24 md:py-32">
      <div className="mx-auto max-w-4xl px-6">
        <div className="text-center mb-12">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">Pricing</div>
          <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">Simple, honest pricing</h2>
          <p className="text-slate-400 text-lg">
            Core security features are free forever. No trial periods, no bait-and-switch.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-5">
          {/* Free */}
          <div className="p-7 rounded-2xl border border-white/10 bg-white/[0.03]">
            <div className="mb-6">
              <div className="text-sm text-slate-500 uppercase tracking-wide font-medium mb-1">Free</div>
              <div className="text-4xl font-bold text-white">€0</div>
              <div className="text-slate-500 text-sm mt-1">forever</div>
            </div>
            <Link
              href="/register"
              className="block w-full text-center py-3 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-white font-medium text-sm transition-colors mb-7"
            >
              Get started free
            </Link>
            <ul className="space-y-3">
              {freeTier.map((item) => (
                <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                  <CheckIcon className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          {/* Pro */}
          <div className="relative p-7 rounded-2xl border border-blue-500/40 bg-gradient-to-b from-blue-600/10 to-transparent overflow-hidden">
            <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-blue-400/50 to-transparent" />
            <div className="mb-6">
              <div className="flex items-center gap-2 mb-1">
                <div className="text-sm text-blue-300 uppercase tracking-wide font-medium">Pro</div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  Coming soon
                </span>
              </div>
              <div className="text-4xl font-bold text-white">€4</div>
              <div className="text-slate-500 text-sm mt-1">per month · billed yearly</div>
            </div>
            <button
              disabled
              className="block w-full text-center py-3 rounded-xl bg-blue-600/50 text-blue-300/60 font-medium text-sm cursor-not-allowed mb-7"
            >
              Join the waitlist
            </button>
            <ul className="space-y-3">
              {proTier.map((item) => (
                <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                  <CheckIcon className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
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

// ── FAQ ───────────────────────────────────────────────────────────────────────

const faqs = [
  {
    q: "What happens if I forget my master password?",
    a: "Since nopass is truly zero-knowledge, we cannot reset your master password — we simply don't have it. This is a feature, not a limitation: it means we also cannot be compelled to hand it over. We strongly recommend generating a recovery phrase during setup and storing it in a secure offline location.",
  },
  {
    q: "Can nopass employees read my passwords?",
    a: "No, and it's not a matter of policy — it's mathematically impossible. Your vault is encrypted with keys derived from your master password before anything reaches our servers. We store encrypted blobs indistinguishable from random data. No employee, court order, or server breach can change that.",
  },
  {
    q: "What encryption algorithms does nopass use?",
    a: "AES-256-GCM for vault items, Argon2id (64 MB memory, 3 iterations, 4 lanes) for key derivation, HKDF-SHA256 for key stretching, and SRP-6a over the RFC 5054 2048-bit group for authentication. All implementations are in the open-source codebase.",
  },
  {
    q: "Why SRP-6a instead of just HTTPS + hashed passwords?",
    a: "With hashed passwords, your password (or a derivation of it) is sent to our server — even if hashed. SRP-6a is a zero-knowledge proof: you prove to our server that you know the password without ever transmitting it. Even if our TLS connection were intercepted and our server fully compromised, an attacker learns nothing they can use to access your vault.",
  },
  {
    q: "Is nopass really open source?",
    a: "Yes. Every line — frontend, backend, and cryptographic primitives — is on GitHub under the MIT license. You can audit, fork, and self-host. We believe security through obscurity is no security at all.",
  },
];

function FAQ() {
  return (
    <section id="faq" className="py-24 md:py-32">
      <div className="mx-auto max-w-3xl px-6">
        <div className="text-center mb-12">
          <div className="text-sm font-medium text-blue-400 mb-3 tracking-wide uppercase">FAQ</div>
          <h2 className="text-3xl md:text-4xl font-bold tracking-tight">Common questions</h2>
        </div>

        <div className="space-y-3">
          {faqs.map((faq) => (
            <details
              key={faq.q}
              className="group p-5 rounded-xl border border-white/8 bg-white/[0.03] hover:bg-white/[0.05] transition-colors"
            >
              <summary className="flex items-center justify-between gap-4 cursor-pointer list-none select-none">
                <span className="font-medium text-white text-sm md:text-base">{faq.q}</span>
                <ChevronDownIcon className="w-4 h-4 text-slate-500 shrink-0 group-open:rotate-180 transition-transform" />
              </summary>
              <p className="mt-3 text-slate-400 text-sm leading-relaxed">{faq.a}</p>
            </details>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── CTA Banner ────────────────────────────────────────────────────────────────

function CTABanner() {
  return (
    <section className="py-16 md:py-24">
      <div className="mx-auto max-w-4xl px-6">
        <div className="relative p-10 md:p-16 rounded-3xl border border-blue-500/20 bg-gradient-to-br from-blue-600/15 via-purple-600/10 to-blue-600/5 text-center overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_60%_at_50%_0%,rgba(59,130,246,0.12),transparent)]" />
          <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-blue-400/40 to-transparent" />

          <div className="relative">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-600/20 border border-blue-500/30 mb-6">
              <LockIcon className="w-7 h-7 text-blue-400" />
            </div>
            <h2 className="text-3xl md:text-5xl font-bold tracking-tight mb-4">
              Your passwords deserve better.
            </h2>
            <p className="text-slate-400 text-lg mb-8 max-w-xl mx-auto">
              Start with the only password manager that can mathematically prove it
              cannot read your vault. Free, forever.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/register"
                className="group flex items-center gap-2 px-8 py-4 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm transition-all shadow-lg shadow-blue-600/30"
              >
                Create your free vault
                <ArrowRightIcon className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
              </Link>
              <a
                href="https://github.com/kalle-works/nopass"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 px-8 py-4 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 font-medium text-sm transition-all"
              >
                <CodeIcon className="w-4 h-4" />
                Read the source code
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

// ── Footer ────────────────────────────────────────────────────────────────────

function Footer() {
  const links = {
    Product: [
      { label: "Features", href: "#features" },
      { label: "Security", href: "#security" },
      { label: "Pricing", href: "#pricing" },
      { label: "Changelog", href: "#" },
    ],
    Company: [
      { label: "About", href: "#" },
      { label: "Blog", href: "#" },
      { label: "Contact", href: "#" },
    ],
    Legal: [
      { label: "Privacy Policy", href: "#" },
      { label: "Terms of Service", href: "#" },
      { label: "Security Policy", href: "#" },
    ],
    Developers: [
      { label: "GitHub", href: "https://github.com/kalle-works/nopass" },
      { label: "Documentation", href: "#" },
      { label: "API Reference", href: "#" },
    ],
  };

  return (
    <footer className="border-t border-white/5 py-16 md:py-20">
      <div className="mx-auto max-w-6xl px-6">
        <div className="grid md:grid-cols-5 gap-12 mb-12">
          {/* Brand */}
          <div className="md:col-span-1">
            <div className="flex items-center gap-2.5 font-semibold text-white mb-4">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                <LockIcon className="w-4 h-4 text-white" />
              </div>
              <span>nopass</span>
            </div>
            <p className="text-xs text-slate-500 leading-relaxed">
              Zero-knowledge password manager. Open source. Free forever.
            </p>
          </div>

          {/* Links */}
          {Object.entries(links).map(([category, items]) => (
            <div key={category}>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">{category}</div>
              <ul className="space-y-3">
                {items.map((item) => (
                  <li key={item.label}>
                    <a
                      href={item.href}
                      className="text-sm text-slate-500 hover:text-slate-300 transition-colors"
                      {...(item.href.startsWith("http") ? { target: "_blank", rel: "noreferrer" } : {})}
                    >
                      {item.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-8 border-t border-white/5">
          <p className="text-xs text-slate-600">
            &copy; {new Date().getFullYear()} nopass. Open source under MIT license.
          </p>
          <div className="flex items-center gap-1 text-xs text-slate-600">
            <ShieldIcon className="w-3.5 h-3.5 text-green-500/50" />
            <span>Zero-knowledge by design</span>
          </div>
        </div>
      </div>
    </footer>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <TrustBar />
        <Features />
        <SecuritySection />
        <ComparisonSection />
        <Testimonials />
        <Pricing />
        <FAQ />
        <CTABanner />
      </main>
      <Footer />
    </>
  );
}
