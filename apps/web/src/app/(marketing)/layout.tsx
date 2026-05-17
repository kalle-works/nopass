import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "nopwd — Zero-knowledge password manager",
  description:
    "Your passwords, encrypted on your device with AES-256-GCM. We cryptographically cannot read your vault. Free, open source, cross-platform.",
  openGraph: {
    title: "nopwd — Zero-knowledge password manager",
    description: "Your passwords. Yours alone. End-to-end encrypted, open source, cross-platform.",
    type: "website",
  },
};

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return <div className="bg-[#080c14] text-white min-h-screen">{children}</div>;
}
