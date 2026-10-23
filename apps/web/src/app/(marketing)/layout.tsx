import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "nopwd — Zero-knowledge vault for passwords and API keys",
  description:
    "A zero-knowledge vault for logins, API keys, TOTP codes and notes. Encrypted on your device, available in the browser, the extension and the CLI. Open source.",
  openGraph: {
    title: "nopwd — Zero-knowledge vault for passwords and API keys",
    description: "Logins, API keys and TOTP codes, encrypted before they leave your device.",
    type: "website",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
  twitter: {
    card: "summary_large_image",
    title: "nopwd — Zero-knowledge vault for passwords and API keys",
    description: "Logins, API keys and TOTP codes, encrypted before they leave your device.",
    images: ["/og.png"],
  },
};

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen bg-bg text-fg">{children}</div>;
}
