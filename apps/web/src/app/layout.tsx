import type { Metadata } from "next";
import { headers } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import { THEME_BOOT_SCRIPT } from "@nopass/ui/theme-boot";
import "./globals.css";

const geist = Geist({ subsets: ["latin"], variable: "--font-geist" });
const geistMono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono" });

export const metadata: Metadata = {
  title: "nopwd",
  description: "Zero-knowledge vault for passwords, API keys and TOTP codes.",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading the request headers also makes every page dynamic, which the
  // per-request CSP nonce requires.
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={`${geist.variable} ${geistMono.variable} h-full`} suppressHydrationWarning>
      <head>
        <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="min-h-full bg-bg text-fg">{children}</body>
    </html>
  );
}
