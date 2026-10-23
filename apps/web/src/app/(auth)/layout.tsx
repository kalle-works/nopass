import type { Metadata } from "next";

export const metadata: Metadata = {
  title: {
    template: "%s — nopwd",
    default: "nopwd",
  },
};

// Each auth screen renders its own AuthShell so the page frame is identical
// for the shared UnlockScreen (also used by the desktop app) and the web-only pages.
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return children;
}
