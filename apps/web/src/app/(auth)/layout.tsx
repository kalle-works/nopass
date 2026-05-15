import type { Metadata } from "next";

export const metadata: Metadata = {
  title: {
    template: "%s — nopass",
    default: "nopass",
  },
};

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen bg-[#0a0a0a]">{children}</div>;
}
