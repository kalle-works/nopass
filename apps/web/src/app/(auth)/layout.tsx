import type { Metadata } from "next";

export const metadata: Metadata = {
  title: {
    template: "%s — nopass",
    default: "nopass",
  },
};

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen bg-gray-50 dark:bg-gray-900">{children}</div>;
}
