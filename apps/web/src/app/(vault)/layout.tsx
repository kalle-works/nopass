import { ErrorBoundary } from "@/components/error-boundary";

export default function VaultLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-[#070706]">
      <ErrorBoundary>{children}</ErrorBoundary>
    </div>
  );
}
