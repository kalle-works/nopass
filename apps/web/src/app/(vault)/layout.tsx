import { ErrorBoundary } from "@/components/error-boundary";
import { VaultShell } from "@/components/vault/VaultShell";

export default function VaultLayout({ children }: { children: React.ReactNode }) {
  return (
    <ErrorBoundary>
      <VaultShell>{children}</VaultShell>
    </ErrorBoundary>
  );
}
