"use client";

import { useRouter } from "next/navigation";
import { UnlockScreen } from "@nopass/ui";
import { api } from "@/lib/api";
import { AuthFooter } from "@/components/auth/auth-footer";
import { downloadRecoveryKit } from "@/lib/recovery-kit";

export default function RegisterPage() {
  const router = useRouter();

  return (
    <UnlockScreen
      apiClient={api}
      mode="register"
      homeHref="/"
      footer={<AuthFooter />}
      onDownloadRecoveryKit={downloadRecoveryKit}
      onSuccess={() => router.replace("/vault")}
      onSwitchMode={() => router.push("/login")}
    />
  );
}
