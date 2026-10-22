"use client";

import { useRouter } from "next/navigation";
import { UnlockScreen } from "@nopass/ui";
import { api } from "@/lib/api";
import { AuthFooter } from "@/components/auth/auth-footer";

export default function LoginPage() {
  const router = useRouter();

  return (
    <UnlockScreen
      apiClient={api}
      mode="login"
      homeHref="/"
      footer={<AuthFooter />}
      onSuccess={() => router.replace("/vault")}
      onSwitchMode={() => router.push("/register")}
      onForgotPassword={() => router.push("/recover")}
    />
  );
}
