"use client";

import { useRouter } from "next/navigation";
import { UnlockScreen } from "@nopass/ui";
import { api } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();

  return (
    <UnlockScreen
      apiClient={api}
      mode="login"
      onSuccess={() => router.replace("/vault")}
      onSwitchMode={() => router.push("/register")}
    />
  );
}
