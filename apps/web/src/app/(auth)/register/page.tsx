"use client";

import { useRouter } from "next/navigation";
import { UnlockScreen } from "@nopass/ui";
import { api } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();

  return (
    <UnlockScreen
      apiClient={api}
      mode="register"
      onSuccess={() => router.replace("/vault")}
      onSwitchMode={() => router.push("/login")}
    />
  );
}
