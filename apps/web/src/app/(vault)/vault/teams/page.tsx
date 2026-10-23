"use client";

import { useEffect } from "react";
import { OrgPanel, useNopassStore } from "@nopass/ui";
import { api } from "@/lib/api";
import { PageShell } from "@/components/vault/PageShell";

export default function TeamsPage() {
  const { sessionToken } = useNopassStore();

  useEffect(() => {
    document.title = "Teams — nopwd";
  }, []);

  return (
    <PageShell
      title="Teams"
      description="Organizations share items between members. The organization key is encrypted separately for each member."
    >
      {sessionToken && <OrgPanel apiClient={api} sessionToken={sessionToken} />}
    </PageShell>
  );
}
