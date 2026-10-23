"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Banner, IconButton, Kbd, cx } from "@nopass/ui";
import { X } from "lucide-react";
import { DetailPane } from "@/components/vault/DetailPane";
import { ListPane } from "@/components/vault/ListPane";
import { useVault } from "@/components/vault/vault-context";
import { useListShortcuts } from "@/components/vault/useListShortcuts";
import { primaryCopy } from "@/components/vault/vault-model";

export default function VaultPage() {
  return (
    <Suspense>
      <VaultPageInner />
    </Suspense>
  );
}

function StatusBar() {
  const v = useVault();
  const plain = v.selectedEntry?.plaintext;
  const quick = plain ? primaryCopy(plain) : null;
  const editorOpen = v.creating !== null || v.editing;

  return (
    <div className="flex h-8 shrink-0 items-center gap-4 overflow-hidden border-t border-divider bg-bg-subtle px-4 text-meta text-muted">
      <span role="status" aria-live="polite" className={v.copyStatus ? "truncate text-fg" : "sr-only"}>
        {v.copyStatus}
      </span>
      {!v.copyStatus && (
        <>
          <span className="hidden items-center gap-1.5 md:flex">
            <Kbd>/</Kbd> Search
          </span>
          <span className="hidden items-center gap-1.5 md:flex">
            <Kbd>N</Kbd> New
          </span>
          <span className="hidden items-center gap-1.5 md:flex">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> Move
          </span>
          {plain && !editorOpen && (
            <>
              <span className="hidden items-center gap-1.5 md:flex">
                <Kbd>E</Kbd> Edit
              </span>
              {quick && (
                <span className="hidden items-center gap-1.5 md:flex">
                  <Kbd>C</Kbd> {quick.label}
                </span>
              )}
              {plain.type === "login" && (
                <span className="hidden items-center gap-1.5 md:flex">
                  <Kbd>U</Kbd> Copy username
                </span>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

function VaultPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const v = useVault();
  const [pickerOpen, setPickerOpen] = useState(false);
  useListShortcuts({ pickerOpen, setPickerOpen });

  useEffect(() => {
    document.title = "Vault — nopwd";
  }, []);

  // Deep link from the health page: /vault?item=<id>
  useEffect(() => {
    const itemId = searchParams.get("item");
    if (itemId) {
      v.openItem(itemId);
      router.replace("/vault");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!window.matchMedia("(min-width: 768px)").matches) return;
    const timer = setTimeout(() => v.focusSearch(), 50);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const detailVisible = v.detailOpen;

  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col">
      {v.error && (
        <div className="border-b border-divider p-3">
          <Banner
            tone="danger"
            action={
              <IconButton label="Dismiss error" onClick={() => v.setError(null)} className="-my-1 -mr-2">
                <X aria-hidden className="size-4" />
              </IconButton>
            }
          >
            {v.error}
          </Banner>
        </div>
      )}
      <div className="flex min-h-0 flex-1">
        <ListPane
          className={cx(detailVisible ? "hidden xl:flex" : "flex")}
          pickerOpen={pickerOpen}
          setPickerOpen={setPickerOpen}
        />
        <DetailPane className={cx(detailVisible ? "flex" : "hidden xl:flex")} />
      </div>
      <StatusBar />
    </div>
  );
}
