"use client";

import { useEffect, type ReactNode } from "react";
import { CommandPalette } from "./CommandPalette";
import { ShareDialog } from "./ShareDialog";
import { Sidebar } from "./Sidebar";
import { VaultProvider, useVault } from "./vault-context";

function GlobalShortcuts() {
  const { paletteOpen, setPaletteOpen, lockVault } = useVault();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
      const key = e.key.toLowerCase();
      if (key === "k") {
        e.preventDefault();
        setPaletteOpen(!paletteOpen);
      } else if (key === "l") {
        e.preventDefault();
        lockVault();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [paletteOpen, setPaletteOpen, lockVault]);

  return null;
}

function Frame({ children }: { children: ReactNode }) {
  const { drawerOpen, setDrawerOpen, notice, shareOpen, setShareOpen, selectedEntry } = useVault();

  useEffect(() => {
    if (!drawerOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setDrawerOpen(false);
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen, setDrawerOpen]);

  return (
    <div className="flex h-dvh bg-bg text-fg">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2 focus:text-ui focus:shadow-overlay"
      >
        Skip to main content
      </a>
      <GlobalShortcuts />

      <Sidebar className="hidden md:flex" />

      {drawerOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div className="absolute inset-0 bg-overlay animate-fade-in" onClick={() => setDrawerOpen(false)} />
          <Sidebar className="relative h-full animate-overlay-in shadow-overlay" />
        </div>
      )}

      <main id="main" tabIndex={-1} className="flex min-h-0 min-w-0 flex-1 focus:outline-none">
        {children}
      </main>

      <div className="pointer-events-none fixed inset-x-0 bottom-10 z-50 flex justify-center px-4" role="status" aria-live="polite">
        {notice && (
          <p className="rounded-lg border border-divider bg-surface px-4 py-2 text-ui text-fg shadow-overlay animate-overlay-in">
            {notice}
          </p>
        )}
      </div>

      <CommandPalette />
      {shareOpen && selectedEntry && <ShareDialog entry={selectedEntry} onClose={() => setShareOpen(false)} />}
    </div>
  );
}

export function VaultShell({ children }: { children: ReactNode }) {
  return (
    <VaultProvider>
      <Frame>{children}</Frame>
    </VaultProvider>
  );
}
