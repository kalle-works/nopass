"use client";

import type { FormEvent, KeyboardEvent } from "react";
import { Button } from "../../primitives/Button";

/** Cmd/Ctrl+Enter saves, Escape cancels. Shared by every editor form. */
export function editorKeyHandler(onCancel: () => void) {
  return (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      e.currentTarget.requestSubmit();
    } else if (e.key === "Escape" && !e.defaultPrevented) {
      e.preventDefault();
      onCancel();
    }
  };
}

export function submitHandler(run: () => void) {
  return (e: FormEvent) => {
    e.preventDefault();
    run();
  };
}

export function EditorActions({ onCancel, saving }: { onCancel: () => void; saving?: boolean | undefined }) {
  return (
    <div className="sticky bottom-0 -mx-1 flex justify-end gap-2 border-t border-divider bg-bg px-1 py-3">
      <Button type="button" variant="ghost" onClick={onCancel}>
        Cancel
      </Button>
      <Button type="submit" variant="primary" pending={saving} pendingLabel="Saving…">
        Save
      </Button>
    </div>
  );
}
