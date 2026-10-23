"use client";

import { useId, useState } from "react";
import { X } from "lucide-react";

/** Trim, drop empties, dedupe case-insensitively (first spelling wins). */
export function normalizeTags(tags: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of tags) {
    const tag = raw.trim();
    if (!tag) continue;
    const key = tag.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
  }
  return out;
}

interface TagsEditorProps {
  tags: string[];
  onChange: (tags: string[]) => void;
}

export function TagsEditor({ tags, onChange }: TagsEditorProps) {
  const [draft, setDraft] = useState("");
  const inputId = useId();

  function commitDraft() {
    if (!draft.trim()) return;
    onChange(normalizeTags([...tags, ...draft.split(",")]));
    setDraft("");
  }

  function removeTag(tag: string) {
    onChange(tags.filter((t) => t !== tag));
  }

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={inputId} className="text-meta font-medium text-fg">
        Tags
      </label>
      <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded border border-border bg-surface px-2 py-1 transition-colors duration-[120ms] focus-within:border-focus focus-within:ring-2 focus-within:ring-focus/30 hover:border-border-strong">
        {tags.map((tag) => (
          <span
            key={tag}
            className="flex items-center gap-1 rounded-sm bg-surface-active py-0.5 pl-2 pr-1 text-mono-sm text-fg"
          >
            {tag}
            <button
              type="button"
              onClick={() => removeTag(tag)}
              aria-label={`Remove tag ${tag}`}
              className="flex size-4 items-center justify-center rounded-sm text-icon hover:bg-surface-selected hover:text-fg"
            >
              <X aria-hidden className="size-3" />
            </button>
          </span>
        ))}
        <input
          id={inputId}
          type="text"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              commitDraft();
            } else if (e.key === "Backspace" && !draft && tags.length > 0) {
              onChange(tags.slice(0, -1));
            }
          }}
          onBlur={commitDraft}
          placeholder={tags.length === 0 ? "work, personal, …" : ""}
          className="min-w-24 flex-1 bg-transparent px-1 py-1 text-ui text-fg placeholder:text-faint focus:outline-none"
        />
      </div>
      <p className="text-meta text-muted">Press Enter or comma to add a tag.</p>
    </div>
  );
}
