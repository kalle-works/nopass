"use client";

import { useState } from "react";

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

  function commitDraft() {
    if (!draft.trim()) return;
    onChange(normalizeTags([...tags, ...draft.split(",")]));
    setDraft("");
  }

  function removeTag(tag: string) {
    onChange(tags.filter((t) => t !== tag));
  }

  return (
    <div>
      <label className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest block mb-1.5">
        Tags
      </label>
      <div className="flex flex-wrap items-center gap-1.5 px-2 py-1.5 border border-[#2B2923] bg-[#070706] focus-within:border-[#D6FF3F] transition-colors">
        {tags.map((tag) => (
          <span
            key={tag}
            className="flex items-center gap-1 px-2 py-0.5 font-mono text-xs bg-[#181713] border border-[#2B2923] text-[#F4F1E8]"
          >
            {tag}
            <button
              type="button"
              onClick={() => removeTag(tag)}
              aria-label={`Remove tag ${tag}`}
              className="text-[#9C988D] hover:text-[#E8321A] transition-colors leading-none"
            >
              ×
            </button>
          </span>
        ))}
        <input
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
          className="flex-1 min-w-24 px-1 py-1 bg-transparent text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none"
        />
      </div>
    </div>
  );
}
