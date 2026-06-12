"use client";

import { useState } from "react";
import type { NoteItem } from "@nopass/types";
import { TagsEditor } from "./TagsEditor";

interface NoteEditorProps {
  initial?: Partial<NoteItem> | undefined;
  onSave: (item: NoteItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function NoteEditor({ initial, onSave, onCancel, saving }: NoteEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [content, setContent] = useState(initial?.content ?? "");
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({ type: "note", name, content, ...(tags.length > 0 ? { tags } : {}) });
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest block mb-1.5">
          Name <span className="text-[#E8321A]">*</span>
        </label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          className={inputClass}
        />
      </div>
      <div>
        <label className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest block mb-1.5">
          Content
        </label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={8}
          className={`${inputClass} resize-y`}
        />
      </div>
      <TagsEditor tags={tags} onChange={setTags} />
      <div className="flex justify-end gap-3 pt-2 border-t border-[#2B2923]">
        <button type="button" onClick={onCancel} className={cancelClass}>
          Cancel
        </button>
        <button type="submit" disabled={saving} className={saveClass}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

const inputClass =
  "w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors";
const cancelClass =
  "px-4 py-2 font-mono text-xs text-[#9C988D] border border-[#2B2923] hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors";
const saveClass =
  "px-4 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] disabled:opacity-50 text-[#070706] transition-colors";
