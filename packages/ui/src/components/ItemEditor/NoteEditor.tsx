"use client";

import { useState } from "react";
import type { NoteItem } from "@nopass/types";

interface NoteEditorProps {
  initial?: Partial<NoteItem> | undefined;
  onSave: (item: NoteItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function NoteEditor({ initial, onSave, onCancel, saving }: NoteEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [content, setContent] = useState(initial?.content ?? "");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({ type: "note", name, content });
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Name <span className="text-red-500">*</span>
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
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          Content
        </label>
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={8}
          className={`${inputClass} resize-y`}
        />
      </div>
      <div className="flex justify-end gap-3 pt-2">
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
  "w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500";
const cancelClass =
  "px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors";
const saveClass =
  "px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg font-medium transition-colors";
