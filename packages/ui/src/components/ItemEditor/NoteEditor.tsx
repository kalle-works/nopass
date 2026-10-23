"use client";

import { useState } from "react";
import type { NoteItem } from "@nopass/types";
import { Field, TextAreaField } from "../../primitives/Field";
import { TagsEditor } from "./TagsEditor";
import { EditorActions, editorKeyHandler, submitHandler } from "./shared";

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

  return (
    <form
      onSubmit={submitHandler(() => onSave({ type: "note", name, content, tags }))}
      onKeyDown={editorKeyHandler(onCancel)}
      className="space-y-4"
    >
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Name" />
      <TextAreaField label="Content" value={content} onChange={(e) => setContent(e.target.value)} rows={8} />
      <TagsEditor tags={tags} onChange={setTags} />
      <EditorActions onCancel={onCancel} saving={saving} />
    </form>
  );
}
