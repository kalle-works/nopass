"use client";

import { useState } from "react";
import type { SshKeyItem } from "@nopass/types";
import { Field, TextAreaField } from "../../primitives/Field";
import { cx } from "../../primitives/cx";
import { TagsEditor } from "./TagsEditor";
import { EditorActions, editorKeyHandler, submitHandler } from "./shared";

interface SshKeyEditorProps {
  initial?: Partial<SshKeyItem> | undefined;
  onSave: (item: SshKeyItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function SshKeyEditor({ initial, onSave, onCancel, saving }: SshKeyEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);
  const [privateKey, setPrivateKey] = useState(initial?.privateKey ?? "");
  const [publicKey, setPublicKey] = useState(initial?.publicKey ?? "");
  const [passphrase, setPassphrase] = useState(initial?.passphrase ?? "");
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [useInAgent, setUseInAgent] = useState(initial?.useInAgent ?? true);

  function save() {
    onSave({
      type: "ssh_key",
      name,
      privateKey,
      ...(publicKey && { publicKey }),
      ...(passphrase && { passphrase }),
      ...(comment && { comment }),
      ...(notes && { notes }),
      tags,
      useInAgent,
    });
  }

  return (
    <form onSubmit={submitHandler(save)} onKeyDown={editorKeyHandler(onCancel)} className="space-y-4">
      <Field
        label="Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        required
        placeholder="e.g. GitHub deploy key"
      />
      <TextAreaField
        label="Private key"
        value={privateKey}
        onChange={(e) => setPrivateKey(e.target.value)}
        required
        rows={8}
        placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"}
        spellCheck={false}
        mono
        className="[&_textarea]:resize-none [&_textarea]:text-mono-sm"
      />
      <Field
        label="Public key"
        value={publicKey}
        onChange={(e) => setPublicKey(e.target.value)}
        placeholder="ssh-ed25519 AAAA… user@host"
        spellCheck={false}
        mono
      />
      <Field
        label="Passphrase"
        type="password"
        revealable
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
        autoComplete="off"
        hint="Leave empty if the key has no passphrase."
      />
      <Field
        label="Comment"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        placeholder="e.g. user@host"
      />
      <TextAreaField
        label="Notes"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={3}
        placeholder="Optional notes"
      />

      <div className="flex items-center justify-between gap-3 rounded-lg border border-divider px-4 py-3">
        <div>
          <p id="ssh-agent-label" className="text-ui font-medium text-fg">
            Use in SSH agent
          </p>
          <p className="text-meta text-muted">Expose this key through the nopwd agent socket.</p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={useInAgent}
          aria-labelledby="ssh-agent-label"
          onClick={() => setUseInAgent((v) => !v)}
          className={cx(
            "relative flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors duration-[120ms]",
            useInAgent ? "border-accent bg-accent" : "border-border bg-surface-active",
          )}
        >
          <span
            className={cx(
              "pointer-events-none inline-block size-3.5 rounded-full transition-transform duration-[120ms]",
              useInAgent ? "translate-x-[18px] bg-accent-fg" : "translate-x-0.5 bg-muted",
            )}
          />
        </button>
      </div>

      <TagsEditor tags={tags} onChange={setTags} />
      <EditorActions onCancel={onCancel} saving={saving} />
    </form>
  );
}
