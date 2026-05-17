"use client";

import { useState } from "react";
import type { SshKeyItem } from "@nopass/types";

interface SshKeyEditorProps {
  initial?: Partial<SshKeyItem> | undefined;
  onSave: (item: SshKeyItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function SshKeyEditor({ initial, onSave, onCancel, saving }: SshKeyEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [privateKey, setPrivateKey] = useState(initial?.privateKey ?? "");
  const [publicKey, setPublicKey] = useState(initial?.publicKey ?? "");
  const [passphrase, setPassphrase] = useState(initial?.passphrase ?? "");
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [useInAgent, setUseInAgent] = useState(initial?.useInAgent ?? true);
  const [showPassphrase, setShowPassphrase] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({
      type: "ssh_key",
      name,
      privateKey,
      ...(publicKey && { publicKey }),
      ...(passphrase && { passphrase }),
      ...(comment && { comment }),
      ...(notes && { notes }),
      useInAgent,
    });
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Field label="Name" required>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          placeholder="e.g. GitHub deploy key"
          className={inputClass}
        />
      </Field>

      <Field label="Private key" required>
        <textarea
          value={privateKey}
          onChange={(e) => setPrivateKey(e.target.value)}
          required
          rows={8}
          placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"}
          spellCheck={false}
          className={`${inputClass} resize-none font-mono text-xs`}
        />
      </Field>

      <Field label="Public key">
        <input
          type="text"
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          placeholder="ssh-ed25519 AAAA… user@host"
          spellCheck={false}
          className={`${inputClass} font-mono text-xs`}
        />
      </Field>

      <Field label="Passphrase">
        <div className="relative">
          <input
            type={showPassphrase ? "text" : "password"}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="off"
            placeholder="Leave empty if key has no passphrase"
            className={`${inputClass} pr-10`}
          />
          <button
            type="button"
            onClick={() => setShowPassphrase((s) => !s)}
            className="absolute inset-y-0 right-0 px-3 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            {showPassphrase ? (
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            ) : (
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
        </div>
      </Field>

      <Field label="Comment">
        <input
          type="text"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="e.g. user@host"
          className={inputClass}
        />
      </Field>

      <Field label="Notes">
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={3}
          placeholder="Optional notes…"
          className={`${inputClass} resize-none`}
        />
      </Field>

      <label className="flex items-center justify-between gap-3 py-1 cursor-pointer select-none">
        <div>
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Use in SSH agent</span>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            Expose this key via the nopass agent socket
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={useInAgent}
          onClick={() => setUseInAgent((v) => !v)}
          className={`relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 ${useInAgent ? "bg-blue-600" : "bg-gray-300 dark:bg-gray-600"}`}
        >
          <span
            className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${useInAgent ? "translate-x-4" : "translate-x-0"}`}
          />
        </button>
      </label>

      <FormActions onCancel={onCancel} {...(saving !== undefined && { saving })} />
    </form>
  );
}

const inputClass =
  "w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition";

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
        {label}
        {required && <span className="text-red-500 ml-0.5"> *</span>}
      </label>
      {children}
    </div>
  );
}

function FormActions({ onCancel, saving }: { onCancel: () => void; saving?: boolean }) {
  return (
    <div className="flex justify-end gap-3 pt-2 border-t border-gray-100 dark:border-gray-700">
      <button
        type="button"
        onClick={onCancel}
        className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
      >
        Cancel
      </button>
      <button
        type="submit"
        disabled={saving}
        className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 disabled:opacity-70 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
      >
        {saving && (
          <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        )}
        {saving ? "Saving…" : "Save"}
      </button>
    </div>
  );
}
