"use client";

import { useState } from "react";
import type { LoginItem } from "@nopass/types";

interface LoginEditorProps {
  initial?: Partial<LoginItem> | undefined;
  onSave: (item: LoginItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

function generatePassword(length = 20): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => chars[b % chars.length])
    .join("");
}

function passwordStrength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string; color: string } {
  if (!pw) return { score: 0, label: "", color: "" };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["", "Weak", "Fair", "Strong", "Very strong"];
  const colors = ["", "bg-red-500", "bg-amber-400", "bg-blue-500", "bg-green-500"];
  return { score: score as 0 | 1 | 2 | 3 | 4, label: labels[score]!, color: colors[score]! };
}

export function LoginEditor({ initial, onSave, onCancel, saving }: LoginEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState(initial?.password ?? (!initial ? generatePassword() : ""));
  const [url, setUrl] = useState(initial?.urls?.[0] ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  const strength = passwordStrength(password);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({
      type: "login",
      name,
      username,
      password,
      urls: url ? [url] : [],
      ...(notes && { notes }),
      customFields: [],
    });
  }

  async function handleCopyPassword() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Field label="Name" required>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          placeholder="Name"
          className={inputClass}
        />
      </Field>

      <Field label="Username / Email">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="off"
          placeholder="Username or email"
          className={inputClass}
        />
      </Field>

      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Password</label>
          <button
            type="button"
            onClick={() => setPassword(generatePassword())}
            className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
          >
            Generate
          </button>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              className={`${inputClass} pr-20`}
            />
            <div className="absolute inset-y-0 right-0 flex items-center gap-0.5 pr-1">
              <button
                type="button"
                onClick={handleCopyPassword}
                disabled={!password}
                title="Copy password"
                className="p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-30"
              >
                {copied ? (
                  <svg className="w-3.5 h-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                ) : (
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                )}
              </button>
              <button
                type="button"
                onClick={() => setShowPassword((s) => !s)}
                className="p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                {showPassword ? (
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
          </div>
        </div>

        {/* Password strength */}
        {password && (
          <div className="mt-2 flex items-center gap-2">
            <div className="flex gap-0.5 flex-1">
              {[1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className={`h-1 flex-1 rounded-full transition-colors ${
                    i <= strength.score ? strength.color : "bg-gray-200 dark:bg-gray-700"
                  }`}
                />
              ))}
            </div>
            <span className="text-xs text-gray-500 dark:text-gray-400 shrink-0">{strength.label}</span>
          </div>
        )}
      </div>

      <Field label="Website URL">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://"
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
