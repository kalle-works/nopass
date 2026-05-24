"use client";

import { useState, useRef, useEffect } from "react";
import type { LoginItem, CustomField } from "@nopass/types";

interface LoginEditorProps {
  initial?: Partial<LoginItem> | undefined;
  onSave: (item: LoginItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

interface GeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

function buildCharset(opts: GeneratorOptions): string {
  let chars = "";
  if (opts.uppercase) chars += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (opts.lowercase) chars += "abcdefghjkmnpqrstuvwxyz";
  if (opts.numbers) chars += "23456789";
  if (opts.symbols) chars += "!@#$%^&*-_+=?";
  return chars || "abcdefghjkmnpqrstuvwxyz";
}

function generatePassword(opts: GeneratorOptions): string {
  const chars = buildCharset(opts);
  const array = new Uint8Array(opts.length);
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

const DEFAULT_OPTS: GeneratorOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

function GeneratorPopover({ onUse, onClose }: { onUse: (pw: string) => void; onClose: () => void }) {
  const [opts, setOpts] = useState<GeneratorOptions>(DEFAULT_OPTS);
  const [preview, setPreview] = useState(() => generatePassword(DEFAULT_OPTS));
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [onClose]);

  function update(next: Partial<GeneratorOptions>) {
    const merged = { ...opts, ...next };
    setOpts(merged);
    setPreview(generatePassword(merged));
  }

  function regenerate() {
    setPreview(generatePassword(opts));
  }

  const toggle = (key: keyof Pick<GeneratorOptions, "uppercase" | "lowercase" | "numbers" | "symbols">) => {
    const next = { ...opts, [key]: !opts[key] };
    const anyOn = next.uppercase || next.lowercase || next.numbers || next.symbols;
    if (!anyOn) return;
    update(next);
  };

  return (
    <div ref={ref} className="absolute right-0 top-full mt-1 z-50 w-72 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-4 space-y-4">
      <div className="flex items-center gap-2">
        <span className="flex-1 font-mono text-sm text-gray-900 dark:text-white bg-gray-50 dark:bg-gray-700 rounded-lg px-3 py-1.5 break-all">{preview}</span>
        <button type="button" onClick={regenerate} title="Regenerate" className="p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 shrink-0">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
            <path d="M1 4v6h6M23 20v-6h-6" /><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15" />
          </svg>
        </button>
      </div>

      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs font-medium text-gray-600 dark:text-gray-400">Length: {opts.length}</span>
        </div>
        <input
          type="range"
          min={8}
          max={64}
          value={opts.length}
          onChange={(e) => update({ length: Number(e.target.value) })}
          className="w-full accent-blue-600"
        />
        <div className="flex justify-between text-[10px] text-gray-400 -mt-0.5">
          <span>8</span><span>64</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {(["uppercase", "lowercase", "numbers", "symbols"] as const).map((key) => (
          <label key={key} className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={opts[key]}
              onChange={() => toggle(key)}
              className="accent-blue-600 w-3.5 h-3.5"
            />
            <span className="text-xs text-gray-700 dark:text-gray-300 capitalize">{key}</span>
          </label>
        ))}
      </div>

      <button
        type="button"
        onClick={() => { onUse(preview); onClose(); }}
        className="w-full py-2 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
      >
        Use this password
      </button>
    </div>
  );
}

function TotpField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [showScanner, setShowScanner] = useState(false);

  function parseOtpUri(input: string): string {
    const trimmed = input.trim();
    if (trimmed.startsWith("otpauth://")) return trimmed;
    // Treat bare base32 secret as a TOTP URI
    const secret = trimmed.replace(/\s/g, "").toUpperCase();
    if (/^[A-Z2-7]+=*$/.test(secret)) {
      return `otpauth://totp/nopwd?secret=${secret}&issuer=nopwd`;
    }
    return trimmed;
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(parseOtpUri(e.target.value))}
          placeholder="otpauth://totp/… or bare secret key"
          autoComplete="off"
          className={inputClass}
        />
        {value && (
          <button
            type="button"
            onClick={() => onChange("")}
            title="Remove TOTP"
            className="p-2 text-gray-400 hover:text-red-500 transition-colors shrink-0"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        )}
      </div>
      <p className="text-[11px] text-gray-400 dark:text-gray-500">
        Paste a <code className="font-mono">otpauth://</code> URI from your authenticator app, or the raw base32 secret key.
      </p>
    </div>
  );
}

function CustomFieldsEditor({
  fields,
  onChange,
}: {
  fields: CustomField[];
  onChange: (fields: CustomField[]) => void;
}) {
  function add() {
    onChange([...fields, { name: "", value: "", fieldType: "text" }]);
  }

  function remove(i: number) {
    onChange(fields.filter((_, idx) => idx !== i));
  }

  function update(i: number, patch: Partial<CustomField>) {
    onChange(fields.map((f, idx) => (idx === i ? { ...f, ...patch } : f)));
  }

  return (
    <div className="space-y-2">
      {fields.map((field, i) => (
        <div key={i} className="flex items-start gap-2">
          <input
            type="text"
            value={field.name}
            onChange={(e) => update(i, { name: e.target.value })}
            placeholder="Field name"
            className={`${inputClass} w-28 shrink-0`}
          />
          <div className="relative flex-1">
            <input
              type={field.fieldType === "hidden" ? "password" : "text"}
              value={field.value}
              onChange={(e) => update(i, { value: e.target.value })}
              placeholder="Value"
              autoComplete="off"
              className={inputClass}
            />
          </div>
          <select
            value={field.fieldType}
            onChange={(e) => update(i, { fieldType: e.target.value as CustomField["fieldType"] })}
            className="py-2 px-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs focus:outline-none"
            title="Field type"
          >
            <option value="text">Text</option>
            <option value="hidden">Secret</option>
          </select>
          <button
            type="button"
            onClick={() => remove(i)}
            className="p-2 text-gray-400 hover:text-red-500 transition-colors shrink-0"
            title="Remove field"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={add}
        className="flex items-center gap-1.5 text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
          <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
        </svg>
        Add field
      </button>
    </div>
  );
}

export function LoginEditor({ initial, onSave, onCancel, saving }: LoginEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState(initial?.password ?? (!initial ? generatePassword(DEFAULT_OPTS) : ""));
  const [url, setUrl] = useState(initial?.urls?.[0] ?? "");
  const [totp, setTotp] = useState(initial?.totp ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [customFields, setCustomFields] = useState<CustomField[]>(initial?.customFields ?? []);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(!!(initial?.totp || initial?.customFields?.length));

  const strength = passwordStrength(password);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({
      type: "login",
      name,
      username,
      password,
      urls: url ? [url] : [],
      ...(totp && { totp }),
      ...(notes && { notes }),
      customFields,
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
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowGenerator((s) => !s)}
              className="text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
            >
              Generate
            </button>
            {showGenerator && (
              <GeneratorPopover
                onUse={(pw) => { setPassword(pw); setShowPassword(true); }}
                onClose={() => setShowGenerator(false)}
              />
            )}
          </div>
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

      {/* Advanced: TOTP + custom fields */}
      <div>
        <button
          type="button"
          onClick={() => setShowAdvanced((s) => !s)}
          className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
        >
          <svg
            className={`w-3.5 h-3.5 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M9 18l6-6-6-6" />
          </svg>
          {showAdvanced ? "Hide" : "Show"} two-factor auth &amp; custom fields
        </button>

        {showAdvanced && (
          <div className="mt-3 space-y-4 pl-4 border-l-2 border-gray-100 dark:border-gray-700">
            <Field label="Two-factor auth (TOTP)">
              <TotpField value={totp} onChange={setTotp} />
            </Field>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Custom fields
              </label>
              <CustomFieldsEditor fields={customFields} onChange={setCustomFields} />
            </div>
          </div>
        )}
      </div>

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
