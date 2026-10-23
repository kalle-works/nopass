"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronRight, Copy, RefreshCw, X } from "lucide-react";
import type { LoginItem, CustomField } from "@nopass/types";
import { Button, IconButton } from "../../primitives/Button";
import { Field, TextAreaField, inputClass } from "../../primitives/Field";
import { SecretText } from "../../primitives/Secret";
import { StrengthMeter } from "../../primitives/StrengthMeter";
import { cx } from "../../primitives/cx";
import { TagsEditor } from "./TagsEditor";
import { EditorActions, editorKeyHandler, submitHandler } from "./shared";

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

  const toggle = (key: "uppercase" | "lowercase" | "numbers" | "symbols") => {
    const next = { ...opts, [key]: !opts[key] };
    const anyOn = next.uppercase || next.lowercase || next.numbers || next.symbols;
    if (!anyOn) return;
    update(next);
  };

  return (
    <div
      ref={ref}
      role="dialog"
      aria-label="Password generator"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose();
        }
      }}
      className="absolute right-0 top-full z-30 mt-1 w-72 space-y-4 rounded-lg border border-divider bg-surface p-4 shadow-overlay"
    >
      <div className="flex items-start gap-2">
        <div className="min-h-9 flex-1 rounded border border-divider bg-bg-subtle px-3 py-1.5 text-mono-sm">
          <SecretText value={preview} />
        </div>
        <IconButton label="Regenerate" onClick={() => setPreview(generatePassword(opts))}>
          <RefreshCw aria-hidden className="size-4" />
        </IconButton>
      </div>

      <div>
        <label htmlFor="generator-length" className="mb-1 block text-meta font-medium text-fg">
          Length: <span className="tabular-nums">{opts.length}</span>
        </label>
        <input
          id="generator-length"
          type="range"
          min={8}
          max={64}
          value={opts.length}
          onChange={(e) => update({ length: Number(e.target.value) })}
          className="w-full accent-accent"
        />
        <div className="flex justify-between text-mono-sm text-muted">
          <span>8</span>
          <span>64</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {(["uppercase", "lowercase", "numbers", "symbols"] as const).map((key) => (
          <label key={key} className="flex cursor-pointer items-center gap-2 text-ui text-fg">
            <input
              type="checkbox"
              checked={opts[key]}
              onChange={() => toggle(key)}
              className="size-4 accent-accent"
            />
            <span className="capitalize">{key}</span>
          </label>
        ))}
      </div>

      <Button
        type="button"
        variant="secondary"
        className="w-full"
        onClick={() => {
          onUse(preview);
          onClose();
        }}
      >
        Use this password
      </Button>
    </div>
  );
}

function parseOtpUri(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith("otpauth://")) return trimmed;
  const secret = trimmed.replace(/\s/g, "").toUpperCase();
  if (/^[A-Z2-7]+=*$/.test(secret)) {
    return `otpauth://totp/nopwd?secret=${secret}&issuer=nopwd`;
  }
  return trimmed;
}

function CustomFieldsEditor({
  fields,
  onChange,
}: {
  fields: CustomField[];
  onChange: (fields: CustomField[]) => void;
}) {
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
            aria-label={`Custom field ${i + 1} name`}
            className={cx(inputClass, "h-9 w-28 shrink-0")}
          />
          <input
            type={field.fieldType === "hidden" ? "password" : "text"}
            value={field.value}
            onChange={(e) => update(i, { value: e.target.value })}
            placeholder="Value"
            autoComplete="off"
            aria-label={`Custom field ${i + 1} value`}
            className={cx(inputClass, "h-9 min-w-0 flex-1")}
          />
          <select
            value={field.fieldType}
            onChange={(e) => update(i, { fieldType: e.target.value as CustomField["fieldType"] })}
            aria-label={`Custom field ${i + 1} type`}
            className={cx(inputClass, "h-9 w-24 shrink-0 px-2")}
          >
            <option value="text">Text</option>
            <option value="hidden">Secret</option>
          </select>
          <IconButton label="Remove field" onClick={() => onChange(fields.filter((_, idx) => idx !== i))}>
            <X aria-hidden className="size-4" />
          </IconButton>
        </div>
      ))}
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={() => onChange([...fields, { name: "", value: "", fieldType: "text" }])}
      >
        Add field
      </Button>
    </div>
  );
}

export function LoginEditor({ initial, onSave, onCancel, saving }: LoginEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState(initial?.password ?? (!initial ? generatePassword(DEFAULT_OPTS) : ""));
  const [url, setUrl] = useState(initial?.urls?.[0] ?? "");
  const [totp, setTotp] = useState(initial?.totp ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [customFields, setCustomFields] = useState<CustomField[]>(initial?.customFields ?? []);
  const [copied, setCopied] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(!!(initial?.totp || initial?.customFields?.length));
  // Name and username are penalised by the estimator so "github" style passwords score low
  const strengthInputs = useMemo(() => [name, username].filter(Boolean), [name, username]);

  function save() {
    onSave({
      type: "login",
      name,
      username,
      password,
      urls: url ? [url] : [],
      ...(totp && { totp }),
      ...(notes && { notes }),
      tags,
      customFields,
      // Passkeys are created by the extension; an edit here must not drop them
      ...(initial?.passkey && { passkey: initial.passkey }),
    });
  }

  async function handleCopyPassword() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <form onSubmit={submitHandler(save)} onKeyDown={editorKeyHandler(onCancel)} className="space-y-4">
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Name" />

      <Field
        label="Username or email"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        autoComplete="off"
        placeholder="Username or email"
      />

      <div className="space-y-2">
        <Field
          label="Password"
          type="password"
          revealable
          mono
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="off"
          action={
            <div className="relative flex items-center gap-3">
              <button
                type="button"
                onClick={handleCopyPassword}
                disabled={!password}
                className="inline-flex items-center gap-1 text-meta text-muted hover:text-fg disabled:opacity-50"
              >
                {copied ? <Check aria-hidden className="size-3.5 text-success" /> : <Copy aria-hidden className="size-3.5" />}
                {copied ? "Copied" : "Copy"}
              </button>
              <button
                type="button"
                onClick={() => setShowGenerator((s) => !s)}
                aria-expanded={showGenerator}
                className="text-meta font-medium text-accent-text hover:underline"
              >
                Generate
              </button>
              {showGenerator && (
                <GeneratorPopover onUse={(pw) => setPassword(pw)} onClose={() => setShowGenerator(false)} />
              )}
            </div>
          }
        />
        {password && <StrengthMeter password={password} userInputs={strengthInputs} />}
      </div>

      <Field
        label="Website URL"
        type="url"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://"
      />

      <TextAreaField
        label="Notes"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={3}
        placeholder="Optional notes"
      />

      <div>
        <button
          type="button"
          onClick={() => setShowAdvanced((s) => !s)}
          aria-expanded={showAdvanced}
          className="flex items-center gap-1.5 rounded text-ui text-muted hover:text-fg"
        >
          <ChevronRight
            aria-hidden
            className={cx("size-4 transition-transform duration-[120ms]", showAdvanced && "rotate-90")}
          />
          One-time password and custom fields
        </button>

        {showAdvanced && (
          <div className="mt-3 space-y-4 border-l-2 border-divider pl-4">
            <Field
              label="One-time password (TOTP)"
              value={totp}
              onChange={(e) => setTotp(parseOtpUri(e.target.value))}
              placeholder="otpauth://totp/… or bare secret key"
              autoComplete="off"
              mono
              hint="Paste an otpauth:// URI from your authenticator app, or the raw base32 secret."
              action={
                totp ? (
                  <button
                    type="button"
                    onClick={() => setTotp("")}
                    className="text-meta text-muted hover:text-fg"
                  >
                    Remove TOTP
                  </button>
                ) : undefined
              }
            />

            <div role="group" aria-labelledby="custom-fields-label" className="flex flex-col gap-1.5">
              <span id="custom-fields-label" className="text-meta font-medium text-fg">
                Custom fields
              </span>
              <CustomFieldsEditor fields={customFields} onChange={setCustomFields} />
            </div>
          </div>
        )}
      </div>

      <TagsEditor tags={tags} onChange={setTags} />
      <EditorActions onCancel={onCancel} saving={saving} />
    </form>
  );
}
