"use client";

import { useState } from "react";
import type { CardItem } from "@nopass/types";
import { TagsEditor } from "./TagsEditor";

interface CardEditorProps {
  initial?: Partial<CardItem> | undefined;
  onSave: (item: CardItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function CardEditor({ initial, onSave, onCancel, saving }: CardEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);
  const [cardholderName, setCardholderName] = useState(initial?.cardholderName ?? "");
  const [number, setNumber] = useState(initial?.number ?? "");
  const [expMonth, setExpMonth] = useState(initial?.expMonth ?? "");
  const [expYear, setExpYear] = useState(initial?.expYear ?? "");
  const [cvv, setCvv] = useState(initial?.cvv ?? "");
  const [showCvv, setShowCvv] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({ type: "card", name, cardholderName, number, expMonth, expYear, cvv, tags });
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Field label="Name" required>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} required className={input} />
      </Field>
      <Field label="Cardholder name">
        <input type="text" value={cardholderName} onChange={(e) => setCardholderName(e.target.value)} autoComplete="cc-name" className={input} />
      </Field>
      <Field label="Card number">
        <input type="text" value={number} onChange={(e) => setNumber(e.target.value)} autoComplete="off" maxLength={19} className={`${input} font-mono`} />
      </Field>
      <div className="flex gap-3">
        <Field label="Expiry month">
          <input type="text" value={expMonth} onChange={(e) => setExpMonth(e.target.value)} placeholder="MM" maxLength={2} className={`${input} font-mono`} />
        </Field>
        <Field label="Expiry year">
          <input type="text" value={expYear} onChange={(e) => setExpYear(e.target.value)} placeholder="YYYY" maxLength={4} className={`${input} font-mono`} />
        </Field>
        <Field label="CVV">
          <div className="flex gap-1">
            <input type={showCvv ? "text" : "password"} value={cvv} onChange={(e) => setCvv(e.target.value)} autoComplete="off" maxLength={4} className={`${input} flex-1 font-mono`} />
            <button
              type="button"
              onClick={() => setShowCvv((s) => !s)}
              className="px-2 font-mono text-xs text-[#9C988D] border border-[#2B2923] hover:text-[#F4F1E8] hover:border-[#9C988D] transition-colors"
            >
              {showCvv ? "Hide" : "Show"}
            </button>
          </div>
        </Field>
      </div>
      <TagsEditor tags={tags} onChange={setTags} />
      <div className="flex justify-end gap-3 pt-2 border-t border-[#2B2923]">
        <button type="button" onClick={onCancel} className="px-4 py-2 font-mono text-xs text-[#9C988D] border border-[#2B2923] hover:border-[#9C988D] hover:text-[#F4F1E8] transition-colors">
          Cancel
        </button>
        <button type="submit" disabled={saving} className="px-4 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] disabled:opacity-50 text-[#070706] transition-colors">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

const input =
  "w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors";

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div className="flex-1">
      <label className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest block mb-1.5">
        {label}{required && <span className="text-[#E8321A] ml-0.5"> *</span>}
      </label>
      {children}
    </div>
  );
}
