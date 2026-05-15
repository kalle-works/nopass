"use client";

import { useState } from "react";
import type { CardItem } from "@nopass/types";

interface CardEditorProps {
  initial?: Partial<CardItem> | undefined;
  onSave: (item: CardItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function CardEditor({ initial, onSave, onCancel, saving }: CardEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [cardholderName, setCardholderName] = useState(initial?.cardholderName ?? "");
  const [number, setNumber] = useState(initial?.number ?? "");
  const [expMonth, setExpMonth] = useState(initial?.expMonth ?? "");
  const [expYear, setExpYear] = useState(initial?.expYear ?? "");
  const [cvv, setCvv] = useState(initial?.cvv ?? "");
  const [showCvv, setShowCvv] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({ type: "card", name, cardholderName, number, expMonth, expYear, cvv });
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
        <input type="text" value={number} onChange={(e) => setNumber(e.target.value)} autoComplete="off" maxLength={19} className={input} />
      </Field>
      <div className="flex gap-3">
        <Field label="Expiry month">
          <input type="text" value={expMonth} onChange={(e) => setExpMonth(e.target.value)} placeholder="MM" maxLength={2} className={input} />
        </Field>
        <Field label="Expiry year">
          <input type="text" value={expYear} onChange={(e) => setExpYear(e.target.value)} placeholder="YYYY" maxLength={4} className={input} />
        </Field>
        <Field label="CVV">
          <div className="flex gap-1">
            <input type={showCvv ? "text" : "password"} value={cvv} onChange={(e) => setCvv(e.target.value)} autoComplete="off" maxLength={4} className={`${input} flex-1`} />
            <button type="button" onClick={() => setShowCvv((s) => !s)} className="px-2 text-xs text-gray-500 border border-gray-300 dark:border-gray-600 rounded-lg">
              {showCvv ? "Hide" : "Show"}
            </button>
          </div>
        </Field>
      </div>
      <div className="flex justify-end gap-3 pt-2">
        <button type="button" onClick={onCancel} className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg">Cancel</button>
        <button type="submit" disabled={saving} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg font-medium">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </form>
  );
}

const input = "w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500";

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div className="flex-1">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}{required && <span className="text-red-500 ml-0.5">*</span>}
      </label>
      {children}
    </div>
  );
}
