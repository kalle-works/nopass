"use client";

import { useState } from "react";
import type { CardItem } from "@nopass/types";
import { Field } from "../../primitives/Field";
import { TagsEditor } from "./TagsEditor";
import { EditorActions, editorKeyHandler, submitHandler } from "./shared";

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

  function save() {
    onSave({
      type: "card",
      name,
      cardholderName,
      number,
      expMonth,
      expYear,
      cvv,
      tags,
      // Notes are not editable here but must survive an edit round-trip
      ...(initial?.notes && { notes: initial.notes }),
    });
  }

  return (
    <form onSubmit={submitHandler(save)} onKeyDown={editorKeyHandler(onCancel)} className="space-y-4">
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Name" />
      <Field
        label="Cardholder name"
        value={cardholderName}
        onChange={(e) => setCardholderName(e.target.value)}
        autoComplete="cc-name"
      />
      <Field
        label="Card number"
        value={number}
        onChange={(e) => setNumber(e.target.value)}
        autoComplete="off"
        maxLength={19}
        mono
      />
      <div className="grid grid-cols-3 gap-3">
        <Field
          label="Expiry month"
          value={expMonth}
          onChange={(e) => setExpMonth(e.target.value)}
          placeholder="MM"
          maxLength={2}
          mono
        />
        <Field
          label="Expiry year"
          value={expYear}
          onChange={(e) => setExpYear(e.target.value)}
          placeholder="YYYY"
          maxLength={4}
          mono
        />
        <Field
          label="CVV"
          type="password"
          revealable
          value={cvv}
          onChange={(e) => setCvv(e.target.value)}
          autoComplete="off"
          maxLength={4}
          mono
        />
      </div>
      <TagsEditor tags={tags} onChange={setTags} />
      <EditorActions onCancel={onCancel} saving={saving} />
    </form>
  );
}
