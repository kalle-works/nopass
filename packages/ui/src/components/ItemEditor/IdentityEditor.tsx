"use client";

import { useState } from "react";
import type { IdentityItem } from "@nopass/types";
import { Field } from "../../primitives/Field";
import { TagsEditor } from "./TagsEditor";
import { EditorActions, editorKeyHandler, submitHandler } from "./shared";

interface IdentityEditorProps {
  initial?: Partial<IdentityItem> | undefined;
  onSave: (item: IdentityItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function IdentityEditor({ initial, onSave, onCancel, saving }: IdentityEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [tags, setTags] = useState<string[]>(initial?.tags ?? []);
  const [firstName, setFirstName] = useState(initial?.firstName ?? "");
  const [lastName, setLastName] = useState(initial?.lastName ?? "");
  const [email, setEmail] = useState(initial?.email ?? "");
  const [phone, setPhone] = useState(initial?.phone ?? "");
  const [address, setAddress] = useState(initial?.address ?? "");
  const [city, setCity] = useState(initial?.city ?? "");
  const [country, setCountry] = useState(initial?.country ?? "");

  return (
    <form
      onSubmit={submitHandler(() =>
        onSave({ type: "identity", name, firstName, lastName, email, phone, address, city, country, tags }),
      )}
      onKeyDown={editorKeyHandler(onCancel)}
      className="space-y-4"
    >
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Name" />
      <div className="grid grid-cols-2 gap-3">
        <Field label="First name" value={firstName} onChange={(e) => setFirstName(e.target.value)} />
        <Field label="Last name" value={lastName} onChange={(e) => setLastName(e.target.value)} />
      </div>
      <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <Field label="Phone" type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} />
      <Field label="Address" value={address} onChange={(e) => setAddress(e.target.value)} />
      <div className="grid grid-cols-2 gap-3">
        <Field label="City" value={city} onChange={(e) => setCity(e.target.value)} />
        <Field label="Country" value={country} onChange={(e) => setCountry(e.target.value)} />
      </div>
      <TagsEditor tags={tags} onChange={setTags} />
      <EditorActions onCancel={onCancel} saving={saving} />
    </form>
  );
}
