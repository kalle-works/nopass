"use client";

import { useState } from "react";
import type { IdentityItem } from "@nopass/types";

interface IdentityEditorProps {
  initial?: Partial<IdentityItem> | undefined;
  onSave: (item: IdentityItem) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function IdentityEditor({ initial, onSave, onCancel, saving }: IdentityEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [firstName, setFirstName] = useState(initial?.firstName ?? "");
  const [lastName, setLastName] = useState(initial?.lastName ?? "");
  const [email, setEmail] = useState(initial?.email ?? "");
  const [phone, setPhone] = useState(initial?.phone ?? "");
  const [address, setAddress] = useState(initial?.address ?? "");
  const [city, setCity] = useState(initial?.city ?? "");
  const [country, setCountry] = useState(initial?.country ?? "");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    onSave({ type: "identity", name, firstName, lastName, email, phone, address, city, country });
  }

  const inp =
    "w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors";
  const lbl = "font-mono text-[10px] text-[#9C988D] uppercase tracking-widest block mb-1.5";

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className={lbl}>Name <span className="text-[#E8321A]">*</span></label>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} required className={inp} />
      </div>
      <div className="flex gap-3">
        <div className="flex-1">
          <label className={lbl}>First name</label>
          <input type="text" value={firstName} onChange={(e) => setFirstName(e.target.value)} className={inp} />
        </div>
        <div className="flex-1">
          <label className={lbl}>Last name</label>
          <input type="text" value={lastName} onChange={(e) => setLastName(e.target.value)} className={inp} />
        </div>
      </div>
      <div>
        <label className={lbl}>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className={inp} />
      </div>
      <div>
        <label className={lbl}>Phone</label>
        <input type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} className={inp} />
      </div>
      <div>
        <label className={lbl}>Address</label>
        <input type="text" value={address} onChange={(e) => setAddress(e.target.value)} className={inp} />
      </div>
      <div className="flex gap-3">
        <div className="flex-1">
          <label className={lbl}>City</label>
          <input type="text" value={city} onChange={(e) => setCity(e.target.value)} className={inp} />
        </div>
        <div className="flex-1">
          <label className={lbl}>Country</label>
          <input type="text" value={country} onChange={(e) => setCountry(e.target.value)} className={inp} />
        </div>
      </div>
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
