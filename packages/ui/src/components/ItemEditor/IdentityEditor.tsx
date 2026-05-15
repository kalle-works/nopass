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

  const inp = "w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500";

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name *</label>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} required className={inp} />
      </div>
      <div className="flex gap-3">
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">First name</label>
          <input type="text" value={firstName} onChange={(e) => setFirstName(e.target.value)} className={inp} />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Last name</label>
          <input type="text" value={lastName} onChange={(e) => setLastName(e.target.value)} className={inp} />
        </div>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className={inp} />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Phone</label>
        <input type="tel" value={phone} onChange={(e) => setPhone(e.target.value)} className={inp} />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Address</label>
        <input type="text" value={address} onChange={(e) => setAddress(e.target.value)} className={inp} />
      </div>
      <div className="flex gap-3">
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">City</label>
          <input type="text" value={city} onChange={(e) => setCity(e.target.value)} className={inp} />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Country</label>
          <input type="text" value={country} onChange={(e) => setCountry(e.target.value)} className={inp} />
        </div>
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
