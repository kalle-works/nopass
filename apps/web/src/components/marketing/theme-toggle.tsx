"use client";

import { cx, useThemePreference, type ThemePreference } from "@nopass/ui";

const OPTIONS: Array<{ value: ThemePreference; label: string }> = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

export function ThemeToggle() {
  const [pref, setPref] = useThemePreference();
  return (
    <div role="group" aria-label="Theme" className="inline-flex rounded border border-border p-0.5">
      {OPTIONS.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={pref === o.value}
          onClick={() => setPref(o.value)}
          className={cx(
            "h-7 rounded-sm px-2.5 text-meta transition-colors duration-[120ms]",
            pref === o.value ? "bg-surface-active text-fg" : "text-muted hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
