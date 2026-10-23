import { useCallback, useEffect, useState } from "react";
import { THEME_STORAGE_KEY as STORAGE_KEY } from "../theme-boot";

export { THEME_BOOT_SCRIPT } from "../theme-boot";

export type ThemePreference = "system" | "light" | "dark";

export function readThemePreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyThemePreference(pref: ThemePreference) {
  const root = document.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
}

export function useThemePreference(): [ThemePreference, (p: ThemePreference) => void] {
  const [pref, setPref] = useState<ThemePreference>("system");
  useEffect(() => setPref(readThemePreference()), []);
  const update = useCallback((p: ThemePreference) => {
    setPref(p);
    applyThemePreference(p);
    try {
      if (p === "system") localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, p);
    } catch {
      // Storage blocked: the choice lasts for this page only.
    }
  }, []);
  return [pref, update];
}
