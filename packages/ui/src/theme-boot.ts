/** Server-safe: no React imports, so Next server components can use it. */
export const THEME_STORAGE_KEY = "nopwd-theme";

/** Inline script for <head> so the stored theme applies before first paint. */
export const THEME_BOOT_SCRIPT = `try{var t=localStorage.getItem("${THEME_STORAGE_KEY}");if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t)}catch(e){}`;
