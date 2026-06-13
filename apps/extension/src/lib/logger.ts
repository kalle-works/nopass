// Lightweight debug logger for the extension service worker.
// Controlled by __LOG__ (injected at build time). Always active in dev;
// set VITE_LOG=1 to enable in a production build.
//
// Errors are always emitted regardless of __LOG__ — they are actionable.

declare const __LOG__: boolean;

const enabled = typeof __LOG__ !== "undefined" && __LOG__;

export const log = {
  debug(msg: string, data?: Record<string, unknown>): void {
    if (enabled) console.debug("[nopass:sw]", msg, data ?? "");
  },
  info(msg: string, data?: Record<string, unknown>): void {
    if (enabled) console.info("[nopass:sw]", msg, data ?? "");
  },
  warn(msg: string, data?: Record<string, unknown>): void {
    if (enabled) console.warn("[nopass:sw]", msg, data ?? "");
  },
  error(msg: string, data?: Record<string, unknown>): void {
    console.error("[nopass:sw]", msg, data ?? "");
  },
};
