/** chrome.storage.local key holding the inactivity auto-lock timeout in minutes. */
export const AUTO_LOCK_SETTING = "autoLockMinutes";
export const DEFAULT_AUTO_LOCK_MINUTES = 15;
export const AUTO_LOCK_CHOICES = [1, 5, 15, 30, 60, 240] as const;

/** The stored timeout if it is one of the offered choices, else the default. */
export function parseAutoLockMinutes(stored: unknown): number {
  return AUTO_LOCK_CHOICES.includes(stored as (typeof AUTO_LOCK_CHOICES)[number])
    ? (stored as number)
    : DEFAULT_AUTO_LOCK_MINUTES;
}
