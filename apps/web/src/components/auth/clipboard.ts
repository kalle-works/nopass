const CLEAR_AFTER_MS = 30_000;

/**
 * Copies text and clears the clipboard 30 seconds later, but only if it still
 * holds the copied value. Returns false when the browser denies the write.
 * If the browser denies reading the clipboard back, the clear is skipped.
 */
export async function copySecret(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
    } catch {
      // Read access denied or page not focused; leave the clipboard alone.
    }
  }, CLEAR_AFTER_MS);
  return true;
}
