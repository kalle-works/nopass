export type GlyphKind = "letter" | "digit" | "symbol";

/** Fixed mask so the rendered length never reveals the secret's length. */
export const SECRET_MASK = "••••••••••••";

export function glyphKind(ch: string): GlyphKind {
  if (/^\p{Nd}$/u.test(ch)) return "digit";
  if (/^\p{L}$/u.test(ch)) return "letter";
  return "symbol";
}

/**
 * Splits a secret into runs of the same glyph kind. Iterates by code point so
 * astral characters (emoji, some scripts) are never split into lone surrogates.
 */
export function glyphRuns(value: string): Array<{ kind: GlyphKind; text: string }> {
  const runs: Array<{ kind: GlyphKind; text: string }> = [];
  for (const ch of value) {
    const kind = glyphKind(ch);
    const last = runs[runs.length - 1];
    if (last && last.kind === kind) last.text += ch;
    else runs.push({ kind, text: ch });
  }
  return runs;
}
