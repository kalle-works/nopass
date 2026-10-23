import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { IconButton } from "./Button";
import { cx } from "./cx";
import { glyphRuns, SECRET_MASK } from "./secret-glyphs";

const GLYPH_CLASS = {
  letter: "text-fg",
  digit: "text-glyph-digit",
  symbol: "text-glyph-symbol",
} as const;

/** Monospace secret with digits and symbols colored. */
export function SecretText({ value, masked, className }: { value: string; masked?: boolean | undefined; className?: string | undefined }) {
  if (masked) {
    return (
      <span className={cx("font-mono tracking-wider text-muted", className)} aria-label="Hidden value">
        {SECRET_MASK}
      </span>
    );
  }
  return (
    <span className={cx("font-mono break-all", className)}>
      {glyphRuns(value).map((run, i) => (
        <span key={i} className={GLYPH_CLASS[run.kind]}>
          {run.text}
        </span>
      ))}
    </span>
  );
}

const REVEAL_TIMEOUT_MS = 30_000;

/** Reveal state that re-masks after 30s or when the window loses focus. */
export function useTimedReveal(): [boolean, () => void] {
  const [revealed, setRevealed] = useState(false);
  useEffect(() => {
    if (!revealed) return;
    const timer = setTimeout(() => setRevealed(false), REVEAL_TIMEOUT_MS);
    const hide = () => setRevealed(false);
    window.addEventListener("blur", hide);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("blur", hide);
    };
  }, [revealed]);
  return [revealed, useCallback(() => setRevealed((r) => !r), [])];
}

/** Inline "Copied" feedback that resets itself. */
export function useCopyFeedback(copy: (text: string) => Promise<boolean>) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const run = useCallback(
    async (text: string) => {
      const ok = await copy(text);
      if (!ok) return false;
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
      return true;
    },
    [copy],
  );
  return { copied, copy: run };
}

export interface SecretRowProps {
  label: string;
  value: string;
  /** Concealed values start masked and get a reveal toggle. */
  concealed?: boolean | undefined;
  mono?: boolean | undefined;
  copy: (text: string) => Promise<boolean>;
  warning?: ReactNode | undefined;
  trailing?: ReactNode | undefined;
  /** Renders the value as something other than text (e.g. a link). */
  renderValue?: (value: string) => ReactNode | undefined;
}

export function SecretRow({ label, value, concealed, mono, copy, warning, trailing, renderValue }: SecretRowProps) {
  const [revealed, toggleReveal] = useTimedReveal();
  const { copied, copy: doCopy } = useCopyFeedback(copy);
  const masked = concealed && !revealed;

  return (
    <div className="group flex flex-col gap-1 border-b border-divider px-4 py-3 last:border-b-0">
      <span className="text-meta text-muted">{label}</span>
      <div className="flex min-h-8 items-center gap-2">
        <button
          type="button"
          onClick={() => doCopy(value)}
          className="min-w-0 flex-1 cursor-copy rounded text-left text-ui"
          aria-label={`Copy ${label}`}
        >
          {renderValue ? (
            renderValue(value)
          ) : concealed || mono ? (
            <SecretText value={value} masked={masked} />
          ) : (
            <span className="break-words">{value}</span>
          )}
        </button>
        <div className="flex shrink-0 items-center gap-0.5">
          {trailing}
          {concealed && (
            <IconButton label={revealed ? `Hide ${label}` : `Reveal ${label}`} onClick={toggleReveal} aria-pressed={revealed}>
              {revealed ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}
            </IconButton>
          )}
          <IconButton label={copied ? "Copied" : `Copy ${label}`} onClick={() => doCopy(value)}>
            {copied ? <Check aria-hidden className="size-4 text-success" /> : <Copy aria-hidden className="size-4" />}
          </IconButton>
        </div>
      </div>
      <span role="status" aria-live="polite" className="sr-only">
        {copied ? `${label} copied. Clipboard clears in 30 seconds.` : ""}
      </span>
      {warning && <p className="text-meta text-warning">{warning}</p>}
    </div>
  );
}
