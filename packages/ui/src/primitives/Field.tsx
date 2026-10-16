import { forwardRef, useId, useState, type InputHTMLAttributes, type ReactNode, type TextareaHTMLAttributes } from "react";
import { AlertCircle, Eye, EyeOff } from "lucide-react";
import { cx } from "./cx";

export const inputClass = cx(
  "w-full rounded border border-border bg-surface px-3 text-ui text-fg placeholder:text-faint",
  "transition-colors duration-[120ms] hover:border-border-strong",
  "focus-visible:border-focus focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus/30",
  "aria-[invalid=true]:border-danger disabled:opacity-60",
);

interface FieldShellProps {
  id: string;
  label: string;
  hint?: ReactNode | undefined;
  error?: ReactNode | undefined;
  action?: ReactNode | undefined;
  children: ReactNode;
  className?: string | undefined;
}

export function FieldShell({ id, label, hint, error, action, children, className }: FieldShellProps) {
  return (
    <div className={cx("flex flex-col gap-1.5", className)}>
      <div className="flex items-baseline justify-between gap-2">
        <label htmlFor={id} className="text-meta font-medium text-fg">
          {label}
        </label>
        {action}
      </div>
      {children}
      {error ? (
        <p id={`${id}-error`} className="flex items-center gap-1.5 text-meta text-danger">
          <AlertCircle aria-hidden className="size-3.5 shrink-0" />
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-meta text-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: ReactNode | undefined;
  error?: ReactNode | undefined;
  action?: ReactNode | undefined;
  mono?: boolean | undefined;
  /** Adds a show/hide toggle; only meaningful for type="password". */
  revealable?: boolean | undefined;
}

export const Field = forwardRef<HTMLInputElement, FieldProps>(function Field(
  { label, hint, error, action, mono, revealable, type = "text", className, id, ...rest },
  ref,
) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const [revealed, setRevealed] = useState(false);
  const effectiveType = revealable && revealed ? "text" : type;
  const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined;

  return (
    <FieldShell id={inputId} label={label} hint={hint} error={error} action={action} className={className}>
      <div className="relative">
        <input
          ref={ref}
          id={inputId}
          type={effectiveType}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={cx(inputClass, "h-9", mono && "font-mono", revealable && "pr-10")}
          {...rest}
        />
        {revealable && (
          <button
            type="button"
            onClick={() => setRevealed((r) => !r)}
            aria-label={revealed ? "Hide password" : "Show password"}
            aria-pressed={revealed}
            className="absolute inset-y-0 right-0 flex w-9 items-center justify-center rounded-r text-icon hover:text-fg"
          >
            {revealed ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}
          </button>
        )}
      </div>
    </FieldShell>
  );
});

export interface TextAreaFieldProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  hint?: ReactNode | undefined;
  error?: ReactNode | undefined;
  mono?: boolean | undefined;
}

export const TextAreaField = forwardRef<HTMLTextAreaElement, TextAreaFieldProps>(function TextAreaField(
  { label, hint, error, mono, className, id, ...rest },
  ref,
) {
  const autoId = useId();
  const inputId = id ?? autoId;
  return (
    <FieldShell id={inputId} label={label} hint={hint} error={error} className={className}>
      <textarea
        ref={ref}
        id={inputId}
        aria-invalid={error ? true : undefined}
        className={cx(inputClass, "min-h-24 py-2", mono && "font-mono")}
        {...rest}
      />
    </FieldShell>
  );
});
