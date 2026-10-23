import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { IconButton } from "./Button";
import { cx } from "./cx";

export type Tone = "neutral" | "success" | "warning" | "danger" | "accent";

const BADGE_TONE: Record<Tone, string> = {
  neutral: "bg-surface-active text-muted",
  success: "bg-success-subtle text-success",
  warning: "bg-warning-subtle text-warning",
  danger: "bg-danger-subtle text-danger",
  accent: "bg-accent-subtle text-accent-text",
};

export function Badge({ tone = "neutral", children, className }: { tone?: Tone | undefined; children: ReactNode; className?: string | undefined }) {
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-mono-sm font-medium", BADGE_TONE[tone], className)}>
      {children}
    </span>
  );
}

const BANNER_TONE: Record<Exclude<Tone, "accent">, string> = {
  neutral: "border-divider bg-bg-subtle text-fg",
  success: "border-success/30 bg-success-subtle text-fg",
  warning: "border-warning/30 bg-warning-subtle text-fg",
  danger: "border-danger/30 bg-danger-subtle text-fg",
};

export function Banner({
  tone = "neutral",
  title,
  children,
  action,
  className,
}: {
  tone?: Exclude<Tone, "accent"> | undefined;
  title?: ReactNode | undefined;
  children?: ReactNode | undefined;
  action?: ReactNode | undefined;
  className?: string | undefined;
}) {
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cx("flex items-start gap-3 rounded-lg border px-4 py-3 text-ui", BANNER_TONE[tone], className)}
    >
      <div className="min-w-0 flex-1">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className="text-muted">{children}</div>}
      </div>
      {action}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  secondary,
  command,
  className,
}: {
  title: ReactNode;
  description?: ReactNode | undefined;
  action?: ReactNode | undefined;
  secondary?: ReactNode | undefined;
  command?: string | undefined;
  className?: string | undefined;
}) {
  return (
    <div className={cx("flex flex-col items-start gap-3 px-6 py-12", className)}>
      <p className="text-h3 font-semibold text-fg">{title}</p>
      {description && <p className="max-w-prose text-ui text-muted">{description}</p>}
      {(action || secondary) && (
        <div className="flex flex-wrap gap-2">
          {action}
          {secondary}
        </div>
      )}
      {command && (
        <code className="rounded border border-divider bg-surface-hover px-2 py-1 font-mono text-mono-sm text-muted">
          <span className="select-none text-faint">$ </span>
          {command}
        </code>
      )}
    </div>
  );
}

/** Accessible modal dialog: focus trap, Escape to close, focus returns to the trigger. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode | undefined;
  children?: ReactNode | undefined;
  footer?: ReactNode | undefined;
  className?: string | undefined;
}) {
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const node = panel.current;
    const focusables = () =>
      Array.from(
        node?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? [],
      ).filter((el) => !el.hasAttribute("disabled"));
    (focusables()[0] ?? node)?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const els = focusables();
      if (els.length === 0) return;
      const first = els[0]!;
      const last = els[els.length - 1]!;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      previous?.focus?.();
    };
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-overlay p-4 pt-[12vh] animate-fade-in" onMouseDown={onClose}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        tabIndex={-1}
        onMouseDown={(e) => e.stopPropagation()}
        className={cx("w-full max-w-[480px] rounded-lg border border-divider bg-surface shadow-overlay animate-overlay-in", className)}
      >
        <div className="flex items-start justify-between gap-4 px-5 pt-5">
          <div>
            <h2 id="dialog-title" className="text-h2 font-semibold text-fg">
              {title}
            </h2>
            {description && <p className="mt-1 text-ui text-muted">{description}</p>}
          </div>
          <IconButton label="Close" onClick={onClose} className="-mr-2 -mt-1">
            <X aria-hidden className="size-4" />
          </IconButton>
        </div>
        {children && <div className="px-5 pt-4">{children}</div>}
        <div className="flex justify-end gap-2 px-5 pb-5 pt-5">{footer}</div>
      </div>
    </div>,
    document.body,
  );
}

export function Spinner({ className }: { className?: string | undefined }) {
  return <span aria-hidden className={cx("inline-block size-4 animate-spin rounded-full border-2 border-divider border-t-accent", className)} />;
}
