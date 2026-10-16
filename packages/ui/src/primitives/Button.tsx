import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { cx } from "./cx";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md" | "lg";

const VARIANT: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover",
  secondary: "bg-surface text-fg border border-border hover:bg-surface-hover hover:border-border-strong",
  ghost: "text-muted hover:bg-surface-hover hover:text-fg",
  danger: "bg-danger-fill text-danger-fill-fg hover:opacity-90",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-meta gap-1.5",
  md: "h-9 px-3.5 text-ui gap-2",
  lg: "h-11 px-5 text-body gap-2",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  pending?: boolean | undefined;
  /** Label shown while pending, e.g. "Unlocking…". */
  pendingLabel?: string | undefined;
  icon?: ReactNode | undefined;
  shortcut?: string | undefined;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", pending, pendingLabel, icon, shortcut, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || pending}
      aria-busy={pending || undefined}
      className={cx(
        "inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded font-medium transition-colors duration-[120ms]",
        "disabled:cursor-not-allowed disabled:opacity-60",
        VARIANT[variant],
        SIZE[size],
        className,
      )}
      {...rest}
    >
      {pending ? <Loader2 aria-hidden className="size-4 animate-spin" /> : icon}
      {pending && pendingLabel ? pendingLabel : children}
      {shortcut && !pending && <Kbd className="ml-1">{shortcut}</Kbd>}
    </button>
  );
});

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
  size?: "sm" | "md" | undefined;
}

/** Icon-only button. `label` becomes the accessible name and tooltip. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, size = "sm", className, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type="button"
      aria-label={label}
      title={label}
      className={cx(
        "inline-flex shrink-0 items-center justify-center rounded text-icon transition-colors duration-[120ms]",
        "hover:bg-surface-hover hover:text-fg disabled:opacity-50",
        size === "sm" ? "size-8" : "size-9",
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
});

export function Kbd({ children, className }: { children: ReactNode; className?: string | undefined }) {
  return (
    <kbd
      className={cx(
        "inline-flex h-5 min-w-5 items-center justify-center rounded-sm border border-divider px-1 font-mono text-mono-sm text-muted",
        className,
      )}
    >
      {children}
    </kbd>
  );
}
