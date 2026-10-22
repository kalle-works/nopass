/**
 * Class names that make a link look like a @nopass/ui Button. Server
 * components can't use the Button primitive for links, so this mirrors its
 * variants and sizes.
 */
type Variant = "primary" | "secondary" | "ghost";
type Size = "sm" | "md" | "lg";

const BASE =
  "inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded font-medium transition-colors duration-[120ms]";

const VARIANT: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover",
  secondary: "bg-surface text-fg border border-border hover:bg-surface-hover hover:border-border-strong",
  ghost: "text-muted hover:bg-surface-hover hover:text-fg",
};

const SIZE: Record<Size, string> = {
  sm: "h-8 px-3 text-meta gap-1.5",
  md: "h-9 px-3.5 text-ui gap-2",
  lg: "h-11 px-5 text-body gap-2",
};

export function linkButton(variant: Variant = "secondary", size: Size = "md"): string {
  return `${BASE} ${VARIANT[variant]} ${SIZE[size]}`;
}
