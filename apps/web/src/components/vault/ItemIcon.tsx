import type { ComponentType } from "react";
import { CreditCard, FileText, Globe, KeyRound, UserRound, type LucideProps } from "lucide-react";
import type { VaultItemType } from "@nopass/types";
import { cx } from "@nopass/ui";

const TYPE_ICON: Record<VaultItemType, ComponentType<LucideProps>> = {
  login: Globe,
  note: FileText,
  card: CreditCard,
  identity: UserRound,
  ssh_key: KeyRound,
};

/**
 * Leading mark of a row or detail header: a monogram for logins, a type icon
 * for everything else. Site favicons are deliberately not fetched: requesting
 * them would tell a third party which sites are in the vault.
 */
export function ItemIcon({
  type,
  name,
  size = 20,
  className,
}: {
  type: VaultItemType;
  name: string;
  size?: 20 | 32;
  className?: string;
}) {
  const box = size === 32 ? "size-8" : "size-5";
  const letter = name.trim().charAt(0).toUpperCase();

  if (type === "login" && letter) {
    return (
      <span
        aria-hidden
        className={cx(
          "flex shrink-0 items-center justify-center rounded bg-surface-active font-medium text-muted",
          box,
          size === 32 ? "text-ui" : "text-mono-sm",
          className,
        )}
      >
        {letter}
      </span>
    );
  }
  const Icon = TYPE_ICON[type];
  return (
    <span aria-hidden className={cx("flex shrink-0 items-center justify-center text-icon", box, className)}>
      <Icon className={size === 32 ? "size-5" : "size-4"} strokeWidth={1.5} />
    </span>
  );
}

export { TYPE_ICON };
