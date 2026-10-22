"use client";

import type { ComponentType } from "react";
import { CreditCard, FileText, Globe, KeyRound, UserRound, type LucideProps } from "lucide-react";
import type { EncryptedVaultItem, VaultItemType } from "@nopass/types";

interface VaultItemCardProps {
  item: EncryptedVaultItem;
  onClick: (item: EncryptedVaultItem) => void;
}

const TYPE_ICONS: Record<VaultItemType, ComponentType<LucideProps>> = {
  login: Globe,
  note: FileText,
  card: CreditCard,
  identity: UserRound,
  ssh_key: KeyRound,
};

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Login",
  note: "Secure note",
  card: "Credit card",
  identity: "Identity",
  ssh_key: "SSH key",
};

function CardRow({ item, title, onClick }: VaultItemCardProps & { title: string }) {
  const Icon = TYPE_ICONS[item.itemType];
  return (
    <button
      type="button"
      onClick={() => onClick(item)}
      className="flex min-h-[52px] w-full items-center gap-3 rounded px-3 py-2 text-left transition-colors duration-[120ms] hover:bg-surface-hover"
    >
      <Icon aria-hidden className="size-4 shrink-0 text-icon" strokeWidth={1.5} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-ui font-medium text-fg">{title}</span>
        <span className="block truncate text-meta text-muted">{TYPE_LABELS[item.itemType]}</span>
      </span>
    </button>
  );
}

export function VaultItemCard({ item, onClick }: VaultItemCardProps) {
  // Name is encrypted: show a short id until the item is decrypted
  return <CardRow item={item} onClick={onClick} title={`${item.id.slice(0, 8)}…`} />;
}

/** Shows a decrypted item name once available */
export function DecryptedVaultItemCard({
  item,
  decryptedName,
  onClick,
}: VaultItemCardProps & { decryptedName: string }) {
  return <CardRow item={item} onClick={onClick} title={decryptedName} />;
}
