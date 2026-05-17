"use client";

import type { EncryptedVaultItem, VaultItemType } from "@nopass/types";

interface VaultItemCardProps {
  item: EncryptedVaultItem;
  onClick: (item: EncryptedVaultItem) => void;
}

const TYPE_ICONS: Record<VaultItemType, string> = {
  login: "🔑",
  note: "📝",
  card: "💳",
  identity: "🪪",
  ssh_key: "🗝",
};

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Login",
  note: "Secure note",
  card: "Credit card",
  identity: "Identity",
  ssh_key: "SSH Key",
};

export function VaultItemCard({ item, onClick }: VaultItemCardProps) {
  return (
    <button
      onClick={() => onClick(item)}
      className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors text-left group"
    >
      <span className="text-xl w-8 shrink-0 text-center" aria-hidden>
        {TYPE_ICONS[item.itemType]}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
          {/* Name is encrypted — show placeholder until decrypted */}
          {item.id.slice(0, 8)}…
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {TYPE_LABELS[item.itemType]}
        </p>
      </div>
      <span
        className="text-gray-400 dark:text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity"
        aria-hidden
      >
        →
      </span>
    </button>
  );
}

/** Shows a decrypted item name once available */
export function DecryptedVaultItemCard({
  item,
  decryptedName,
  onClick,
}: VaultItemCardProps & { decryptedName: string }) {
  return (
    <button
      onClick={() => onClick(item)}
      className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors text-left group"
    >
      <span className="text-xl w-8 shrink-0 text-center" aria-hidden>
        {TYPE_ICONS[item.itemType]}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
          {decryptedName}
        </p>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {TYPE_LABELS[item.itemType]}
        </p>
      </div>
      <span
        className="text-gray-400 dark:text-gray-500 opacity-0 group-hover:opacity-100 transition-opacity"
        aria-hidden
      >
        →
      </span>
    </button>
  );
}
