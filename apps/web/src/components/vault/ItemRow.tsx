"use client";

import { Check, Copy } from "lucide-react";
import type { EncryptedVaultItem, LoginItem, VaultItemPlaintext } from "@nopass/types";
import { Badge, IconButton, cx, useCopyFeedback } from "@nopass/ui";
import { ItemIcon } from "./ItemIcon";
import { itemSubtitle, primaryCopy } from "./vault-model";

export function ItemRow({
  item,
  plaintext,
  selected,
  breached,
  copy,
  onOpen,
}: {
  item: EncryptedVaultItem;
  plaintext: VaultItemPlaintext | undefined;
  selected: boolean;
  breached: boolean;
  copy: (text: string) => Promise<boolean>;
  onOpen: () => void;
}) {
  const { copied, copy: doCopy } = useCopyFeedback(copy);
  const quick = plaintext ? primaryCopy(plaintext) : null;
  const name = plaintext?.name ?? "…";
  const subtitle = plaintext ? itemSubtitle(plaintext) : "";
  const hasTotp = plaintext?.type === "login" && Boolean((plaintext as LoginItem).totp);

  return (
    <li className="relative px-2" data-item-id={item.id}>
      <button
        type="button"
        onClick={onOpen}
        aria-current={selected ? "true" : undefined}
        className={cx(
          "relative flex h-[52px] w-full items-center gap-3 rounded px-3 text-left transition-colors duration-[120ms]",
          quick ? "pr-12" : "pr-3",
          selected
            ? "bg-accent-subtle before:absolute before:inset-y-1.5 before:left-0 before:w-0.5 before:rounded-full before:bg-accent"
            : "hover:bg-surface-hover",
        )}
      >
        <ItemIcon type={item.itemType} name={name} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-ui font-medium text-fg">{name}</span>
          {subtitle && <span className="block truncate text-meta text-muted">{subtitle}</span>}
        </span>
        <span className="flex shrink-0 items-center gap-1">
          {breached && <Badge tone="danger">Breached</Badge>}
          {hasTotp && <Badge>TOTP</Badge>}
        </span>
      </button>
      {quick && (
        <IconButton
          label={copied ? "Copied" : quick.label}
          onClick={() => doCopy(quick.value)}
          className="absolute right-3 top-1/2 -translate-y-1/2"
        >
          {copied ? <Check aria-hidden className="size-3.5 text-success" /> : <Copy aria-hidden className="size-3.5" />}
        </IconButton>
      )}
    </li>
  );
}
