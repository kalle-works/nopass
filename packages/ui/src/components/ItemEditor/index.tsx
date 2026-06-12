"use client";

import { CardEditor } from "./CardEditor";
import { IdentityEditor } from "./IdentityEditor";
import { LoginEditor } from "./LoginEditor";
import { NoteEditor } from "./NoteEditor";
import { SshKeyEditor } from "./SshKeyEditor";
import type { VaultItemPlaintext, VaultItemType } from "@nopass/types";

interface ItemEditorProps {
  itemType: VaultItemType;
  initial?: Partial<VaultItemPlaintext> | undefined;
  onSave: (item: VaultItemPlaintext) => void;
  onCancel: () => void;
  saving?: boolean | undefined;
}

export function ItemEditor({ itemType, initial, onSave, onCancel, saving }: ItemEditorProps) {
  const commonProps = { onSave, onCancel, ...(saving !== undefined && { saving }) };

  switch (itemType) {
    case "login":
      return (
        <LoginEditor
          {...commonProps}
          {...(initial !== undefined && { initial: initial as Parameters<typeof LoginEditor>[0]["initial"] })}
        />
      );
    case "note":
      return (
        <NoteEditor
          {...commonProps}
          {...(initial !== undefined && { initial: initial as Parameters<typeof NoteEditor>[0]["initial"] })}
        />
      );
    case "card":
      return (
        <CardEditor
          {...commonProps}
          {...(initial !== undefined && { initial: initial as Parameters<typeof CardEditor>[0]["initial"] })}
        />
      );
    case "identity":
      return (
        <IdentityEditor
          {...commonProps}
          {...(initial !== undefined && { initial: initial as Parameters<typeof IdentityEditor>[0]["initial"] })}
        />
      );
    case "ssh_key":
      return (
        <SshKeyEditor
          {...commonProps}
          {...(initial !== undefined && { initial: initial as Parameters<typeof SshKeyEditor>[0]["initial"] })}
        />
      );
  }
}

export * from "./LoginEditor";
export * from "./NoteEditor";
export * from "./CardEditor";
export * from "./IdentityEditor";
export * from "./SshKeyEditor";
export * from "./TagsEditor";
