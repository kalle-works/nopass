import { Badge, Button } from "@nopass/ui";

export interface VaultEntry {
  id: string;
  name: string;
  username: string;
  urls: string[];
  hasPasskey?: boolean;
}

interface EntryRowProps {
  entry: VaultEntry;
  onOpen: (entry: VaultEntry) => void;
  onFill: (entry: VaultEntry) => void;
}

/** 52px row: monogram, title, username, one Fill action. The row body opens the detail view. */
export function EntryRow({ entry, onOpen, onFill }: EntryRowProps) {
  return (
    <li className="flex h-[52px] items-center gap-1 border-b border-divider pl-2 pr-3 last:border-b-0 hover:bg-surface-hover">
      <button
        type="button"
        onClick={() => onOpen(entry)}
        aria-label={`Open ${entry.name}`}
        className="flex h-full min-w-0 flex-1 items-center gap-3 rounded px-2 text-left"
      >
        <span
          aria-hidden
          className="flex size-5 shrink-0 items-center justify-center rounded-sm bg-surface-active text-mono-sm font-medium text-muted"
        >
          {entry.name.charAt(0).toUpperCase()}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="truncate text-ui font-medium text-fg">{entry.name}</span>
            {entry.hasPasskey && <Badge>Passkey</Badge>}
          </span>
          <span className="block truncate text-meta text-muted">{entry.username}</span>
        </span>
      </button>
      <Button size="sm" aria-label={`Fill ${entry.name}`} onClick={() => onFill(entry)}>
        Fill
      </Button>
    </li>
  );
}
