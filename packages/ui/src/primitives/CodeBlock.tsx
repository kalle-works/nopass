import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { IconButton } from "./Button";
import { cx } from "./cx";

export interface CodeLine {
  /** "cmd" lines get a non-copyable `$` prompt and are included in Copy. */
  kind: "cmd" | "out" | "comment";
  text: string;
}

export function CodeBlock({ lines, tabs, className }: { lines?: CodeLine[] | undefined; tabs?: Array<{ label: string; lines: CodeLine[] }> | undefined; className?: string | undefined }) {
  const [tab, setTab] = useState(0);
  const [copied, setCopied] = useState(false);
  const shown = tabs ? tabs[tab]!.lines : (lines ?? []);
  const commands = shown.filter((l) => l.kind === "cmd").map((l) => l.text).join("\n");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(commands);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard denied; the text stays selectable.
    }
  };

  return (
    <div className={cx("overflow-hidden rounded-lg border border-divider bg-surface-hover", className)}>
      <div className="flex items-center justify-between gap-2 border-b border-divider px-2 py-1">
        <div role={tabs ? "tablist" : undefined} className="flex gap-1">
          {tabs?.map((t, i) => (
            <button
              key={t.label}
              role="tab"
              aria-selected={i === tab}
              onClick={() => setTab(i)}
              className={cx("rounded px-2 py-1 text-meta", i === tab ? "bg-surface text-fg" : "text-muted hover:text-fg")}
            >
              {t.label}
            </button>
          ))}
        </div>
        <IconButton label={copied ? "Copied" : "Copy command"} onClick={copy}>
          {copied ? <Check aria-hidden className="size-4 text-success" /> : <Copy aria-hidden className="size-4" />}
        </IconButton>
      </div>
      <pre className="overflow-x-auto px-4 py-3 font-mono text-[13px] leading-5">
        {shown.map((l, i) => (
          <div key={i} className={l.kind === "cmd" ? "text-fg" : l.kind === "out" ? "text-muted" : "text-faint"}>
            {l.kind === "cmd" && <span className="select-none text-faint">$ </span>}
            {l.text}
          </div>
        ))}
      </pre>
    </div>
  );
}
