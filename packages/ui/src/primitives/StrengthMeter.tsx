import { useMemo } from "react";
import { cx } from "./cx";
import { estimateStrength } from "./strength";

const SEGMENT_COLOR = ["bg-divider", "bg-danger", "bg-warning", "bg-warning", "bg-success"] as const;
const TEXT_COLOR = ["text-muted", "text-danger", "text-warning", "text-warning", "text-success"] as const;

export function StrengthMeter({ password, userInputs, className }: { password: string; userInputs?: string[] | undefined; className?: string | undefined }) {
  const s = useMemo(() => estimateStrength(password, userInputs), [password, userInputs]);
  return (
    <div className={cx("flex flex-col gap-1.5", className)}>
      <div className="grid grid-cols-4 gap-1" aria-hidden>
        {[1, 2, 3, 4].map((seg) => (
          <span key={seg} className={cx("h-1 rounded-full", s.level >= seg ? SEGMENT_COLOR[s.level] : "bg-divider")} />
        ))}
      </div>
      <p className="min-h-[18px] text-meta text-muted" aria-live="polite">
        {s.level > 0 && (
          <>
            <span className={cx("font-medium", TEXT_COLOR[s.level])}>{s.label}</span>
            {" · "}
            {s.crackTime} to guess
            {s.suggestion && s.level < 4 && <span className="block">{s.suggestion}</span>}
          </>
        )}
      </p>
    </div>
  );
}
