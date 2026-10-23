import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";

let factory: ZxcvbnFactory | undefined;
function estimator(): ZxcvbnFactory {
  factory ??= new ZxcvbnFactory({
    dictionary: { ...common.dictionary, ...en.dictionary },
    graphs: common.adjacencyGraphs,
    translations: en.translations,
  });
  return factory;
}

export type StrengthLevel = 0 | 1 | 2 | 3 | 4;

export interface StrengthResult {
  /** 0 = empty, 1 = weak, 2 = fair, 3 = good, 4 = strong */
  level: StrengthLevel;
  label: string;
  crackTime: string;
  suggestion?: string | undefined;
}

const LABELS = ["Too weak", "Weak", "Fair", "Good", "Strong"] as const;

export function estimateStrength(password: string, userInputs: string[] = []): StrengthResult {
  if (!password) return { level: 0, label: "", crackTime: "" };
  const r = estimator().check(password, userInputs);
  // zxcvbn's 0 and 1 both map to "Weak" segment 1; a non-empty password always fills one segment.
  const level = Math.max(1, r.score) as StrengthLevel;
  return {
    level,
    label: LABELS[r.score],
    crackTime: r.crackTimes.offlineSlowHashingXPerSecond.display,
    suggestion: r.feedback.warning || r.feedback.suggestions[0] || undefined,
  };
}

/** Minimum level a master password must reach. */
export const MASTER_PASSWORD_MIN_LEVEL: StrengthLevel = 4;
