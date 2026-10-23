import { randomBytes } from "node:crypto";
import { readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { LoginItem } from "@nopass/types";
import { formatReference, isReference, parseDotenvLine } from "./secret-refs.js";

/** Shortest quoted literal treated as a secret in a source file. */
const MIN_SOURCE_SECRET_LENGTH = 8;

export interface ExtractedSecret {
  value: string;
  /** Variable name of a `.env` assignment; absent for source files */
  envKey?: string;
  /** Builds the replacement line for a `.env` file; absent when the file must not be edited */
  rewriteLine?: (reference: string) => string;
}

export function isDotenvPath(path: string): boolean {
  const name = basename(path);
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env");
}

/** Shows enough of a secret to recognise it: `sk-p…dc (32 chars)`. */
export function redactedPreview(value: string): string {
  if (value.length <= 8) return `${value.length} chars`;
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

/**
 * Pulls the secret out of one line of a file. In a `.env` file that is the
 * assigned value. In source code it is the only quoted literal long enough to
 * be a secret, or the one starting with `match` when there are several.
 */
export function extractSecret(path: string, lineText: string, match?: string): ExtractedSecret {
  if (isDotenvPath(path)) {
    const parsed = parseDotenvLine(lineText);
    if (!parsed || parsed.value === "") throw new Error("line is not a KEY=value assignment");
    if (parsed.unterminatedQuote) {
      throw new Error(`${parsed.key} is a multi-line value; move it into the vault by hand`);
    }
    if (isReference(parsed.value)) throw new Error(`${parsed.key} already points at the vault`);
    const prefix = parsed.exportPrefix ? "export " : "";
    return {
      value: parsed.value,
      envKey: parsed.key,
      // Single quotes keep dotenv-expand and docker compose from interpolating the reference
      rewriteLine: (reference) => `${prefix}${parsed.key}='${reference}'${parsed.trailing}`,
    };
  }

  const candidates = [...lineText.matchAll(/(["'`])((?:\\.|(?!\1).)*)\1/g)]
    .map((m) => m[2]!)
    .filter((s) => s.length >= MIN_SOURCE_SECRET_LENGTH && !s.includes("\\"));
  const chosen = match ? candidates.filter((s) => s.startsWith(match)) : candidates;
  if (chosen.length === 0) {
    throw new Error(match ? `no quoted string on that line starts with "${match}"` : "no quoted secret found on that line");
  }
  if (chosen.length > 1) {
    const previews = chosen.map(redactedPreview).join(", ");
    throw new Error(`that line has several quoted strings (${previews}); pass --match with the start of the secret`);
  }
  return { value: chosen[0]! };
}

export function defaultItemName(path: string, secret: ExtractedSecret, lineNumber: number): string {
  const project = basename(dirname(path));
  return secret.envKey ? `${project} ${secret.envKey}` : `${project} ${basename(path)}:${lineNumber}`;
}

/** Item names end up inside a quoted `.env` value and a `nopwd://name/field` reference. */
function validateItemName(name: string): void {
  // eslint-disable-next-line no-control-regex
  if (/[/'\u0000-\u001f\u007f]/.test(name)) {
    throw new Error(`item name "${name}" must not contain "/", "'" or control characters`);
  }
}

export interface AdoptOptions {
  path: string;
  /** 1-based */
  line: number;
  name?: string | undefined;
  /** Start of the secret, to pick it out of a source line with several quoted strings */
  match?: string | undefined;
  existingNames: string[];
  saveItem: (item: LoginItem) => Promise<void>;
}

export interface AdoptResult {
  itemName: string;
  reference: string;
  rewritten: boolean;
  /** Redacted form of the value that was saved, so the user can check it was the right one */
  preview: string;
}

/**
 * Moves a secret from a file into the vault. The file is only rewritten after
 * the item is saved, so a failed save leaves it exactly as it was. Only the
 * target line changes: other lines, their line endings and a BOM are kept.
 */
export async function adoptSecret(opts: AdoptOptions): Promise<AdoptResult> {
  // Rewrite the file a symlink points at, not the link itself
  const path = realpathSync(opts.path);
  const content = readFileSync(path, "utf-8");
  // Split into [text, terminator, text, terminator, …] so each line keeps its own ending
  const parts = content.split(/(\r?\n)/);
  const index = (opts.line - 1) * 2;
  if (index >= parts.length || (index === parts.length - 1 && parts[index] === "")) {
    throw new Error(`${opts.path} has no line ${opts.line}`);
  }
  const bom = index === 0 && parts[0]!.startsWith("﻿") ? "﻿" : "";
  const lineText = parts[index]!.slice(bom.length);

  const secret = extractSecret(path, lineText, opts.match);
  const itemName = opts.name ?? defaultItemName(path, secret, opts.line);
  validateItemName(itemName);
  if (opts.existingNames.some((n) => n.toLowerCase() === itemName.toLowerCase())) {
    throw new Error(
      `a vault item named "${itemName}" already exists (adopted before?); pass --name to choose another`,
    );
  }

  await opts.saveItem({
    type: "login",
    name: itemName,
    username: "",
    password: secret.value,
    urls: [],
    notes: `Moved from ${path}:${opts.line}`,
    customFields: [],
  });

  const reference = formatReference(itemName, "password");
  const preview = redactedPreview(secret.value);
  if (!secret.rewriteLine) return { itemName, reference, rewritten: false, preview };

  parts[index] = bom + secret.rewriteLine(reference);
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString("hex")}.nopwd-tmp`);
  try {
    // `wx` refuses to follow or reuse anything already at the temp path
    writeFileSync(tmp, parts.join(""), { flag: "wx", mode: statSync(path).mode & 0o777 });
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* never created */ }
    throw new Error(
      `saved "${itemName}" to the vault but could not rewrite ${opts.path}: ${(err as Error).message}`,
    );
  }
  return { itemName, reference, rewritten: true, preview };
}
