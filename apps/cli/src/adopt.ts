import { readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
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

/**
 * Pulls the secret out of one line of a file. In a `.env` file that is the
 * assigned value; in source code it is the longest quoted string literal.
 */
export function extractSecret(path: string, lineText: string): ExtractedSecret {
  if (isDotenvPath(path)) {
    const parsed = parseDotenvLine(lineText);
    if (!parsed || parsed.value === "") throw new Error("line is not a KEY=value assignment");
    if (isReference(parsed.value)) throw new Error(`${parsed.key} already points at the vault`);
    const prefix = parsed.exportPrefix ? "export " : "";
    return {
      value: parsed.value,
      envKey: parsed.key,
      rewriteLine: (reference) => `${prefix}${parsed.key}="${reference.replace(/[\\"]/g, "\\$&")}"`,
    };
  }

  const literals = [...lineText.matchAll(/(["'`])((?:\\.|(?!\1).)*)\1/g)]
    .map((m) => m[2]!)
    .filter((s) => s.length >= MIN_SOURCE_SECRET_LENGTH)
    .sort((a, b) => b.length - a.length);
  if (literals.length === 0) throw new Error("no quoted secret found on that line");
  return { value: literals[0]! };
}

export function defaultItemName(path: string, secret: ExtractedSecret, lineNumber: number): string {
  const project = basename(dirname(path));
  return secret.envKey ? `${project} ${secret.envKey}` : `${project} ${basename(path)}:${lineNumber}`;
}

export interface AdoptOptions {
  path: string;
  /** 1-based */
  line: number;
  name?: string | undefined;
  existingNames: string[];
  saveItem: (item: LoginItem) => Promise<void>;
}

export interface AdoptResult {
  itemName: string;
  reference: string;
  rewritten: boolean;
}

/**
 * Moves a secret from a file into the vault. The file is only rewritten after
 * the item is saved, so a failed save leaves it exactly as it was.
 */
export async function adoptSecret(opts: AdoptOptions): Promise<AdoptResult> {
  const content = readFileSync(opts.path, "utf-8");
  const eol = content.includes("\r\n") ? "\r\n" : "\n";
  const lines = content.split(/\r?\n/);
  const lineText = lines[opts.line - 1];
  if (lineText === undefined) throw new Error(`${opts.path} has no line ${opts.line}`);

  const secret = extractSecret(opts.path, lineText);
  const itemName = opts.name ?? defaultItemName(opts.path, secret, opts.line);
  if (itemName.includes("/")) throw new Error(`item name "${itemName}" must not contain "/"`);
  if (opts.existingNames.some((n) => n.toLowerCase() === itemName.toLowerCase())) {
    throw new Error(`a vault item named "${itemName}" already exists; pass --name to choose another`);
  }

  await opts.saveItem({
    type: "login",
    name: itemName,
    username: "",
    password: secret.value,
    urls: [],
    notes: `Moved from ${opts.path}:${opts.line}`,
    customFields: [],
  });

  const reference = formatReference(itemName, "password");
  if (!secret.rewriteLine) return { itemName, reference, rewritten: false };

  lines[opts.line - 1] = secret.rewriteLine(reference);
  const tmp = join(dirname(opts.path), `.${basename(opts.path)}.nopwd-tmp`);
  writeFileSync(tmp, lines.join(eol), { mode: statSync(opts.path).mode });
  renameSync(tmp, opts.path);
  return { itemName, reference, rewritten: true };
}
