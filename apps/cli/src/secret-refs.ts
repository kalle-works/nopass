import type { LoginItem, VaultItemPlaintext } from "@nopass/types";

export const REF_PREFIX = "nopwd://";

export function toEnvKey(name: string): string {
  return name.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

export function itemToEnvVars(item: VaultItemPlaintext): Record<string, string> {
  const vars: Record<string, string> = {};
  const key = toEnvKey(item.name);

  switch (item.type) {
    case "login": {
      const login = item as LoginItem;
      if (login.password) vars[key] = login.password;
      if (login.username) vars[`${key}_USERNAME`] = login.username;
      if (login.totp) vars[`${key}_TOTP`] = login.totp;
      for (const field of login.customFields) {
        if (field.value) vars[`${key}_${toEnvKey(field.name)}`] = field.value;
      }
      break;
    }
    case "note":
      vars[key] = item.content;
      break;
    case "ssh_key":
      if (item.publicKey) vars[`${key}_PUBLIC`] = item.publicKey;
      vars[`${key}_PRIVATE`] = item.privateKey;
      break;
  }
  return vars;
}

export function formatReference(itemName: string, field: string): string {
  return `${REF_PREFIX}${itemName}/${field}`;
}

export function isReference(value: string | undefined): value is string {
  return value?.startsWith(REF_PREFIX) ?? false;
}

export type ResolveResult = { ok: true; value: string } | { ok: false; error: string };

/** Looks up a single `nopwd://item-name/field` reference. Item and field names match case-insensitively. */
export function resolveReference(vault: VaultItemPlaintext[], ref: string): ResolveResult {
  const rest = ref.slice(REF_PREFIX.length);
  const slashIdx = rest.indexOf("/");
  if (!isReference(ref) || slashIdx <= 0) return { ok: false, error: `malformed reference ${ref}` };

  const itemName = rest.slice(0, slashIdx).toLowerCase();
  const fieldName = rest.slice(slashIdx + 1).toLowerCase();
  const item = vault.find((i) => i.name.toLowerCase() === itemName);
  if (!item) return { ok: false, error: `no vault item matches reference ${ref}` };

  const itemKey = toEnvKey(item.name);
  const fieldKey =
    fieldName === "password" ? itemKey :
    fieldName === "username" ? `${itemKey}_USERNAME` :
    fieldName === "totp" ? `${itemKey}_TOTP` :
    `${itemKey}_${toEnvKey(fieldName)}`;
  const value = itemToEnvVars(item)[fieldKey];
  if (value === undefined) return { ok: false, error: `field "${fieldName}" not found in vault item "${item.name}"` };
  return { ok: true, value };
}

export interface DotenvEntry {
  key: string;
  value: string;
  /** 1-based line number */
  line: number;
}

const DOTENV_LINE = /^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

export interface ParsedDotenvLine {
  exportPrefix: boolean;
  key: string;
  value: string;
  /** Whatever follows the value on the line, such as an inline comment */
  trailing: string;
  /** The value opens a quote that the line never closes (a multi-line value) */
  unterminatedQuote: boolean;
}

/** Parses one `.env` line. Returns null for blank lines, comments and anything that isn't an assignment. */
export function parseDotenvLine(line: string): ParsedDotenvLine | null {
  const m = DOTENV_LINE.exec(line);
  if (!m) return null;
  const raw = m[3]!.trimEnd();
  const base = { exportPrefix: Boolean(m[1]), key: m[2]! };
  const quote = raw[0];
  if (quote === '"' || quote === "'") {
    const quoted = quote === '"' ? /^"((?:\\.|[^"\\])*)"/.exec(raw) : /^'([^']*)'/.exec(raw);
    if (!quoted) return { ...base, value: raw, trailing: "", unterminatedQuote: true };
    // Double-quoted values honour escapes; single-quoted ones are literal
    const value = quote === '"' ? quoted[1]!.replace(/\\(.)/g, (_, c: string) => (c === "n" ? "\n" : c)) : quoted[1]!;
    return { ...base, value, trailing: raw.slice(quoted[0].length), unterminatedQuote: false };
  }
  // Unquoted values end at an inline comment
  const comment = /\s+#.*$/.exec(raw);
  return {
    ...base,
    value: comment ? raw.slice(0, comment.index) : raw,
    trailing: comment ? comment[0] : "",
    unterminatedQuote: false,
  };
}

export function parseDotenv(content: string): DotenvEntry[] {
  const entries: DotenvEntry[] = [];
  content.split(/\r?\n/).forEach((line, i) => {
    const parsed = parseDotenvLine(line);
    if (parsed && !parsed.unterminatedQuote) entries.push({ key: parsed.key, value: parsed.value, line: i + 1 });
  });
  return entries;
}
