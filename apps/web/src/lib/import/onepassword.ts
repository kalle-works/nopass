/**
 * 1Password 1PUX import parser.
 *
 * Accepts a .1pux file (ZIP archive containing export.data JSON),
 * parses it, and maps items to nopass VaultItemPlaintext format.
 * All processing happens client-side — no data ever leaves the browser.
 */
import { unzipSync } from "fflate";
import type {
  CardItem,
  CustomField,
  IdentityItem,
  LoginItem,
  NoteItem,
  SshKeyItem,
  VaultItemPlaintext,
} from "@nopass/types";

// ─── 1PUX raw types ──────────────────────────────────────────────────────────

interface OnePuxLoginField {
  value: string;
  id: string;
  name: string;
  type: "T" | "P" | "E" | "U" | "N" | "A" | "TEL" | "OTP";
  designation?: "username" | "password" | string;
}

type OnePuxFieldKind =
  | "string"
  | "concealed"
  | "email"
  | "url"
  | "date"
  | "monthYear"
  | "menu"
  | "cctype"
  | "phone"
  | "address"
  | "sshKey"
  | "reference"
  | string;

interface OnePuxSectionField {
  title: string;
  id: string;
  kind: OnePuxFieldKind;
  value:
    | string
    | { concealed: string }
    | { date: number }
    | { monthYear: number }
    | { email: string }
    | { url: string }
    | { phone: string }
    | { address: { street: string; city: string; country: string; zip: string; state: string } }
    | { sshKey: { privateKey: string; publicKey: string; fingerprint: string; keyType: string } }
    | { menu: string }
    | { cctype: string }
    | { reference: string }
    | Record<string, unknown>;
  inputTraits?: { autocapitalization?: string; keyboard?: string };
}

interface OnePuxSection {
  title: string;
  name?: string;
  fields?: OnePuxSectionField[];
}

interface OnePuxDetails {
  loginFields?: OnePuxLoginField[];
  notesPlain?: string;
  sections?: OnePuxSection[];
  password?: string;
  documentAttributes?: Record<string, unknown>;
}

interface OnePuxOverview {
  title: string;
  url?: string;
  urls?: Array<{ label: string; url: string }>;
  ainfo?: string;
  tags?: string[];
  ps?: number;
  pbe?: number;
}

interface OnePuxItem {
  uuid: string;
  favIndex: number;
  createdAt: number;
  updatedAt: number;
  trashed: "Y" | "N";
  categoryUuid: string;
  details: OnePuxDetails;
  overview: OnePuxOverview;
}

interface OnePuxVault {
  attrs: { name: string; desc?: string; avatar?: string; type: string };
  items: OnePuxItem[];
}

interface OnePuxAccount {
  attrs: { name: string; email: string; masterKeyUuid: string; type: string };
  vaults: OnePuxVault[];
}

interface OnePuxExport {
  accounts: OnePuxAccount[];
}

// ─── Category UUIDs ───────────────────────────────────────────────────────────

const CATEGORY_LOGIN = "001";
const CATEGORY_CREDIT_CARD = "002";
const CATEGORY_SECURE_NOTE = "003";
const CATEGORY_IDENTITY = "004";
const CATEGORY_SSH_KEY = "115";

// ─── Field value extraction ───────────────────────────────────────────────────

function stringValue(raw: OnePuxSectionField["value"]): string {
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object") {
    if ("concealed" in raw) return (raw as { concealed: string }).concealed;
    if ("email" in raw) return (raw as { email: string }).email;
    if ("url" in raw) return (raw as { url: string }).url;
    if ("phone" in raw) return (raw as { phone: string }).phone;
    if ("menu" in raw) return (raw as { menu: string }).menu;
    if ("cctype" in raw) return (raw as { cctype: string }).cctype;
    if ("monthYear" in raw) {
      const my = (raw as { monthYear: number }).monthYear;
      const month = String(my % 100).padStart(2, "0");
      const year = String(Math.floor(my / 100));
      return `${month}/${year}`;
    }
  }
  return "";
}

function findFieldById(sections: OnePuxSection[] | undefined, ...ids: string[]): string {
  for (const section of sections ?? []) {
    for (const field of section.fields ?? []) {
      if (ids.includes(field.id)) return stringValue(field.value);
    }
  }
  return "";
}

function findFieldByTitle(sections: OnePuxSection[] | undefined, ...titles: string[]): string {
  const lower = titles.map((t) => t.toLowerCase());
  for (const section of sections ?? []) {
    for (const field of section.fields ?? []) {
      if (lower.includes(field.title.toLowerCase())) return stringValue(field.value);
    }
  }
  return "";
}

// ─── Per-category mappers ─────────────────────────────────────────────────────

function mapLogin(item: OnePuxItem): LoginItem {
  const fields = item.details.loginFields ?? [];
  const username = fields.find((f) => f.designation === "username")?.value ?? "";
  const password = fields.find((f) => f.designation === "password")?.value ?? "";

  const urls: string[] = [];
  if (item.overview.urls?.length) {
    urls.push(...item.overview.urls.map((u) => u.url).filter(Boolean));
  } else if (item.overview.url) {
    urls.push(item.overview.url);
  }

  const totp = findFieldById(item.details.sections, "TOTP_field", "one-time password");

  const customFields: CustomField[] = [];
  for (const section of item.details.sections ?? []) {
    for (const field of section.fields ?? []) {
      if (["username", "password"].includes(field.id)) continue;
      const val = stringValue(field.value);
      if (!val) continue;
      customFields.push({
        name: field.title || field.id,
        value: val,
        fieldType: field.kind === "concealed" ? "hidden" : "text",
      });
    }
  }

  return {
    type: "login",
    name: item.overview.title || "Unnamed",
    username,
    password,
    urls,
    totp: totp || undefined,
    notes: item.details.notesPlain || undefined,
    customFields,
  };
}

function mapCreditCard(item: OnePuxItem): CardItem {
  const sections = item.details.sections;
  const number = findFieldById(sections, "ccnum") || findFieldByTitle(sections, "card number", "number");
  const cardholder =
    findFieldById(sections, "cardholder") || findFieldByTitle(sections, "cardholder name", "name on card");
  const expiry = findFieldById(sections, "expiry") || findFieldByTitle(sections, "expiry date", "expiration");
  const cvv = findFieldById(sections, "cvv") || findFieldByTitle(sections, "cvv", "cvc", "security code");

  let expMonth = "";
  let expYear = "";
  if (expiry) {
    const parts = expiry.split("/");
    if (parts.length === 2) {
      expMonth = parts[0]!.trim();
      expYear = parts[1]!.trim();
    }
  }

  return {
    type: "card",
    name: item.overview.title || "Unnamed",
    cardholderName: cardholder,
    number,
    expMonth,
    expYear,
    cvv,
    notes: item.details.notesPlain || undefined,
  };
}

function mapSecureNote(item: OnePuxItem): NoteItem {
  const extraSections: string[] = [];
  for (const section of item.details.sections ?? []) {
    for (const field of section.fields ?? []) {
      const val = stringValue(field.value);
      if (val) extraSections.push(`${field.title}: ${val}`);
    }
  }
  const content = [item.details.notesPlain, ...extraSections].filter(Boolean).join("\n\n");

  return {
    type: "note",
    name: item.overview.title || "Unnamed",
    content,
  };
}

function mapIdentity(item: OnePuxItem): IdentityItem {
  const sections = item.details.sections;
  const firstName =
    findFieldById(sections, "firstname") || findFieldByTitle(sections, "first name", "firstname");
  const lastName =
    findFieldById(sections, "lastname") || findFieldByTitle(sections, "last name", "lastname");
  const email =
    findFieldById(sections, "email") || findFieldById(sections, "defEmailNew") || findFieldByTitle(sections, "email");
  const phone =
    findFieldById(sections, "defphone") ||
    findFieldById(sections, "cellphone") ||
    findFieldByTitle(sections, "phone", "mobile", "cell phone");

  // Address: 1Password stores as structured object
  let address = "";
  let city = "";
  let country = "";
  for (const section of sections ?? []) {
    for (const field of section.fields ?? []) {
      if (field.kind === "address" && field.value && typeof field.value === "object" && "address" in field.value) {
        const addr = (
          field.value as {
            address: { street: string; city: string; country: string; zip: string; state: string };
          }
        ).address;
        address = [addr.street, addr.zip, addr.state].filter(Boolean).join(", ");
        city = addr.city;
        country = addr.country;
      }
    }
  }

  return {
    type: "identity",
    name: item.overview.title || "Unnamed",
    firstName,
    lastName,
    email,
    phone,
    address,
    city,
    country,
    notes: item.details.notesPlain || undefined,
  };
}

function mapSshKey(item: OnePuxItem): SshKeyItem {
  let privateKey = "";
  let publicKey = "";
  for (const section of item.details.sections ?? []) {
    for (const field of section.fields ?? []) {
      if (field.kind === "sshKey" && field.value && typeof field.value === "object" && "sshKey" in field.value) {
        const sk = (field.value as { sshKey: { privateKey: string; publicKey: string } }).sshKey;
        privateKey = sk.privateKey;
        publicKey = sk.publicKey;
      }
    }
  }
  const passphrase = findFieldById(item.details.sections, "passphrase") || undefined;

  return {
    type: "ssh_key",
    name: item.overview.title || "Unnamed",
    privateKey,
    publicKey: publicKey || undefined,
    passphrase: passphrase || undefined,
    notes: item.details.notesPlain || undefined,
  };
}

function mapGenericToNote(item: OnePuxItem): NoteItem {
  const lines: string[] = [];
  if (item.details.notesPlain) lines.push(item.details.notesPlain);
  for (const section of item.details.sections ?? []) {
    if (section.title) lines.push(`\n## ${section.title}`);
    for (const field of section.fields ?? []) {
      const val = stringValue(field.value);
      if (val) lines.push(`${field.title}: ${val}`);
    }
  }
  if (item.details.password) lines.push(`Password: ${item.details.password}`);
  return {
    type: "note",
    name: item.overview.title || "Unnamed",
    content: lines.join("\n"),
  };
}

function mapItem(item: OnePuxItem): VaultItemPlaintext | null {
  if (item.trashed === "Y") return null;

  switch (item.categoryUuid) {
    case CATEGORY_LOGIN:
      return mapLogin(item);
    case CATEGORY_CREDIT_CARD:
      return mapCreditCard(item);
    case CATEGORY_SECURE_NOTE:
      return mapSecureNote(item);
    case CATEGORY_IDENTITY:
      return mapIdentity(item);
    case CATEGORY_SSH_KEY:
      return mapSshKey(item);
    default:
      return mapGenericToNote(item);
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ImportResult {
  items: VaultItemPlaintext[];
  skipped: number;
  vaultNames: string[];
}

export async function parseOnePux(file: File): Promise<ImportResult> {
  const buffer = await file.arrayBuffer();
  const zip = unzipSync(new Uint8Array(buffer));

  const dataFile = zip["export.data"];
  if (!dataFile) throw new Error("Invalid .1pux file: missing export.data");

  const json = new TextDecoder().decode(dataFile);
  const exported = JSON.parse(json) as OnePuxExport;

  const items: VaultItemPlaintext[] = [];
  let skipped = 0;
  const vaultNames: string[] = [];

  for (const account of exported.accounts ?? []) {
    for (const vault of account.vaults ?? []) {
      vaultNames.push(vault.attrs.name);
      for (const rawItem of vault.items ?? []) {
        const mapped = mapItem(rawItem);
        if (mapped) {
          items.push(mapped);
        } else {
          skipped++;
        }
      }
    }
  }

  return { items, skipped, vaultNames };
}
