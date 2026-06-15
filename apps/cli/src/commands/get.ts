import { Command } from "commander";
import type { LoginItem, NoteItem, CardItem, IdentityItem, VaultItemPlaintext } from "@nopass/types";
import { fetchAndDecryptItems, withSession } from "../vault.js";

type LoginField = "password" | "username" | "url" | "notes" | "totp";
type NoteField = "content";
type CardField = "number" | "cvv" | "cardholder" | "expiry" | "notes";

function extractField(item: VaultItemPlaintext, field: string | undefined): string {
  switch (item.type) {
    case "login": {
      const login = item as LoginItem;
      const f = (field ?? "password") as LoginField;
      if (f === "password") return login.password;
      if (f === "username") return login.username;
      if (f === "url") return login.urls[0] ?? "";
      if (f === "notes") return login.notes ?? "";
      if (f === "totp") return login.totp ?? "";
      throw new Error(`Unknown field "${field}" for login item. Valid: password, username, url, notes, totp`);
    }
    case "note": {
      const note = item as NoteItem;
      const f = field ?? "content";
      if (f === "content" || f === "notes") return note.content;
      throw new Error(`Unknown field "${field}" for note item. Valid: content`);
    }
    case "card": {
      const card = item as CardItem;
      const f = (field ?? "number") as CardField;
      if (f === "number") return card.number;
      if (f === "cvv") return card.cvv;
      if (f === "cardholder") return card.cardholderName;
      if (f === "expiry") return `${card.expMonth}/${card.expYear}`;
      if (f === "notes") return card.notes ?? "";
      throw new Error(`Unknown field "${field}" for card item. Valid: number, cvv, cardholder, expiry, notes`);
    }
    case "identity": {
      const id = item as IdentityItem;
      const f = field ?? "email";
      if (f === "email") return id.email;
      if (f === "phone") return id.phone;
      if (f === "name") return `${id.firstName} ${id.lastName}`;
      if (f === "address") return id.address;
      if (f === "notes") return id.notes ?? "";
      throw new Error(`Unknown field "${field}" for identity item. Valid: email, phone, name, address, notes`);
    }
    case "ssh_key": {
      const ssh = item as import("@nopass/types").SshKeyItem;
      const f = field ?? "private";
      if (f === "private") return ssh.privateKey;
      if (f === "public") return ssh.publicKey ?? "";
      if (f === "passphrase") return ssh.passphrase ?? "";
      if (f === "notes") return ssh.notes ?? "";
      throw new Error(`Unknown field "${field}" for ssh_key item. Valid: private, public, passphrase, notes`);
    }
  }
}

export const getCommand = new Command("get")
  .description("get a secret from the vault")
  .argument("<name>", "vault item name (case-insensitive, partial match supported)")
  .option("-f, --field <field>", "field to retrieve (default: password/content/number/email)")
  .option("--json", "output the full item as JSON")
  .action(async (name: string, opts: { field?: string; json?: boolean }) => {
    await withSession(async (session) => {
      const items = await fetchAndDecryptItems(session);
      const query = name.toLowerCase();
      const exactMatches = items.filter((i) => i.name.toLowerCase() === query);
      const partialMatches = exactMatches.length > 0
        ? exactMatches
        : items.filter((i) => i.name.toLowerCase().includes(query));

      if (partialMatches.length === 0) {
        process.stderr.write(`Not found: "${name}"\n`);
        process.exit(2);
      }

      if (partialMatches.length > 1) {
        process.stderr.write(
          `Ambiguous: "${name}" matches ${partialMatches.length} items:\n` +
          partialMatches.map((i) => `  ${i.name}`).join("\n") + "\n" +
          `Use an exact name to disambiguate.\n`,
        );
        process.exit(2);
      }

      const match = partialMatches[0]!;

      if (opts.json) {
        process.stdout.write(JSON.stringify(match, null, 2) + "\n");
        return;
      }

      try {
        const value = extractField(match, opts.field);
        process.stdout.write(value + "\n");
      } catch (err) {
        process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      }
    });
  });
