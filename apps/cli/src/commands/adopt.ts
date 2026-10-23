import { Command } from "commander";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { encryptVaultItem } from "@nopass/crypto";
import { adoptSecret } from "../adopt.js";
import { createApiClient } from "../api-client.js";
import { importKeys } from "../auth.js";
import { openRevisionStore } from "../session.js";
import { fetchAndDecryptItems, withSession } from "../vault.js";

export const adoptCommand = new Command("adopt")
  .description("move a secret found in a file into the vault and point the file at it")
  .argument("<file>", "file that contains the secret")
  .requiredOption("-l, --line <n>", "1-based line number of the secret", (v) => Number.parseInt(v, 10))
  .option("-n, --name <name>", "vault item name (default: <directory> <KEY> or <directory> <file>:<line>)")
  .option("-m, --match <start>", "in a source line with several quoted strings, the start of the secret")
  .option("--json", "print the result as JSON")
  .addHelpText(
    "after",
    `
In a .env file the line is rewritten to KEY='nopwd://<name>/password' once the
item is saved; run the app with: nopwd run --dotenv .env -- <command>
In other files nothing is edited; the reference is printed so you can replace
the literal with an environment variable yourself.`,
  )
  .action(async (file: string, opts: { line: number; name?: string; match?: string; json?: boolean }) => {
    if (!Number.isInteger(opts.line) || opts.line < 1) {
      process.stderr.write("nopwd adopt: --line must be a positive integer\n");
      process.exit(1);
    }
    await withSession(async (session) => {
      const api = createApiClient(session.apiUrl);
      const existing = await fetchAndDecryptItems(session);
      const { vaultEncKey } = await importKeys(session, { write: true });
      const revisions = openRevisionStore(session.defaultVaultId);

      let result;
      try {
        result = await adoptSecret({
          path: resolve(file),
          line: opts.line,
          name: opts.name,
          match: opts.match,
          existingNames: existing.map((i) => i.name),
          saveItem: async (item) => {
            const id = randomUUID();
            const { encrypted, revision } = await encryptVaultItem(
              item,
              { scope: { kind: "personal" }, itemId: id, itemType: "login" },
              vaultEncKey,
              revisions,
            );
            await api.vault.createItem(session.defaultVaultId, { id, itemType: "login", ...encrypted }, session.sessionToken);
            revisions.record(id, revision);
          },
        });
      } catch (err) {
        process.stderr.write(`nopwd adopt: ${(err as Error).message}\n`);
        process.exit(1);
      }

      if (opts.json) {
        process.stdout.write(`${JSON.stringify(result)}\n`);
      } else if (result.rewritten) {
        process.stdout.write(`Saved "${result.itemName}" (${result.preview}) to the vault and replaced the value with ${result.reference}\n`);
        process.stdout.write(`Run with: nopwd run --dotenv ${file} -- <command>\n`);
      } else {
        process.stdout.write(`Saved "${result.itemName}" (${result.preview}) to the vault. ${file} was not edited.\n`);
        process.stdout.write(`Read it from an environment variable and set that to ${result.reference}\n`);
      }
    });
  });
