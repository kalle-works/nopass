import { Command } from "commander";
import type { VaultItemPlaintext } from "@nopass/types";
import { fetchAndDecryptItems, withSession } from "../vault.js";

export const listCommand = new Command("list")
  .description("list all vault items")
  .option("--json", "output as JSON array")
  .action(async (opts: { json?: boolean }) => {
    await withSession(async (session) => {
      const items = await fetchAndDecryptItems(session);

      if (opts.json) {
        process.stdout.write(JSON.stringify(items, null, 2) + "\n");
        return;
      }

      if (items.length === 0) {
        process.stdout.write("Vault is empty.\n");
        return;
      }

      const maxLen = Math.max(...items.map((i) => i.name.length));
      for (const item of items) {
        const name = item.name.padEnd(maxLen);
        process.stdout.write(`${name}  [${item.type}]\n`);
      }
    });
  });
