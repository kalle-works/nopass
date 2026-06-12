import { Command } from "commander";
import type { VaultItemPlaintext } from "@nopass/types";
import { fetchAndDecryptItems, withSession } from "../vault.js";

export const listCommand = new Command("list")
  .description("list all vault items")
  .option("--json", "output as JSON array")
  .option("-t, --tag <tag>", "only show items with this tag")
  .action(async (opts: { json?: boolean; tag?: string }) => {
    await withSession(async (session) => {
      let items: VaultItemPlaintext[] = await fetchAndDecryptItems(session);

      if (opts.tag) {
        const wanted = opts.tag.toLowerCase();
        items = items.filter((i) => i.tags?.some((t) => t.toLowerCase() === wanted));
      }

      if (opts.json) {
        process.stdout.write(JSON.stringify(items, null, 2) + "\n");
        return;
      }

      if (items.length === 0) {
        process.stdout.write(opts.tag ? `No items tagged "${opts.tag}".\n` : "Vault is empty.\n");
        return;
      }

      const maxLen = Math.max(...items.map((i) => i.name.length));
      for (const item of items) {
        const name = item.name.padEnd(maxLen);
        const tags = item.tags?.length ? `  #${item.tags.join(" #")}` : "";
        process.stdout.write(`${name}  [${item.type}]${tags}\n`);
      }
    });
  });
