import { Command } from "commander";
import { spawn } from "node:child_process";
import type { LoginItem, VaultItemPlaintext } from "@nopass/types";
import { fetchAndDecryptItems, withSession } from "../vault.js";

function toEnvKey(name: string): string {
  return name.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function itemToEnvVars(item: VaultItemPlaintext): Record<string, string> {
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

export const runCommand = new Command("run")
  .description("run a command with vault secrets injected as environment variables")
  .argument("<command...>", "command and arguments to run")
  .option(
    "-i, --item <names>",
    "comma-separated list of vault item names to inject (default: all login items)",
  )
  .option("--env-file", "print env vars to stdout instead of running a command (for .env generation)")
  .addHelpText(
    "after",
    `
Examples:
  nopwd run -- python agent.py
  nopwd run -i "OpenAI API Key,Anthropic API Key" -- node index.js
  nopwd run --env-file -i "OpenAI API Key" > .env
  OPENAI_API_KEY=$(nopwd get "OpenAI API Key") node index.js`,
  )
  .action(async (args: string[], opts: { item?: string; envFile?: boolean }) => {
    await withSession(async (session) => {
      const all = await fetchAndDecryptItems(session);

      let selected: VaultItemPlaintext[];
      if (opts.item) {
        const names = opts.item.split(",").map((n) => n.trim().toLowerCase());
        selected = all.filter((i) => names.some((n) => i.name.toLowerCase() === n || i.name.toLowerCase().includes(n)));
        if (selected.length === 0) {
          process.stderr.write(`No items found matching: ${opts.item}\n`);
          process.exit(2);
        }
      } else {
        selected = all.filter((i) => i.type === "login");
      }

      const injected: Record<string, string> = {};
      for (const item of selected) {
        Object.assign(injected, itemToEnvVars(item));
      }

      if (opts.envFile) {
        for (const [k, v] of Object.entries(injected)) {
          process.stdout.write(`${k}=${JSON.stringify(v)}\n`);
        }
        return;
      }

      if (args.length === 0) {
        process.stderr.write("No command specified. Usage: nopwd run -- <command>\n");
        process.exit(1);
      }

      const [cmd, ...cmdArgs] = args as [string, ...string[]];
      const child = spawn(cmd, cmdArgs, {
        stdio: "inherit",
        env: { ...process.env, ...injected },
        shell: false,
      });

      child.on("error", (err) => {
        process.stderr.write(`nopwd run: ${err.message}\n`);
        process.exit(1);
      });

      child.on("exit", (code, signal) => {
        if (signal) {
          process.kill(process.pid, signal);
        } else {
          process.exit(code ?? 0);
        }
      });
    });
  });
