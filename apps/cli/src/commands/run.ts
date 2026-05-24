import { Command } from "commander";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

/** Resolve nopwd://item-name/field references in the parent process environment. */
function resolveSecretRefs(
  vault: VaultItemPlaintext[],
): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const [envKey, envVal] of Object.entries(process.env)) {
    if (!envVal?.startsWith("nopwd://")) continue;
    const rest = envVal.slice("nopwd://".length);
    const slashIdx = rest.indexOf("/");
    if (slashIdx <= 0) continue;

    const itemName = rest.slice(0, slashIdx).toLowerCase();
    const fieldName = rest.slice(slashIdx + 1).toLowerCase();
    const item = vault.find((i) => i.name.toLowerCase() === itemName);
    if (!item) {
      process.stderr.write(`nopwd run: no vault item matches reference ${envVal}\n`);
      continue;
    }
    const vars = itemToEnvVars(item);
    const itemKey = toEnvKey(item.name);
    const fieldKey =
      fieldName === "password" ? itemKey :
      fieldName === "username" ? `${itemKey}_USERNAME` :
      fieldName === "totp" ? `${itemKey}_TOTP` :
      `${itemKey}_${toEnvKey(fieldName)}`;
    const value = vars[fieldKey];
    if (value === undefined) {
      process.stderr.write(`nopwd run: field "${fieldName}" not found in vault item "${item.name}"\n`);
      continue;
    }
    resolved[envKey] = value;
  }
  return resolved;
}

/** Start a Unix domain socket server that serves secrets on demand.
 *  The child receives NOPWD_SOCKET pointing to the socket path.
 *  Any process can request a secret via:
 *    curl --unix-socket "$NOPWD_SOCKET" http://localhost/secret/ITEM_NAME/FIELD
 */
function spawnViaSocket(
  vault: VaultItemPlaintext[],
  cmd: string,
  cmdArgs: string[],
): void {
  const socketDir = mkdtempSync(join(tmpdir(), "nopwd-"));
  const socketPath = join(socketDir, "secrets.sock");

  const server = createServer((req, res) => {
    const match = req.url?.match(/^\/secret\/([^/]+)\/([^/]+)$/);
    if (!match) {
      res.writeHead(400);
      res.end("expected /secret/ITEM/FIELD");
      return;
    }
    const itemName = decodeURIComponent(match[1]!).toLowerCase();
    const fieldName = decodeURIComponent(match[2]!).toLowerCase();
    const item = vault.find((i) => i.name.toLowerCase() === itemName);
    if (!item) {
      res.writeHead(404);
      res.end("item not found");
      return;
    }
    const vars = itemToEnvVars(item);
    const itemKey = toEnvKey(item.name);
    const fieldKey =
      fieldName === "password" ? itemKey :
      fieldName === "username" ? `${itemKey}_USERNAME` :
      fieldName === "totp" ? `${itemKey}_TOTP` :
      `${itemKey}_${toEnvKey(fieldName)}`;
    const value = vars[fieldKey];
    if (value === undefined) {
      res.writeHead(404);
      res.end("field not found");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(value);
  });

  server.listen(socketPath, () => {
    const child = spawn(cmd, cmdArgs, {
      stdio: "inherit",
      env: { ...process.env, NOPWD_SOCKET: socketPath },
      shell: false,
    });

    child.on("error", (err) => {
      server.close();
      cleanup();
      process.stderr.write(`nopwd run: ${err.message}\n`);
      process.exit(1);
    });

    child.on("exit", (code, signal) => {
      server.close();
      cleanup();
      if (signal) {
        process.kill(process.pid, signal);
      } else {
        process.exit(code ?? 0);
      }
    });
  });

  function cleanup() {
    try { rmSync(socketDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

export const runCommand = new Command("run")
  .description("run a command with vault secrets injected as environment variables")
  .argument("<command...>", "command and arguments to run")
  .option(
    "-i, --item <names>",
    "comma-separated list of vault item names to inject (default: all login items)",
  )
  .option("--env-file", "print env vars to stdout instead of running a command (for .env generation)")
  .option(
    "--via-socket",
    "serve secrets over a Unix domain socket (NOPWD_SOCKET) instead of injecting into env; secrets never appear in ps output",
  )
  .addHelpText(
    "after",
    `
Examples:
  nopwd run -- python agent.py
  nopwd run -i "OpenAI API Key,Anthropic API Key" -- node index.js
  nopwd run --env-file -i "OpenAI API Key" > .env
  nopwd run --via-socket -- python agent.py  # secrets served via $NOPWD_SOCKET, not in env
  OPENAI_API_KEY=$(nopwd get "OpenAI API Key") node index.js`,
  )
  .action(async (args: string[], opts: { item?: string; envFile?: boolean; viaSocket?: boolean }) => {
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

      // Resolve any nopwd:// references in the calling environment
      const refOverrides = resolveSecretRefs(all);

      const [cmd, ...cmdArgs] = args as [string, ...string[]];

      if (opts.viaSocket) {
        // Secrets never enter the child's environment — served on demand via socket
        spawnViaSocket(selected, cmd, cmdArgs);
        // spawnViaSocket manages its own event loop — don't return
        return new Promise<void>(() => { /* intentionally never resolves */ });
      }

      const child = spawn(cmd, cmdArgs, {
        stdio: "inherit",
        env: { ...process.env, ...refOverrides, ...injected },
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
