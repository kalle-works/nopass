import { Command } from "commander";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import type { VaultItemPlaintext } from "@nopass/types";
import { fetchAndDecryptItems, withSession } from "../vault.js";
import { formatReference, isReference, itemToEnvVars, parseDotenv, resolveReference } from "../secret-refs.js";

/** Resolves `nopwd://item-name/field` references in an environment-like map. Unresolvable ones are reported and dropped. */
function resolveSecretRefs(
  vault: VaultItemPlaintext[],
  source: Record<string, string | undefined>,
): Record<string, string> {
  const resolved: Record<string, string> = {};
  for (const [envKey, envVal] of Object.entries(source)) {
    if (!isReference(envVal)) continue;
    const result = resolveReference(vault, envVal);
    if (result.ok) {
      resolved[envKey] = result.value;
    } else {
      process.stderr.write(`nopwd run: ${result.error}\n`);
    }
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
  env: Record<string, string | undefined>,
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
    const ref = formatReference(decodeURIComponent(match[1]!), decodeURIComponent(match[2]!));
    const result = resolveReference(vault, ref);
    if (!result.ok) {
      res.writeHead(404);
      res.end(result.error);
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(result.value);
  });

  server.listen(socketPath, () => {
    const child = spawn(cmd, cmdArgs, {
      stdio: "inherit",
      env: { ...env, NOPWD_SOCKET: socketPath },
      shell: false,
    });

    // Forward termination signals so a `kill <nopwd-pid>` doesn't orphan the
    // child and leave the secrets socket on disk
    const forward = (sig: NodeJS.Signals) => child.kill(sig);
    process.on("SIGINT", forward);
    process.on("SIGTERM", forward);

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
        process.removeListener("SIGINT", forward);
        process.removeListener("SIGTERM", forward);
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

/**
 * Items whose fields are injected wholesale: the ones named with -i, otherwise
 * every login. With --dotenv the file names exactly what the app needs, so
 * nothing else from the vault is handed over unless -i asks for it.
 */
export function selectInjectedItems(
  all: VaultItemPlaintext[],
  opts: { item?: string | undefined; dotenv?: string | undefined },
): VaultItemPlaintext[] {
  if (opts.item) {
    const names = opts.item.split(",").map((n) => n.trim().toLowerCase());
    return all.filter((i) => names.some((n) => i.name.toLowerCase() === n || i.name.toLowerCase().includes(n)));
  }
  if (opts.dotenv) return [];
  return all.filter((i) => i.type === "login");
}

export const runCommand = new Command("run")
  .description("run a command with vault secrets injected as environment variables")
  .argument("<command...>", "command and arguments to run")
  .option(
    "-i, --item <names>",
    "comma-separated list of vault item names to inject (default: all login items, or none with --dotenv)",
  )
  .option("--env-file", "print env vars to stdout instead of running a command (for .env generation)")
  .option(
    "--via-socket",
    "serve secrets over a Unix domain socket (NOPWD_SOCKET) instead of injecting into env; secrets never appear in ps output",
  )
  .option(
    "--dotenv <path>",
    "load variables from a .env file and resolve its nopwd:// values; only those secrets are injected unless -i is given (variables already set in the environment win)",
  )
  .addHelpText(
    "after",
    `
Examples:
  nopwd run -- python agent.py
  nopwd run -i "OpenAI API Key,Anthropic API Key" -- node index.js
  nopwd run --env-file -i "OpenAI API Key" > .env
  nopwd run --via-socket -- python agent.py  # secrets served via $NOPWD_SOCKET, not in env
  nopwd run --dotenv .env -- npm run dev       # .env may hold KEY="nopwd://Item/password"
  OPENAI_API_KEY=$(nopwd get "OpenAI API Key") node index.js`,
  )
  .action(async (args: string[], opts: { item?: string; envFile?: boolean; viaSocket?: boolean; dotenv?: string }) => {
    let dotenvVars: Record<string, string> = {};
    if (opts.dotenv) {
      try {
        dotenvVars = Object.fromEntries(parseDotenv(readFileSync(opts.dotenv, "utf-8")).map((e) => [e.key, e.value]));
      } catch (err) {
        process.stderr.write(`nopwd run: cannot read ${opts.dotenv}: ${(err as Error).message}\n`);
        process.exit(1);
      }
    }
    const baseEnv: Record<string, string | undefined> = { ...dotenvVars, ...process.env };

    await withSession(async (session) => {
      const all = await fetchAndDecryptItems(session);

      const selected = selectInjectedItems(all, opts);
      if (opts.item && selected.length === 0) {
        process.stderr.write(`No items found matching: ${opts.item}\n`);
        process.exit(2);
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

      if (opts.viaSocket) {
        // Secrets never enter the child's environment — served on demand via socket.
        // nopwd:// env references are deliberately left unresolved here (resolving
        // them would put plaintext back into the env); tell the user instead.
        const unresolvedRefs = Object.entries(baseEnv)
          .filter(([, v]) => isReference(v))
          .map(([k]) => k);
        if (unresolvedRefs.length > 0) {
          process.stderr.write(
            `nopwd run: --via-socket does not resolve nopwd:// references (${unresolvedRefs.join(", ")}); ` +
            `fetch them via $NOPWD_SOCKET instead\n`,
          );
        }
        spawnViaSocket(selected, cmd, cmdArgs, baseEnv);
        // spawnViaSocket manages its own event loop — don't return
        return new Promise<void>(() => { /* intentionally never resolves */ });
      }

      // Resolve nopwd:// references from the calling environment and the --dotenv file
      const refOverrides = resolveSecretRefs(all, baseEnv);

      const child = spawn(cmd, cmdArgs, {
        stdio: "inherit",
        env: { ...baseEnv, ...refOverrides, ...injected },
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
