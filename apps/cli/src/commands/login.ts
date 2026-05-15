import { Command } from "commander";
import { createInterface } from "readline";
import { loginWithCredentials } from "../auth.js";
import { getApiUrl } from "../session.js";
import { ApiError } from "../api-client.js";

function prompt(question: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    if (hidden) {
      // Disable echo for password input
      process.stdout.write(question);
      process.stdin.setRawMode?.(true);
      let input = "";
      process.stdin.setEncoding("utf-8");
      process.stdin.once("data", function handler(chunk: string) {
        process.stdin.setRawMode?.(false);
        process.stdin.removeListener("data", handler);
        process.stdout.write("\n");
        rl.close();
        for (const c of chunk) {
          if (c === "\r" || c === "\n") break;
          if (c === "\x7f" || c === "\b") { input = input.slice(0, -1); continue; }
          if (c === "\x03") process.exit(1);
          input += c;
        }
        resolve(input);
      });
      process.stdin.resume();
    } else {
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    }
  });
}

export const loginCommand = new Command("login")
  .description("authenticate with the nopass vault")
  .option("-e, --email <email>", "email address (or set NOPASS_EMAIL)")
  .option("-u, --api-url <url>", "API base URL (or set NOPASS_API_URL)")
  .action(async (opts: { email?: string; apiUrl?: string }) => {
    const apiUrl = opts.apiUrl ?? getApiUrl();
    const email = opts.email ?? process.env.NOPASS_EMAIL ?? await prompt("Email: ");
    const password = process.env.NOPASS_MASTER_PASSWORD ?? await prompt("Master password: ", true);

    try {
      process.stderr.write("Deriving key with Argon2id…\n");
      await loginWithCredentials(email, password, apiUrl);
      process.stdout.write(`Logged in as ${email}\n`);
    } catch (err) {
      if (err instanceof ApiError) {
        process.stderr.write(`Login failed: ${err.message}\n`);
      } else {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      }
      process.exit(1);
    }
  });
