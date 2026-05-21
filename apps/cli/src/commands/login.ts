import { Command } from "commander";
import { createInterface } from "readline";
import { loginWithCredentials } from "../auth.js";
import { getApiUrl } from "../session.js";
import { ApiError } from "../api-client.js";

function prompt(question: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    if (hidden) {
      process.stdout.write(question);
      process.stdin.setRawMode?.(true);
      process.stdin.resume();
      let input = "";
      const handler = (chunk: Buffer) => {
        for (const byte of chunk) {
          if (byte === 0x0d || byte === 0x0a) { // enter
            process.stdin.setRawMode?.(false);
            process.stdin.removeListener("data", handler);
            process.stdin.pause();
            process.stdout.write("\n");
            resolve(input);
            return;
          }
          if (byte === 0x03) process.exit(1); // Ctrl+C
          if (byte === 0x7f || byte === 0x08) { input = input.slice(0, -1); continue; } // backspace
          input += String.fromCharCode(byte);
        }
      };
      process.stdin.on("data", handler);
    } else {
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      rl.question(question, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    }
  });
}

export const loginCommand = new Command("login")
  .description("authenticate with the nopwd vault")
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
