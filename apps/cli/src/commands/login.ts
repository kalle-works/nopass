import { Command } from "commander";
import { loginWithCredentials } from "../auth.js";
import { prompt, closePrompt } from "../prompt.js";
import { getApiUrl } from "../session.js";
import { ApiError } from "../api-client.js";

export const loginCommand = new Command("login")
  .description("authenticate with the nopwd vault")
  .option("-e, --email <email>", "email address (or set NOPASS_EMAIL)")
  .option("-u, --api-url <url>", "API base URL (or set NOPASS_API_URL)")
  .action(async (opts: { email?: string; apiUrl?: string }) => {
    const apiUrl = opts.apiUrl ?? getApiUrl();
    const email = opts.email ?? process.env.NOPASS_EMAIL ?? await prompt("Email: ");
    const password = process.env.NOPASS_MASTER_PASSWORD ?? await prompt("Master password: ", true);
    closePrompt();

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
