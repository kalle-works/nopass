import { Command } from "commander";
import { changeMasterPassword, IncorrectPasswordError } from "@nopass/crypto";
import { ApiError, createApiClient } from "../api-client.js";
import { prompt, closePrompt } from "../prompt.js";
import { loadSession } from "../session.js";

export const passwdCommand = new Command("passwd")
  .description("change your master password (signs out your other devices)")
  .action(async () => {
    const session = loadSession();
    if (!session) {
      process.stderr.write("Log in first (`nopwd login`), then run this again.\n");
      process.exit(1);
    }

    const currentPassword = await prompt("Current master password: ", true);
    const newPassword = await prompt("New master password: ", true);
    const confirm = await prompt("Repeat it: ", true);
    closePrompt();
    if (newPassword !== confirm) {
      process.stderr.write("Passwords don't match.\n");
      process.exit(1);
    }
    if (newPassword.length < 8) {
      process.stderr.write("Use at least 8 characters.\n");
      process.exit(1);
    }

    try {
      process.stderr.write("Deriving keys (Argon2id)…\n");
      // Only the wrap of the account key changes, so this session's vault keys stay valid.
      await changeMasterPassword(createApiClient(session.apiUrl).auth, {
        email: session.email,
        sessionToken: session.sessionToken,
        currentPassword,
        newPassword,
      });
      process.stdout.write("Master password changed. Your other devices are signed out; your recovery kit still works.\n");
    } catch (err) {
      if (err instanceof IncorrectPasswordError || (err instanceof ApiError && err.status === 401)) {
        process.stderr.write("Current master password is incorrect.\n");
      } else if (err instanceof ApiError && err.status === 403) {
        process.stderr.write("Your session is too old to change the password. Run `nopwd login`, then retry within 15 minutes.\n");
      } else if (err instanceof ApiError && err.status === 409) {
        process.stderr.write("Log in again first so your account can be upgraded, then retry.\n");
      } else {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      }
      process.exit(1);
    }
  });
