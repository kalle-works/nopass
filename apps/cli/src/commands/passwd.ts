import { Command } from "commander";
import {
  changeMasterPassword,
  deriveMasterKey,
  IncorrectPasswordError,
  stretchMasterKeyRaw,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { ApiError, createApiClient } from "../api-client.js";
import { prompt, closePrompt } from "../prompt.js";
import { loadSession, saveSession } from "../session.js";

export const passwdCommand = new Command("passwd")
  .description("change your master password (re-encrypts the vault, signs out other devices)")
  .action(async () => {
    const session = loadSession();
    if (!session) {
      process.stderr.write("Not logged in. Run `nopwd login` first.\n");
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
      await changeMasterPassword(createApiClient(session.apiUrl).auth, {
        email: session.email,
        sessionToken: session.sessionToken,
        currentPassword,
        newPassword,
        onProgress: (step) => process.stderr.write(`${step}\n`),
      });

      // This session survives the change; it just needs the new vault keys.
      const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(
        await deriveMasterKey(newPassword, session.email, DEFAULT_KDF_PARAMS),
        session.email,
      );
      saveSession({
        ...session,
        vaultEncKeyB64: Buffer.from(encKeyBytes).toString("base64"),
        vaultMacKeyB64: Buffer.from(macKeyBytes).toString("base64"),
      });
      encKeyBytes.fill(0);
      macKeyBytes.fill(0);

      process.stdout.write(
        "Master password changed. Other devices are signed out. Your recovery kit no longer works: create a new one in the web app.\n",
      );
    } catch (err) {
      if (err instanceof IncorrectPasswordError || (err instanceof ApiError && err.status === 401)) {
        process.stderr.write("Current master password is incorrect.\n");
      } else {
        process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
      }
      process.exit(1);
    }
  });
