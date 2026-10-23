import { Command } from "commander";
import {
  completeAccountRecovery,
  computeEmailHash,
  deriveRecoveryKeys,
  unwrapVaultSubkeys,
} from "@nopass/crypto";
import { createApiClient } from "../api-client.js";
import { prompt, closePrompt } from "../prompt.js";
import { clearSession, getApiUrl } from "../session.js";

export const recoverCommand = new Command("recover")
  .description("recover your account with a recovery code and set a new master password")
  .option("-e, --email <email>", "email address (or set NOPASS_EMAIL)")
  .option("-u, --api-url <url>", "API base URL (or set NOPASS_API_URL)")
  .action(async (opts: { email?: string; apiUrl?: string }) => {
    const apiUrl = opts.apiUrl ?? getApiUrl();
    const api = createApiClient(apiUrl);

    const email = opts.email ?? process.env["NOPASS_EMAIL"] ?? (await prompt("Email: "));
    const code = await prompt("Recovery code: ");

    try {
      process.stderr.write("Deriving recovery key (Argon2id)…\n");
      const { authKeyB64, wrapKey } = await deriveRecoveryKeys(code, email);

      const init = await api.auth.recoveryInit({
        emailHash: computeEmailHash(email),
        recoveryAuthKey: authKeyB64,
      });

      const old = await unwrapVaultSubkeys(
        { blob: init.recoveryBlob, blobIv: init.recoveryBlobIv, blobMac: "" },
        wrapKey,
      );
      process.stderr.write("Vault keys recovered.\n");

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

      process.stderr.write("Deriving new keys (Argon2id)…\n");
      // The kit holds the account key: re-wrap it under the new password;
      // no item is re-encrypted.
      const replacementCode = await completeAccountRecovery(
        { opaqueStart: api.auth.recoveryOpaqueStart, complete: api.auth.recoveryComplete },
        { email, newPassword, init, recovered: old },
      );
      old.smkBytes.fill(0);
      old.encKeyBytes.fill(0);
      old.macKeyBytes.fill(0);

      clearSession();

      process.stdout.write("\nAccount recovered. All other sessions are revoked.\n\n");
      process.stdout.write("Your NEW recovery code (the old one is dead) — store it offline now:\n\n");
      process.stdout.write(`    ${replacementCode}\n\n`);
      process.stdout.write(`Sign in with the new password: nopwd login -e ${email}\n`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.toLowerCase().includes("invalid recovery") || msg.toLowerCase().includes("unauthorized")) {
        process.stderr.write("That email and recovery code combination doesn't match.\n");
      } else if (msg.toLowerCase().includes("operation")) {
        process.stderr.write("The recovery code didn't decrypt your vault keys — check it character by character.\n");
      } else {
        process.stderr.write(`Recovery failed: ${msg}\n`);
      }
      process.exit(1);
    }
  });
