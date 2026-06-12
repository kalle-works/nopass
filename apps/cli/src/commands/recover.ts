import { Command } from "commander";
import {
  computeEmailHash,
  decryptBytes,
  decryptItem,
  deriveMasterKey,
  deriveRecoveryKeys,
  encryptBytes,
  encryptItem,
  generateRecoveryCode,
  generateSrpRegistration,
  stretchMasterKey,
  stretchMasterKeyAllRaw,
  unwrapVaultSubkeys,
  wrapVaultSubkeys,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS, type ReencryptedItem } from "@nopass/types";
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
      process.stderr.write(`Vault keys recovered. ${init.items.length} item(s) to re-encrypt.\n`);

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

      const importAes = (bytes: Uint8Array<ArrayBuffer>, usages: KeyUsage[]) =>
        crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, usages);
      const oldEncKey = await importAes(old.encKeyBytes, ["decrypt"]);
      const oldMacKey = await crypto.subtle.importKey(
        "raw",
        old.macKeyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      const oldSmkKey = await importAes(old.smkBytes, ["decrypt"]);

      process.stderr.write("Deriving new keys…\n");
      const newMasterKey = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
      const newKeys = await stretchMasterKey(newMasterKey, email);
      const newRaw = await stretchMasterKeyAllRaw(newMasterKey, email);
      const { srpSalt, srpVerifier } = generateSrpRegistration(email, newPassword);

      process.stderr.write("Re-encrypting vault…\n");
      const items: ReencryptedItem[] = [];
      for (const item of init.items) {
        const plain = await decryptItem(
          { blob: item.blob, blobIv: item.blobIv, blobMac: item.blobMac },
          oldEncKey,
          oldMacKey,
        );
        const reencrypted = await encryptItem(plain, newKeys.vaultEncKey, newKeys.vaultMacKey);
        items.push({ id: item.id, ...reencrypted });
      }

      const protectedKey = await encryptBytes(newRaw.encKeyBytes, newKeys.stretchedMasterKey);

      let protectedPrivateKey: string | undefined;
      let protectedPrivateKeyIv: string | undefined;
      if (init.protectedPrivateKey && init.protectedPrivateKeyIv) {
        const pkcs8 = await decryptBytes(
          { blob: init.protectedPrivateKey, blobIv: init.protectedPrivateKeyIv, blobMac: "" },
          oldSmkKey,
        );
        const rewrapped = await encryptBytes(pkcs8, newKeys.stretchedMasterKey);
        pkcs8.fill(0);
        protectedPrivateKey = rewrapped.blob;
        protectedPrivateKeyIv = rewrapped.blobIv;
      }

      // The used code burns server-side — mint the replacement in the same pass
      const replacementCode = generateRecoveryCode();
      const replacementKeys = await deriveRecoveryKeys(replacementCode, email);
      const replacementBlob = await wrapVaultSubkeys(newRaw, replacementKeys.wrapKey);

      newRaw.smkBytes.fill(0);
      newRaw.encKeyBytes.fill(0);
      newRaw.macKeyBytes.fill(0);
      old.smkBytes.fill(0);
      old.encKeyBytes.fill(0);
      old.macKeyBytes.fill(0);

      await api.auth.recoveryComplete({
        recoveryToken: init.recoveryToken,
        srpSalt,
        srpVerifier,
        protectedSymmetricKey: protectedKey.blob,
        protectedSymmetricKeyIv: protectedKey.blobIv,
        ...(protectedPrivateKey && protectedPrivateKeyIv
          ? { protectedPrivateKey, protectedPrivateKeyIv }
          : {}),
        items,
        recoveryAuthKey: replacementKeys.authKeyB64,
        recoveryBlob: replacementBlob.blob,
        recoveryBlobIv: replacementBlob.blobIv,
      });

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
