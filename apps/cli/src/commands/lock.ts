import { Command } from "commander";
import { loadSession, clearSession } from "../session.js";
import { createApiClient } from "../api-client.js";

export const lockCommand = new Command("lock")
  .description("revoke session on server and clear local credentials")
  .action(async () => {
    const session = loadSession();
    if (session) {
      try {
        await createApiClient(session.apiUrl).auth.logout(session.sessionToken);
      } catch {
        // Best-effort — clear locally regardless of network failures
      }
    }
    clearSession();
    process.stdout.write("Vault locked — session revoked.\n");
  });
