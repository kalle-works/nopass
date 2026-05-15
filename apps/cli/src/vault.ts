import { decryptItem } from "@nopass/crypto";
import type { VaultItemPlaintext } from "@nopass/types";
import { createApiClient, ApiError } from "./api-client.js";
import { loadSession, clearSession, type Session } from "./session.js";
import { importKeys } from "./auth.js";

export async function fetchAndDecryptItems(
  session: Session,
): Promise<VaultItemPlaintext[]> {
  const api = createApiClient(session.apiUrl);
  const encrypted = await api.vault.items(session.defaultVaultId, session.sessionToken);
  const active = encrypted.filter((i) => i.deletedAt === null);

  const { vaultEncKey, vaultMacKey } = await importKeys(session);
  const results = await Promise.all(
    active.map((item) =>
      decryptItem({ blob: item.blob, blobIv: item.blobIv, blobMac: item.blobMac }, vaultEncKey, vaultMacKey),
    ),
  );
  return results;
}

export async function requireSession(): Promise<Session> {
  const session = loadSession();
  if (!session) {
    process.stderr.write("Not logged in. Run: nopwd login\n");
    process.exit(1);
  }
  return session;
}

export async function withSession<T>(
  fn: (session: Session) => Promise<T>,
): Promise<T> {
  const session = await requireSession();
  try {
    return await fn(session);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      clearSession();
      process.stderr.write("Session expired. Run: nopwd login\n");
      process.exit(1);
    }
    throw err;
  }
}
