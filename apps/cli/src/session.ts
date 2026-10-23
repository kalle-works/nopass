import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomUUID } from "crypto";
import type { AccountState, AccountStateStore } from "@nopass/crypto";
import { MemoryRevisionStore, type RevisionSnapshot, applyV2OnlyMarker, trustStateId } from "@nopass/crypto";

export interface Session {
  sessionToken: string;
  email: string;
  /** Account id; absent in sessions saved before password change existed */
  userId?: string;
  /** base64-encoded AES-256-GCM vault encryption key bytes */
  vaultEncKeyB64: string;
  /** base64-encoded HMAC-SHA256 vault MAC key bytes */
  vaultMacKeyB64: string;
  defaultVaultId: string;
  apiUrl: string;
  /** Stable device UUID — used to link sessions to this machine */
  deviceId?: string;
}

export const SESSION_DIR = join(homedir(), ".nopwd");
const SESSION_PATH = join(SESSION_DIR, "session.json");
const DEVICE_ID_PATH = join(SESSION_DIR, "device_id");

export function loadSession(): Session | null {
  if (!existsSync(SESSION_PATH)) return null;
  try {
    const raw = readFileSync(SESSION_PATH, "utf-8");
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function saveSession(session: Session): void {
  mkdirSync(SESSION_DIR, { recursive: true });
  chmodSync(SESSION_DIR, 0o700);
  writeFileSync(SESSION_PATH, JSON.stringify(session, null, 2), { encoding: "utf-8", mode: 0o600 });
}

/**
 * Highest revision seen per vault item, persisted next to the session so a
 * server serving an older item blob is refused on later runs too. The file
 * is named by the account key rather than a server-supplied id, and the
 * account's v2-only marker is applied when the server has one.
 */
export async function openRevisionStore(
  vaultMacKey: CryptoKey,
  fetchMarker?: () => Promise<{ marker: string | null }>,
): Promise<MemoryRevisionStore> {
  const path = join(SESSION_DIR, `item-revisions-v2-${await trustStateId(vaultMacKey)}.json`);
  let initial: Partial<RevisionSnapshot> = {};
  try {
    initial = JSON.parse(readFileSync(path, "utf-8")) as Partial<RevisionSnapshot>;
  } catch {
    // first run on this machine
  }
  const store = new MemoryRevisionStore(initial, (snapshot) => {
    mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify(snapshot), { encoding: "utf-8", mode: 0o600 });
  });
  // Before the upgrade the file was named by the default vault id in this
  // machine's saved session. Fold it in (max per item) and remove it.
  const savedVaultId = loadSession()?.defaultVaultId;
  const legacyPath = savedVaultId && join(SESSION_DIR, `item-revisions-${savedVaultId}.json`);
  if (legacyPath && existsSync(legacyPath)) {
    try {
      const legacy = JSON.parse(readFileSync(legacyPath, "utf-8")) as Record<string, number>;
      for (const [itemId, revision] of Object.entries(legacy)) store.record(itemId, revision);
      unlinkSync(legacyPath);
    } catch {
      // unreadable — leave it for inspection rather than lose it silently
    }
  }
  if (fetchMarker) {
    try {
      await applyV2OnlyMarker((await fetchMarker()).marker, vaultMacKey, store);
    } catch {
      // offline — keep what this machine already knows
    }
  }
  return store;
}

export function clearSession(): void {
  if (existsSync(SESSION_PATH)) {
    unlinkSync(SESSION_PATH);
  }
}

export function loadDeviceId(): string | null {
  if (!existsSync(DEVICE_ID_PATH)) return null;
  try {
    const id = readFileSync(DEVICE_ID_PATH, "utf-8").trim();
    return id.length > 0 ? id : null;
  } catch {
    return null;
  }
}

export function saveDeviceId(deviceId: string): void {
  mkdirSync(SESSION_DIR, { recursive: true });
  chmodSync(SESSION_DIR, 0o700);
  writeFileSync(DEVICE_ID_PATH, deviceId, { encoding: "utf-8", mode: 0o600 });
}

export function getApiUrl(): string {
  const url = process.env.NOPASS_API_URL ?? "http://localhost:3001";
  if (url.startsWith("http://") && !url.includes("localhost") && !url.includes("127.0.0.1")) {
    process.stderr.write("Warning: NOPASS_API_URL uses plaintext HTTP over a non-local host — credentials may be exposed\n");
  }
  return url;
}

const ACCOUNT_STATE_PATH = join(SESSION_DIR, "account-state.json");

/**
 * Per-account facts this machine has seen (OPAQUE in use, account key
 * wrapped), so a server can't quietly downgrade them. Survives `nopwd lock`.
 */
export function fileAccountState(): AccountStateStore {
  const read = (): Record<string, AccountState> => {
    try {
      return JSON.parse(readFileSync(ACCOUNT_STATE_PATH, "utf-8")) as Record<string, AccountState>;
    } catch {
      return {};
    }
  };
  return {
    get: async (emailHash) => ({ ...read()[emailHash] }),
    update: async (emailHash, patch) => {
      const all = read();
      all[emailHash] = { ...all[emailHash], ...patch };
      mkdirSync(SESSION_DIR, { recursive: true });
      chmodSync(SESSION_DIR, 0o700);
      writeFileSync(ACCOUNT_STATE_PATH, JSON.stringify(all, null, 2), { encoding: "utf-8", mode: 0o600 });
    },
  };
}
