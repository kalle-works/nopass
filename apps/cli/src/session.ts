import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";

export interface Session {
  sessionToken: string;
  email: string;
  /** base64-encoded AES-256-GCM vault encryption key bytes */
  vaultEncKeyB64: string;
  /** base64-encoded HMAC-SHA256 vault MAC key bytes */
  vaultMacKeyB64: string;
  defaultVaultId: string;
  apiUrl: string;
}

const SESSION_DIR = join(homedir(), ".nopwd");
const SESSION_PATH = join(SESSION_DIR, "session.json");

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
  if (!existsSync(SESSION_DIR)) {
    mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });
  }
  writeFileSync(SESSION_PATH, JSON.stringify(session, null, 2), { encoding: "utf-8", mode: 0o600 });
}

export function clearSession(): void {
  if (existsSync(SESSION_PATH)) {
    unlinkSync(SESSION_PATH);
  }
}

export function getApiUrl(): string {
  return process.env.NOPASS_API_URL ?? "http://localhost:3001";
}
