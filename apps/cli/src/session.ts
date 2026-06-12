import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync, chmodSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomUUID } from "crypto";

export interface Session {
  sessionToken: string;
  email: string;
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
