/**
 * Client-side trust state that must outlive a session but is not secret:
 * the highest revision seen per vault item (rollback protection) and the
 * identity keys pinned for other users (TOFU). Kept in localStorage per
 * account so a server cannot reset it.
 */
import { type KeyPinStore, MemoryRevisionStore } from "@nopass/crypto";

function readJson<T>(key: string, fallback: T): T {
  if (typeof localStorage === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(key: string, value: unknown): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // storage unavailable — protection degrades to this session only
  }
}

/** Revision store for one account, keyed by its default vault id. */
export function openRevisionStore(accountKey: string): MemoryRevisionStore {
  const key = `nopass:item-revisions:${accountKey}`;
  return new MemoryRevisionStore(readJson(key, {}), (snapshot) => writeJson(key, snapshot));
}

/** Identity keys this account has pinned for other users, keyed by user id. */
export function openKeyPinStore(accountKey: string): KeyPinStore {
  const key = `nopass:key-pins:${accountKey}`;
  const pins = readJson<Record<string, string>>(key, {});
  return {
    get: (userId) => pins[userId],
    set: (userId, identityPublicKeyB64) => {
      pins[userId] = identityPublicKeyB64;
      writeJson(key, pins);
    },
  };
}
