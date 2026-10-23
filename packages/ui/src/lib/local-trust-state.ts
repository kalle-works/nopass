/**
 * Client-side trust state that must outlive a session but is not secret:
 * the highest revision seen per vault item (rollback protection). Kept in
 * localStorage per account so a server cannot reset it.
 */
import { MemoryRevisionStore } from "@nopass/crypto";

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
