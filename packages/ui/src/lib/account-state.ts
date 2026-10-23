import { keyValueAccountState, memoryAccountState, type AccountStateStore } from "@nopass/crypto";

/**
 * Per-account facts this browser has seen (OPAQUE in use, account key
 * wrapped), kept in localStorage so a server can't quietly downgrade them.
 */
export function browserAccountState(): AccountStateStore {
  return typeof localStorage === "undefined" ? memoryAccountState() : keyValueAccountState(localStorage);
}
