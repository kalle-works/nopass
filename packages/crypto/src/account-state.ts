/**
 * What this device has already seen of an account, kept locally per email
 * hash. The server can't be trusted to report it honestly: once an account
 * is known to use OPAQUE, a server that answers like a legacy SRP account is
 * downgrading it; once its account key is known to be wrapped, a login
 * response without the wrap is refused instead of falling back to deriving
 * legacy keys.
 */
import type { KdfParams } from "@nopass/types";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";

export interface AccountState {
  /** The account has logged in over OPAQUE on this device */
  opaque?: boolean;
  /** The account key is wrapped server-side (account-key hierarchy) */
  accountKey?: boolean;
}

export interface AccountStateStore {
  get(emailHash: string): Promise<AccountState>;
  update(emailHash: string, patch: AccountState): Promise<void>;
}

/** For tests and short-lived tools; forgets everything when the process ends. */
export function memoryAccountState(): AccountStateStore {
  const states = new Map<string, AccountState>();
  return {
    get: async (emailHash) => ({ ...states.get(emailHash) }),
    update: async (emailHash, patch) => {
      states.set(emailHash, { ...states.get(emailHash), ...patch });
    },
  };
}

/** Synchronous key-value storage such as localStorage. */
export function keyValueAccountState(storage: Pick<Storage, "getItem" | "setItem">): AccountStateStore {
  const key = (emailHash: string) => `nopass:account-state:${emailHash}`;
  return {
    get: async (emailHash) => {
      try {
        return JSON.parse(storage.getItem(key(emailHash)) ?? "{}") as AccountState;
      } catch {
        return {};
      }
    },
    update: async (emailHash, patch) => {
      let current: AccountState = {};
      try {
        current = JSON.parse(storage.getItem(key(emailHash)) ?? "{}") as AccountState;
      } catch {
        // A corrupted entry is replaced
      }
      storage.setItem(key(emailHash), JSON.stringify({ ...current, ...patch }));
    },
  };
}

/** The server chose KDF parameters weaker than every client uses. */
export class WeakKdfParamsError extends Error {
  constructor() {
    super("The server asked for weaker password hashing than this app allows. Not signing in.");
    this.name = "WeakKdfParamsError";
  }
}

/**
 * Server-supplied Argon2id parameters feed the OPAQUE key stretching. A
 * malicious server could lower them to make the password cheaper to guess
 * from what the client sends, so anything below the defaults is refused.
 */
export function assertKdfFloor(params: KdfParams): KdfParams {
  if (
    params.type !== "argon2id" ||
    params.memoryKib < DEFAULT_KDF_PARAMS.memoryKib ||
    params.iterations < DEFAULT_KDF_PARAMS.iterations ||
    params.parallelism < 1
  ) {
    throw new WeakKdfParamsError();
  }
  return params;
}
