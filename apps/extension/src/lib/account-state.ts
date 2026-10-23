import type { AccountState, AccountStateStore } from "@nopass/crypto";

/**
 * Per-account facts this extension has seen (OPAQUE in use, account key
 * wrapped), in storage.local so they survive restarts and a server can't
 * quietly downgrade them.
 */
export function extensionAccountState(): AccountStateStore {
  const key = (emailHash: string) => `accountState:${emailHash}`;
  const get = async (emailHash: string): Promise<AccountState> =>
    ((await chrome.storage.local.get(key(emailHash)))[key(emailHash)] as AccountState | undefined) ?? {};
  return {
    get,
    update: async (emailHash, patch) => {
      await chrome.storage.local.set({ [key(emailHash)]: { ...(await get(emailHash)), ...patch } });
    },
  };
}
