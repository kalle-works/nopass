import { invoke } from "@tauri-apps/api/core";

// The service name is pinned on the Rust side; only the account is passed.
export const keychain = {
  save: (account: string, value: string): Promise<void> =>
    invoke("keychain_save", { account, password: value }),

  load: (account: string): Promise<string | null> =>
    invoke("keychain_load", { account }),

  delete: (account: string): Promise<void> =>
    invoke("keychain_delete", { account }),
};

export const DEVICE_KEY_ACCOUNT = "device-enc-key";
