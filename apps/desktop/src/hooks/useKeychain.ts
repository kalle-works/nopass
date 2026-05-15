import { invoke } from "@tauri-apps/api/core";

const SERVICE = "app.nopass.desktop";

export const keychain = {
  save: (account: string, value: string): Promise<void> =>
    invoke("keychain_save", { service: SERVICE, account, password: value }),

  load: (account: string): Promise<string | null> =>
    invoke("keychain_load", { service: SERVICE, account }),

  delete: (account: string): Promise<void> =>
    invoke("keychain_delete", { service: SERVICE, account }),
};

export const DEVICE_KEY_ACCOUNT = "device-enc-key";
