import { invoke } from "@tauri-apps/api/core";

export const sshAgent = {
  add: (privateKey: string, passphrase?: string): Promise<string> =>
    invoke("ssh_agent_add", { privateKey, passphrase: passphrase ?? null }),

  remove: (publicKey: string): Promise<string> =>
    invoke("ssh_agent_remove", { publicKey }),

  list: (): Promise<string> =>
    invoke("ssh_agent_list"),

  writeKeyFile: (filename: string, privateKey: string, publicKey?: string): Promise<string> =>
    invoke("ssh_write_key_file", { filename, privateKey, publicKey: publicKey ?? null }),

  deleteKeyFile: (filename: string): Promise<void> =>
    invoke("ssh_delete_key_file", { filename }),
};
