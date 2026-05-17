import { invoke } from "@tauri-apps/api/core";

export interface SshKeyPayload {
  privateKey: string;
  passphrase?: string;
  comment?: string;
}

export const sshAgent = {
  // ── Legacy helpers (add to system ssh-agent via ssh-add) ──────────────────
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

  // ── In-process agent (Unix socket served by nopass) ───────────────────────

  /** Load all SSH keys from the unlocked vault into the in-process agent. */
  loadVaultKeys: (keys: SshKeyPayload[]): Promise<number> =>
    invoke("ssh_agent_load_vault_keys", { keys }),

  /** Clear all keys from the in-process agent (called when vault locks). */
  clearVaultKeys: (): Promise<void> =>
    invoke("ssh_agent_clear_vault_keys"),

  /** Returns the Unix socket path, e.g. ~/.nopass/agent.sock */
  socketPath: (): Promise<string> =>
    invoke("ssh_agent_socket_path"),

  /** Returns the shell snippet to add to ~/.zshrc / ~/.bashrc */
  shellConfig: (): Promise<string> =>
    invoke("ssh_agent_shell_config"),
};
