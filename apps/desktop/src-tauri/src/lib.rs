mod commands;
mod ssh_agent;

use ssh_agent::SharedKeys;
use std::sync::{Arc, Mutex};

/// Tauri-managed wrapper so commands can access the shared key store.
pub struct AgentState(pub SharedKeys);

fn agent_socket_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join(".nopass").join("agent.sock")
}

#[tauri::command]
fn ssh_agent_load_vault_keys(
    keys: Vec<commands::SshKeyPayload>,
    state: tauri::State<'_, AgentState>,
) -> Result<usize, String> {
    let mut store = state.0.lock().map_err(|e| e.to_string())?;
    store.clear();

    for payload in keys {
        if let Some(key) = ssh_agent::load_key(
            &payload.private_key,
            payload.passphrase.as_deref(),
            payload.comment.as_deref(),
        ) {
            store.push(key);
        }
    }

    eprintln!("[nopass-agent] loaded {} key(s) from vault", store.len());
    Ok(store.len())
}

#[tauri::command]
fn ssh_agent_clear_vault_keys(state: tauri::State<'_, AgentState>) -> Result<(), String> {
    let mut store = state.0.lock().map_err(|e| e.to_string())?;
    store.clear();
    eprintln!("[nopass-agent] keys cleared (vault locked)");
    Ok(())
}

#[tauri::command]
fn ssh_agent_socket_path() -> String {
    agent_socket_path().to_string_lossy().to_string()
}

/// Returns the shell snippet the user should add to their shell config.
#[tauri::command]
fn ssh_agent_shell_config() -> String {
    let path = agent_socket_path();
    format!(
        "# nopass SSH agent\nexport SSH_AUTH_SOCK=\"{}\"\n\n\
         # To avoid 'Too many authentication failures', add per-host config to ~/.ssh/config:\n\
         # Host example.com\n\
         #   IdentitiesOnly yes\n\
         #   IdentityFile ~/.ssh/<keyname>.pub  # use 'ssh config' button per key",
        path.to_string_lossy()
    )
}

pub fn run() {
    let shared_keys: SharedKeys = Arc::new(Mutex::new(vec![]));
    let agent_keys = shared_keys.clone();

    // Start the SSH agent socket in a background task.
    tauri::async_runtime::spawn(async move {
        let socket_path = agent_socket_path();
        ssh_agent::start(&socket_path, agent_keys).await;
    });

    tauri::Builder::default()
        .manage(AgentState(shared_keys))
        .plugin(tauri_plugin_sql::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            commands::keychain_save,
            commands::keychain_load,
            commands::keychain_delete,
            commands::touch_id_available,
            commands::touch_id_authenticate,
            commands::ssh_agent_add,
            commands::ssh_agent_remove,
            commands::ssh_agent_list,
            commands::ssh_write_key_file,
            commands::ssh_delete_key_file,
            ssh_agent_load_vault_keys,
            ssh_agent_clear_vault_keys,
            ssh_agent_socket_path,
            ssh_agent_shell_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running nopass");
}
