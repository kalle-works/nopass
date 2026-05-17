mod commands;

pub fn run() {
    tauri::Builder::default()
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running nopass");
}
