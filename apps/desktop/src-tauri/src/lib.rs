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
        ])
        .run(tauri::generate_context!())
        .expect("error while running nopass");
}
