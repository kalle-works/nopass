use keyring::Entry;

// ─── Keychain ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn keychain_save(service: &str, account: &str, password: &str) -> Result<(), String> {
    Entry::new(service, account)
        .map_err(|e| e.to_string())?
        .set_password(password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn keychain_load(service: &str, account: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(service, account).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(pw) => Ok(Some(pw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn keychain_delete(service: &str, account: &str) -> Result<(), String> {
    let entry = Entry::new(service, account).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// ─── Biometric availability ───────────────────────────────────────────────────
// Full Touch ID integration via LocalAuthentication is planned for v2.
// The Keychain still provides fast re-unlock (no Argon2id re-run) in v1.

#[tauri::command]
pub fn touch_id_available() -> bool {
    false
}

#[tauri::command]
pub async fn touch_id_authenticate(_reason: String) -> Result<bool, String> {
    Ok(false)
}
