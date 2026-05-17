use keyring::Entry;
use serde::Deserialize;
use std::io::Write;
use std::process::{Command, Stdio};

/// Payload for loading SSH keys into the in-process agent.
#[derive(Deserialize)]
pub struct SshKeyPayload {
    pub private_key: String,
    pub passphrase: Option<String>,
    pub comment: Option<String>,
}

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

// ─── SSH agent ────────────────────────────────────────────────────────────────

/// Add a private key to the running ssh-agent.
/// On macOS, passes --apple-use-keychain so the passphrase is stored in Keychain
/// and the key survives a reboot without re-adding.
#[tauri::command]
pub fn ssh_agent_add(private_key: String, passphrase: Option<String>) -> Result<String, String> {
    // Write key to a temp file with 0600 permissions
    let tmp_path = write_tmp_key(&private_key)?;

    let result = (|| {
        let mut args: Vec<&str> = Vec::new();
        #[cfg(target_os = "macos")]
        args.push("--apple-use-keychain");

        // If passphrase provided, set SSH_ASKPASS to echo it
        let mut cmd = Command::new("ssh-add");
        cmd.args(&args).arg(&tmp_path).stderr(Stdio::piped()).stdout(Stdio::piped());

        if let Some(ref pass) = passphrase {
            // Use SSH_ASKPASS with a helper script to supply the passphrase
            let askpass_script = write_askpass_script(pass)?;
            cmd.env("SSH_ASKPASS", &askpass_script)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .stdin(Stdio::null());
            let output = cmd.output().map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&askpass_script);
            if output.status.success() {
                Ok("Key added to ssh-agent".to_string())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).into_owned())
            }
        } else {
            let output = cmd.output().map_err(|e| e.to_string())?;
            if output.status.success() {
                Ok("Key added to ssh-agent".to_string())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).into_owned())
            }
        }
    })();

    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// Remove a key from the running ssh-agent using the public key fingerprint.
#[tauri::command]
pub fn ssh_agent_remove(public_key: String) -> Result<String, String> {
    let tmp_path = {
        let path = std::env::temp_dir().join(format!("nopass_pub_{}.pub", uuid_str()));
        std::fs::write(&path, public_key.as_bytes()).map_err(|e| e.to_string())?;
        path
    };

    let output = Command::new("ssh-add")
        .arg("-d")
        .arg(&tmp_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;

    let _ = std::fs::remove_file(&tmp_path);

    if output.status.success() {
        Ok("Key removed from ssh-agent".to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// List keys currently loaded in the ssh-agent.
#[tauri::command]
pub fn ssh_agent_list() -> Result<String, String> {
    let output = Command::new("ssh-add")
        .arg("-l")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;

    // Exit code 1 means no identities — treat as empty list, not error
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() || stdout.contains("no identities") {
        Ok(stdout)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

/// Write a private key to ~/.ssh/<filename> with 0600 permissions.
/// Returns the absolute path written.
#[tauri::command]
pub fn ssh_write_key_file(filename: String, private_key: String, public_key: Option<String>) -> Result<String, String> {
    let ssh_dir = dirs_path()?;
    std::fs::create_dir_all(&ssh_dir).map_err(|e| e.to_string())?;

    let key_path = ssh_dir.join(&filename);
    write_key_with_permissions(&key_path, private_key.as_bytes())?;

    if let Some(pub_key) = public_key {
        let pub_path = ssh_dir.join(format!("{}.pub", filename));
        std::fs::write(&pub_path, pub_key.as_bytes()).map_err(|e| e.to_string())?;
    }

    Ok(key_path.to_string_lossy().into_owned())
}

/// Delete a key pair from ~/.ssh/.
#[tauri::command]
pub fn ssh_delete_key_file(filename: String) -> Result<(), String> {
    let ssh_dir = dirs_path()?;
    let key_path = ssh_dir.join(&filename);
    let pub_path = ssh_dir.join(format!("{}.pub", filename));

    if key_path.exists() {
        std::fs::remove_file(&key_path).map_err(|e| e.to_string())?;
    }
    if pub_path.exists() {
        let _ = std::fs::remove_file(&pub_path);
    }
    Ok(())
}

fn dirs_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(std::path::PathBuf::from(home).join(".ssh"))
}

fn uuid_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    format!("{:016x}", nanos ^ (pid.wrapping_shl(32)))
}

fn write_tmp_key(private_key: &str) -> Result<std::path::PathBuf, String> {
    let path = std::env::temp_dir().join(format!("nopass_key_{}", uuid_str()));
    write_key_with_permissions(&path, private_key.as_bytes())?;
    Ok(path)
}

#[cfg(unix)]
fn write_key_with_permissions(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(data).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn write_key_with_permissions(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| e.to_string())
}

fn write_askpass_script(passphrase: &str) -> Result<std::path::PathBuf, String> {
    let path = std::env::temp_dir().join(format!("nopass_askpass_{}.sh", uuid_str()));
    let script = format!("#!/bin/sh\necho '{}'\n", passphrase.replace('\'', "'\\''"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(&path)
            .map_err(|e| e.to_string())?;
        file.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, script.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
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
