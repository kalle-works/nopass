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

/// Every keychain entry belongs to this service. It is not a command
/// parameter: a compromised webview must not be able to read or overwrite
/// entries of other apps (or other services) through our commands.
const KEYCHAIN_SERVICE: &str = "app.nopass.desktop";

fn keychain_entry(account: &str) -> Result<Entry, String> {
    let valid = !account.is_empty()
        && account.len() <= 64
        && account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid {
        return Err("invalid keychain account".to_string());
    }
    Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn keychain_save(account: &str, password: &str) -> Result<(), String> {
    keychain_entry(account)?
        .set_password(password)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn keychain_load(account: &str) -> Result<Option<String>, String> {
    match keychain_entry(account)?.get_password() {
        Ok(pw) => Ok(Some(pw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub fn keychain_delete(account: &str) -> Result<(), String> {
    match keychain_entry(account)?.delete_credential() {
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
    validate_key_filename(&filename)?;
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
    validate_key_filename(&filename)?;
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

/// Key files live directly in ~/.ssh under a plain name. Rejecting separators,
/// leading dots and the files ssh itself reads keeps these commands from being
/// used to overwrite authorized_keys, config, or anything outside ~/.ssh.
fn validate_key_filename(filename: &str) -> Result<(), String> {
    const RESERVED: [&str; 5] = ["authorized_keys", "config", "known_hosts", "environment", "rc"];
    let valid = !filename.is_empty()
        && filename.len() <= 128
        && !filename.starts_with('.')
        && !filename.ends_with(".pub")
        && !RESERVED.contains(&filename)
        && filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if valid {
        Ok(())
    } else {
        Err("invalid key file name".to_string())
    }
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

// ─── Biometric (Touch ID via LocalAuthentication) ────────────────────────────
// The vault keys live in the login Keychain; Touch ID gates the load in-app.
// evaluatePolicy presents its own system prompt and replies on a private
// queue, so the whole interaction runs on a blocking thread.

#[cfg(target_os = "macos")]
pub(crate) fn touch_id_available_blocking() -> bool {
    use objc2_local_authentication::{LAContext, LAPolicy};
    unsafe {
        LAContext::new()
            .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
            .is_ok()
    }
}

// LAContext is not documented thread-safe, so both commands take the same
// path: a fresh context used start-to-finish on one blocking thread.
#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn touch_id_available() -> bool {
    tauri::async_runtime::spawn_blocking(touch_id_available_blocking)
        .await
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn touch_id_authenticate(reason: String) -> Result<bool, String> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::mpsc;
    use std::time::Duration;

    tauri::async_runtime::spawn_blocking(move || {
        let (tx, rx) = mpsc::channel::<bool>();
        unsafe {
            let ctx = LAContext::new();
            let ns_reason = NSString::from_str(&reason);
            let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
                let _ = tx.send(success.as_bool());
            });
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &ns_reason,
                &reply,
            );
            // The context must outlive the system prompt; recv blocks until
            // the user confirms, cancels, or the prompt times out. ns_reason
            // is ARC-retained (Retained<NSString>), safe for the OS queue.
            let ok = rx.recv_timeout(Duration::from_secs(120)).unwrap_or(false);
            // Dismiss the prompt if our timeout won the race — otherwise a
            // zombie dialog outlives the command that already returned false
            ctx.invalidate();
            drop(ctx);
            Ok(ok)
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub fn touch_id_available() -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub async fn touch_id_authenticate(_reason: String) -> Result<bool, String> {
    Ok(false)
}

#[cfg(all(test, target_os = "macos"))]
mod biometric_tests {
    /// canEvaluatePolicy never shows a prompt — this exercises the real
    /// LocalAuthentication call. The value depends on the host hardware,
    /// so only the call itself is asserted (no panic / no ObjC exception).
    #[test]
    fn touch_id_availability_probe() {
        let available = super::touch_id_available_blocking();
        println!("touch_id_available: {available}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_filename_rejects_paths_and_ssh_control_files() {
        for bad in ["", "../x", "a/b", ".hidden", "authorized_keys", "config", "id.pub", "a b", "..", "x\0"] {
            assert!(validate_key_filename(bad).is_err(), "{bad:?} must be rejected");
        }
        for good in ["id_ed25519", "work-key_2", "deploy.key"] {
            assert!(validate_key_filename(good).is_ok(), "{good:?} must be accepted");
        }
    }

    #[test]
    fn keychain_account_rejects_foreign_shapes() {
        for bad in ["", "a/b", "a b", &"x".repeat(65), "acct\n"] {
            assert!(keychain_entry(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(keychain_entry("device-enc-key").is_ok());
    }
}
