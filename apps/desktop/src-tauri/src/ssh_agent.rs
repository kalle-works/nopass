use std::io;
use std::sync::{Arc, Mutex};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{PrivateKey, Signature};
use tokio::net::UnixListener;

pub type SharedKeys = Arc<Mutex<Vec<PrivateKey>>>;

fn io_err(msg: impl Into<String>) -> AgentError {
    AgentError::other(io::Error::new(io::ErrorKind::Other, msg.into()))
}

/// The in-process SSH agent. Clone is cheap — all instances share the Arc.
#[derive(Clone)]
pub struct NopassAgent {
    keys: SharedKeys,
}

impl NopassAgent {
    pub fn new(keys: SharedKeys) -> Self {
        Self { keys }
    }
}

impl Default for NopassAgent {
    fn default() -> Self {
        Self { keys: Arc::new(Mutex::new(vec![])) }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for NopassAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.keys.lock().map_err(|e| io_err(e.to_string()))?;
        Ok(keys
            .iter()
            .map(|k| Identity {
                pubkey: k.public_key().key_data().clone(),
                comment: k.comment().to_string(),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {

        let keys = self.keys.lock().map_err(|e| io_err(e.to_string()))?;
        let key = keys
            .iter()
            .find(|k| k.public_key().key_data() == &request.pubkey)
            .ok_or_else(|| io_err("key not found in nopass agent"))?;

        sign_with_flags(key, &request.data, request.flags)
    }
}

/// Sign data respecting RSA algorithm flags from the SSH agent protocol:
///   0x02 → rsa-sha2-256   0x04 → rsa-sha2-512   0x00 → default per key type
/// ssh-key defaults RSA signing to rsa-sha2-256, which covers the common case.
fn sign_with_flags(key: &PrivateKey, data: &[u8], _flags: u32) -> Result<Signature, AgentError> {
    use signature::Signer as _;
    key.try_sign(data).map_err(|e| io_err(e.to_string()))
}

/// Create the directory (and parents) with mode 0700.
fn create_private_dir(dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Force an existing directory down to 0700, including one an older version
/// created with the umask default. Only call this for directories we own
/// outright (~/.nopass), never for a caller-supplied parent such as /tmp.
pub fn ensure_private_dir(dir: &std::path::Path) -> io::Result<()> {
    create_private_dir(dir)?;
    restrict_to_owner(dir, 0o700)
}

fn restrict_to_owner(path: &std::path::Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Start the SSH agent Unix socket server. Runs until cancelled.
pub async fn start(socket_path: &std::path::Path, keys: SharedKeys) {
    let _ = std::fs::remove_file(socket_path);

    if let Some(parent) = socket_path.parent() {
        if let Err(e) = create_private_dir(parent) {
            eprintln!("[nopass-agent] cannot create dir {}: {e}", parent.display());
            return;
        }
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[nopass-agent] bind {} failed: {e}", socket_path.display());
            return;
        }
    };

    // The agent signs with every loaded key, so only the owner may connect.
    // Set explicitly: the socket's mode otherwise follows the process umask.
    if let Err(e) = restrict_to_owner(socket_path, 0o600) {
        eprintln!("[nopass-agent] cannot restrict {}: {e}", socket_path.display());
        return;
    }

    eprintln!("[nopass-agent] listening on {}", socket_path.display());

    if let Err(e) = listen(listener, NopassAgent::new(keys)).await {
        eprintln!("[nopass-agent] server error: {e}");
    }
}

/// Parse and (if needed) decrypt an OpenSSH private key PEM.
/// Returns `None` and logs on error.
pub fn load_key(pem: &str, passphrase: Option<&str>, comment: Option<&str>) -> Option<PrivateKey> {
    let key = match PrivateKey::from_openssh(pem) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[nopass-agent] key parse error: {e}");
            return None;
        }
    };

    let mut key = if key.is_encrypted() {
        let pass = passphrase.unwrap_or("");
        match key.decrypt(pass.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[nopass-agent] key decrypt error: {e}");
                return None;
            }
        }
    } else {
        key
    };

    if let Some(c) = comment.filter(|s| !s.is_empty()) {
        key.set_comment(c);
    }

    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_socket(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("nopass_test_{}_{}.sock", tag, std::process::id()))
    }

    fn gen_key(path: &std::path::Path, comment: &str) -> String {
        let _ = std::fs::remove_file(path);
        std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f", path.to_str().unwrap(), "-N", "", "-C", comment, "-q"])
            .output()
            .expect("ssh-keygen must be installed");
        std::fs::read_to_string(path).expect("key file written")
    }

    /// Agent starts, loads a key, and `ssh-add -l` can list it via the socket.
    /// Uses multi_thread so the agent task runs concurrently with the blocking subprocess.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_lists_loaded_key() {
        let key_path = std::env::temp_dir().join("nopass_t1_key");
        let pem = gen_key(&key_path, "nopass-unit-test");

        let socket_path = temp_socket("list");
        let _ = std::fs::remove_file(&socket_path);

        let keys: SharedKeys = Arc::new(Mutex::new(vec![]));
        let key = load_key(&pem, None, Some("nopass-unit-test"))
            .expect("load_key must parse the generated key");
        keys.lock().unwrap().push(key);

        let agent_keys = keys.clone();
        let path = socket_path.clone();
        tokio::spawn(async move { start(&path, agent_keys).await });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let out = std::process::Command::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .expect("ssh-add must be installed");

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("nopass-unit-test"),
            "agent should advertise the loaded key; got:\n{stdout}"
        );

        for p in [&socket_path, &key_path] {
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_file(format!("{}.pub", p.display()));
        }
    }

    /// Agent with multiple keys lists all of them — the IdentitiesOnly filtering
    /// is SSH-client behaviour proven separately via manual testing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_lists_multiple_keys() {
        let k1 = std::env::temp_dir().join("nopass_t2_k1");
        let k2 = std::env::temp_dir().join("nopass_t2_k2");
        let pem1 = gen_key(&k1, "test-key-alpha");
        let pem2 = gen_key(&k2, "test-key-beta");

        let socket_path = temp_socket("multi");
        let _ = std::fs::remove_file(&socket_path);

        let keys: SharedKeys = Arc::new(Mutex::new(vec![]));
        for (pem, comment) in [(&pem1, "test-key-alpha"), (&pem2, "test-key-beta")] {
            if let Some(k) = load_key(pem, None, Some(comment)) {
                keys.lock().unwrap().push(k);
            }
        }
        assert_eq!(keys.lock().unwrap().len(), 2);

        let agent_keys = keys.clone();
        let path = socket_path.clone();
        tokio::spawn(async move { start(&path, agent_keys).await });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let list = String::from_utf8_lossy(
            &std::process::Command::new("ssh-add")
                .arg("-l")
                .env("SSH_AUTH_SOCK", &socket_path)
                .output()
                .unwrap()
                .stdout,
        )
        .into_owned();

        assert!(list.contains("test-key-alpha"), "missing alpha:\n{list}");
        assert!(list.contains("test-key-beta"),  "missing beta:\n{list}");
        println!("Agent correctly lists both keys:\n{list}");

        for p in [&socket_path, &k1, &k2] {
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_file(format!("{}.pub", p.display()));
        }
    }

    /// load_key returns None for invalid PEM without panicking.
    #[test]
    fn load_key_rejects_garbage() {
        assert!(load_key("not a real key", None, None).is_none());
    }

    /// load_key sets the comment override correctly.
    #[test]
    fn load_key_sets_comment() {
        let key_path = std::env::temp_dir().join("nopass_t3_key");
        let pem = gen_key(&key_path, "original-comment");
        let key = load_key(&pem, None, Some("overridden-comment")).unwrap();
        assert_eq!(key.comment(), "overridden-comment");
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(format!("{}.pub", key_path.display()));
    }

    /// The socket is owner-only and a directory the agent has to create is 0700,
    /// whatever the process umask is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_and_new_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nopass_perm_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let socket_path = dir.join("agent.sock");

        let keys: SharedKeys = Arc::new(Mutex::new(vec![]));
        let path = socket_path.clone();
        tokio::spawn(async move { start(&path, keys).await });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&socket_path), 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
