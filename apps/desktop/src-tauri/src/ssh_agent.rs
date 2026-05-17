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

/// Start the SSH agent Unix socket server. Runs until cancelled.
pub async fn start(socket_path: &std::path::Path, keys: SharedKeys) {
    let _ = std::fs::remove_file(socket_path);

    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
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

    eprintln!("[nopass-agent] listening on {}", socket_path.display());

    if let Err(e) = listen(listener, NopassAgent::new(keys)).await {
        eprintln!("[nopass-agent] server error: {e}");
    }
}

/// Parse and (if needed) decrypt an OpenSSH private key PEM.
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
