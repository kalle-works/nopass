//! The JSON these types produce is a contract with the TypeScript clients and
//! with rows already stored in production. Both sides of the Rust API tests use
//! these same structs, so a renamed field would pass them and break every client.

use nopass_models::{KdfParams, SyncEventType, VaultItemType};
use serde_json::json;

#[test]
fn kdf_params_use_the_field_names_and_defaults_clients_send() {
    assert_eq!(
        serde_json::to_value(KdfParams::default()).unwrap(),
        json!({ "type": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 4 })
    );
}

#[test]
fn enum_variants_keep_their_stored_names() {
    assert_eq!(serde_json::to_value(VaultItemType::SshKey).unwrap(), json!("ssh_key"));
    assert_eq!(serde_json::to_value(VaultItemType::Login).unwrap(), json!("login"));
    assert_eq!(serde_json::to_value(SyncEventType::Upsert).unwrap(), json!("upsert"));
    assert_eq!(serde_json::to_value(SyncEventType::Delete).unwrap(), json!("delete"));
}
