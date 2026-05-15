use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

#[derive(Debug, Clone)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // OWASP 2024 recommended Argon2id settings
        Self {
            memory_kib: 65536, // 64 MB
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Key material derived from the master password — zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StretchedKeys {
    /// Used to encrypt/decrypt the ProtectedSymmetricKey stored on server
    pub stretched_master_key: [u8; 32],
    /// AES-256-GCM key for vault item encryption
    pub vault_enc_key: [u8; 32],
    /// HMAC-SHA256 key for vault item MAC
    pub vault_mac_key: [u8; 32],
}

/// Derive the 32-byte master key from the master password using Argon2id.
///
/// The salt is deterministic so the same key is derived on any device:
///   salt = SHA-256("nopass-v1-kdf:" || lowercase(email))
/// This means the user can recover their key on a new device from password alone.
pub fn derive_master_key(
    password: &[u8],
    email: &str,
    params: &Argon2Params,
) -> Result<[u8; 32], CryptoError> {
    use sha2::Digest;

    let salt_input = format!("nopass-v1-kdf:{}", email.to_lowercase());
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut master_key = [0u8; 32];
    argon2
        .hash_password_into(password, &salt, &mut master_key)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    Ok(master_key)
}

/// Expand the 32-byte master key into three 32-byte subkeys via HKDF-SHA256.
pub fn stretch_master_key(
    master_key: &[u8; 32],
    email: &str,
) -> Result<StretchedKeys, CryptoError> {
    let ikm = master_key;
    let salt = email.to_lowercase();

    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm);

    let mut stretched_master_key = [0u8; 32];
    let mut vault_enc_key = [0u8; 32];
    let mut vault_mac_key = [0u8; 32];

    hk.expand(b"nopass-v1-smk", &mut stretched_master_key)
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for stretched_master_key".into()))?;

    hk.expand(b"nopass-v1-enc", &mut vault_enc_key)
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for vault_enc_key".into()))?;

    hk.expand(b"nopass-v1-mac", &mut vault_mac_key)
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for vault_mac_key".into()))?;

    Ok(StretchedKeys {
        stretched_master_key,
        vault_enc_key,
        vault_mac_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_master_key_is_deterministic() {
        let params = Argon2Params {
            memory_kib: 4096, // reduced for test speed
            iterations: 1,
            parallelism: 1,
        };
        let key1 = derive_master_key(b"correct horse battery staple", "user@example.com", &params)
            .unwrap();
        let key2 = derive_master_key(b"correct horse battery staple", "user@example.com", &params)
            .unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_master_key_differs_by_password() {
        let params = Argon2Params {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let key1 = derive_master_key(b"password1", "user@example.com", &params).unwrap();
        let key2 = derive_master_key(b"password2", "user@example.com", &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_master_key_differs_by_email() {
        let params = Argon2Params {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let key1 = derive_master_key(b"password", "alice@example.com", &params).unwrap();
        let key2 = derive_master_key(b"password", "bob@example.com", &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn email_case_insensitive_for_kdf() {
        let params = Argon2Params {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        };
        let key1 = derive_master_key(b"password", "User@Example.COM", &params).unwrap();
        let key2 = derive_master_key(b"password", "user@example.com", &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn stretch_produces_distinct_subkeys() {
        let master_key = [0x42u8; 32];
        let keys = stretch_master_key(&master_key, "user@example.com").unwrap();
        assert_ne!(keys.stretched_master_key, keys.vault_enc_key);
        assert_ne!(keys.vault_enc_key, keys.vault_mac_key);
        assert_ne!(keys.stretched_master_key, keys.vault_mac_key);
    }

    #[test]
    fn stretch_is_deterministic() {
        let master_key = [0x42u8; 32];
        let keys1 = stretch_master_key(&master_key, "user@example.com").unwrap();
        let keys2 = stretch_master_key(&master_key, "user@example.com").unwrap();
        assert_eq!(keys1.vault_enc_key, keys2.vault_enc_key);
    }

    /// Cross-platform parity test — must match packages/crypto cross-platform-parity.test.ts.
    /// password  : "correct horse battery staple"
    /// email     : "alice@example.com"
    /// memory_kib: 4096, iterations: 1, parallelism: 1
    #[test]
    fn cross_platform_parity() {
        let params = Argon2Params { memory_kib: 4096, iterations: 1, parallelism: 1 };

        let master_key = derive_master_key(
            b"correct horse battery staple",
            "alice@example.com",
            &params,
        ).unwrap();

        let expected_master = hex::decode(
            "5586138d4e49edaee8036d44fd531c31c5af69198dd2670e821d002262a795f1",
        ).unwrap();
        assert_eq!(master_key.as_slice(), expected_master.as_slice(), "masterKey mismatch vs TS");

        let keys = stretch_master_key(&master_key, "alice@example.com").unwrap();

        let expected_enc = hex::decode(
            "aae88de470c73778fcb96f189fa1bf80f869ae9aaff25117355c3e015843ca3c",
        ).unwrap();
        let expected_mac = hex::decode(
            "d35595df72fd49310849020d96bc031443952a689f13004b2fdee9d4b2e7a867",
        ).unwrap();

        assert_eq!(keys.vault_enc_key.as_slice(), expected_enc.as_slice(), "vaultEncKey mismatch vs TS");
        assert_eq!(keys.vault_mac_key.as_slice(), expected_mac.as_slice(), "vaultMacKey mismatch vs TS");
    }
}
