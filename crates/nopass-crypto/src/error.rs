use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed — ciphertext tampered or wrong key")]
    Decrypt,

    #[error("MAC verification failed")]
    MacMismatch,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("SRP error: {0}")]
    Srp(String),
}
