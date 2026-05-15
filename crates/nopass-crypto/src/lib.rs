pub mod aes_gcm;
pub mod error;
pub mod kdf;
pub mod srp;

pub use error::CryptoError;
pub use kdf::{derive_master_key, stretch_master_key, Argon2Params, StretchedKeys};
pub use aes_gcm::{decrypt, encrypt, EncryptedData};
