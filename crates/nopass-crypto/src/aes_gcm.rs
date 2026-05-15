use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroize;

use crate::CryptoError;

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    /// 12-byte nonce
    pub iv: [u8; 12],
}

/// Encrypt plaintext with AES-256-GCM. Generates a random 12-byte nonce.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;

    let mut iv = [0u8; 12];
    iv.copy_from_slice(&nonce);

    Ok(EncryptedData { ciphertext, iv })
}

/// Decrypt AES-256-GCM ciphertext. Returns error if MAC verification fails.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], iv: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;

    // Caller is responsible for zeroizing the returned plaintext after use.
    // We provide a convenience note but cannot enforce it from here.
    let result = plaintext.clone();
    plaintext.zeroize();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"super secret password";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted.ciphertext, &encrypted.iv).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_ivs_each_encrypt() {
        let key = [0x42u8; 32];
        let plaintext = b"same plaintext";

        let e1 = encrypt(&key, plaintext).unwrap();
        let e2 = encrypt(&key, plaintext).unwrap();

        // IVs should be different (random nonce)
        assert_ne!(e1.iv, e2.iv);
        // Ciphertexts should be different
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"secret";

        let encrypted = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &encrypted.ciphertext, &encrypted.iv);

        assert!(matches!(result, Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"secret";

        let mut encrypted = encrypt(&key, plaintext).unwrap();
        encrypted.ciphertext[0] ^= 0xff; // flip bits

        let result = decrypt(&key, &encrypted.ciphertext, &encrypted.iv);
        assert!(matches!(result, Err(CryptoError::Decrypt)));
    }
}
