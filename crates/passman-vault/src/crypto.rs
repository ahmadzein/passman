use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use passman_types::{EncryptedBlob, KdfParams};
use rand::RngCore;
use zeroize::Zeroize;

use crate::VaultError;

/// Derive a 256-bit encryption key from a master password using Argon2id.
pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; 32], VaultError> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
            .map_err(|e| VaultError::Crypto(format!("invalid KDF params: {e}")))?,
    );

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Crypto(format!("key derivation failed: {e}")))?;

    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM using a unique random nonce.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedBlob, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("cipher init failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Crypto(format!("encryption failed: {e}")))?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt an AES-256-GCM encrypted blob.
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Crypto(format!("cipher init failed: {e}")))?;

    let nonce = Nonce::from_slice(&blob.nonce);

    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| VaultError::Crypto(format!("decryption failed: {e}")))
}

/// Generate a random 32-byte salt.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// A wrapper that holds the derived key and zeroizes it on drop.
pub struct DerivedKey {
    key: [u8; 32],
}

impl DerivedKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob, VaultError> {
        encrypt(&self.key, plaintext)
    }

    pub fn decrypt(&self, blob: &EncryptedBlob) -> Result<Vec<u8>, VaultError> {
        decrypt(&self.key, blob)
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Known plaintext used to verify the master password on unlock.
const VERIFICATION_PLAINTEXT: &[u8] = b"passman-vault-verification-v1";

/// Create a verification blob that can later be used to check the master password.
pub fn create_verification(key: &[u8; 32]) -> Result<EncryptedBlob, VaultError> {
    encrypt(key, VERIFICATION_PLAINTEXT)
}

/// Verify a master password by attempting to decrypt the verification blob.
pub fn verify_password(key: &[u8; 32], blob: &EncryptedBlob) -> Result<bool, VaultError> {
    match decrypt(key, blob) {
        Ok(plaintext) => Ok(plaintext == VERIFICATION_PLAINTEXT),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello, world!";
        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let blob = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_unique_nonces() {
        let key = [42u8; 32];
        let b1 = encrypt(&key, b"data").unwrap();
        let b2 = encrypt(&key, b"data").unwrap();
        assert_ne!(b1.nonce, b2.nonce);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0u8; 32];
        let params = KdfParams {
            memory_kib: 1024, // small for testing
            iterations: 1,
            parallelism: 1,
        };
        let k1 = derive_key("password", &salt, &params).unwrap();
        let k2 = derive_key("password", &salt, &params).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0u8; 32];
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let k1 = derive_key("password1", &salt, &params).unwrap();
        let k2 = derive_key("password2", &salt, &params).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_verification_roundtrip() {
        let key = [42u8; 32];
        let blob = create_verification(&key).unwrap();
        assert!(verify_password(&key, &blob).unwrap());
    }

    #[test]
    fn test_verification_wrong_password() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let blob = create_verification(&key1).unwrap();
        assert!(!verify_password(&key2, &blob).unwrap());
    }

    #[test]
    fn test_derived_key_zeroize_on_drop() {
        let key = DerivedKey::new([42u8; 32]);
        assert_eq!(key.as_bytes(), &[42u8; 32]);
        // key is zeroized when dropped
    }
}
