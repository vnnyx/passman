use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::PassmanError;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], PassmanError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|e| PassmanError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| PassmanError::Crypto(e.to_string()))?;
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    salt
}

pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, PassmanError> {
    let salt = generate_salt();
    let mut key = derive_key(password, &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| PassmanError::Crypto(e.to_string()))?;
    key.zeroize();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PassmanError::Crypto("encryption failed".into()))?;

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, PassmanError> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err(PassmanError::InvalidPassword);
    }

    let salt: [u8; SALT_LEN] = data[..SALT_LEN]
        .try_into()
        .map_err(|_| PassmanError::InvalidPassword)?;
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| PassmanError::Crypto(e.to_string()))?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PassmanError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_kdf_same_salt() {
        let password = b"test-password";
        let salt = [1u8; SALT_LEN];
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let password = b"test-password";
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world";
        let password = b"strong-password";
        let encrypted = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, b"correct").unwrap();
        let result = decrypt(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let result = decrypt(&[0u8; 10], b"password");
        assert!(result.is_err());
    }

    #[test]
    fn two_encryptions_produce_different_ciphertext() {
        let plaintext = b"same data";
        let password = b"password";
        let enc1 = encrypt(plaintext, password).unwrap();
        let enc2 = encrypt(plaintext, password).unwrap();
        assert_ne!(enc1, enc2);
    }
}
