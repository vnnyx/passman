use passman::crypto::{decrypt, derive_key, encrypt};

#[test]
fn deterministic_kdf_same_salt() {
    let password = b"test-password";
    let salt = [1u8; 16];
    let key1 = derive_key(password, &salt).unwrap();
    let key2 = derive_key(password, &salt).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn different_salts_produce_different_keys() {
    let password = b"test-password";
    let salt1 = [1u8; 16];
    let salt2 = [2u8; 16];
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
