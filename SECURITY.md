# Security Model

## Threat Model

Passman protects passwords at rest on a local filesystem. It is designed to defend against:

- **Offline vault theft**: An attacker who obtains the `vault.enc` file cannot recover passwords without the master password.
- **Brute-force attacks**: Argon2id with high memory/time parameters makes brute-forcing the master password computationally expensive.
- **Tampered vault files**: AES-256-GCM authenticated encryption detects any modification to the ciphertext.

It does **not** defend against:
- Malware with memory access on the running system
- Keyloggers capturing the master password
- Physical access to an unlocked session

## Cryptographic Choices

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| KDF | Argon2id | m=64MB, t=3, p=4, 16-byte salt |
| Encryption | AES-256-GCM | 12-byte nonce, 32-byte key |
| Random | ChaCha20 (via `rand` crate) | OS-seeded CSPRNG |

- **Fresh salt and nonce** generated for every encryption operation, ensuring identical plaintext produces different ciphertext.
- **GCM authentication tag** provides integrity — any tampering is detected and returns a generic "Invalid master password" error (no information leakage about the nature of the failure).

## Zeroize Guarantees

Sensitive data is zeroized (overwritten with zeros) after use:

| Data | Location | Mechanism |
|------|----------|-----------|
| Master password (`String`) | `cli.rs` every handler | `.zeroize()` before return, including error paths |
| Derived key (`[u8; 32]`) | `crypto.rs` encrypt/decrypt | `.zeroize()` after cipher construction |
| Decrypted JSON (`Vec<u8>`) | `vault.rs` load | `.zeroize()` after deserialization |
| Serialized JSON (`Vec<u8>`) | `vault.rs` save | `.zeroize()` after encryption |
| Entry fields (password, etc.) | `entry.rs` | `#[zeroize(drop)]` on `Entry` struct |

### Limitations

- The Rust compiler or OS may copy memory (stack frames, page swaps) before zeroize runs. `zeroize` prevents optimizing away the zeroing, but cannot prevent all copies.
- Clipboard contents are cleared after 10 seconds, but another application may have read them in that window.
- The `VaultData` struct implements `Drop` to clear entries, but `Vec` reallocation may leave copies in freed memory.

## Vault File Format

```
[16 bytes salt][12 bytes nonce][AES-256-GCM ciphertext + 16 bytes auth tag]
```

The plaintext inside the ciphertext is a JSON-serialized `VaultData` structure.

## Password Generation

- Uses `rand::rng()` backed by the OS CSPRNG (ChaCha20)
- Guarantees at least one character from each enabled character set
- Fisher-Yates shuffle ensures uniform distribution
- Default length: 20 characters, configurable 8-128
