# Passman

A secure CLI password manager built in Rust. Passwords are encrypted locally using AES-256-GCM with Argon2id key derivation — nothing leaves your machine.

## Features

- **Encrypted vault** — All entries stored in a single AES-256-GCM encrypted file at `~/.passman/vault.enc`
- **Strong key derivation** — Argon2id with 64MB memory cost makes brute-force attacks impractical
- **Password generator** — Cryptographically secure random passwords with configurable length and character sets
- **Clipboard integration** — Copy passwords to clipboard with automatic 10-second clearing
- **Case-insensitive search** — Look up entries without worrying about capitalization
- **Zeroized memory** — Master password, derived keys, and decrypted data are wiped from memory after use

## Installation

```
cargo install --path .
```

## Usage

### Initialize a new vault

```
pm init
```

### Add an entry

```
pm add GitHub --username user@example.com --url https://github.com
pm add AWS --username admin --generate    # auto-generate password
```

### Retrieve an entry

```
pm get GitHub
```

Displays name, username, URL, and notes. Prompts to copy the password to clipboard.

### List all entries

```
pm list
```

Shows a table of all entries (names, usernames, URLs, last updated) — passwords are never displayed.

### Delete an entry

```
pm delete GitHub
```

### Generate a password

```
pm generate
pm generate --length 32
pm generate --no-symbols --no-numbers
```

Standalone command — no vault or master password required.

### Change master password

```
pm change-master
```

Re-encrypts the entire vault with a new password.

## Security

See [SECURITY.md](SECURITY.md) for the full threat model, cryptographic choices, and zeroize guarantees.
