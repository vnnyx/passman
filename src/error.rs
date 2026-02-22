use thiserror::Error;

#[derive(Debug, Error)]
pub enum PassmanError {
    #[error("Invalid master password.")]
    InvalidPassword,

    #[error("Vault already exists at {0}")]
    VaultAlreadyExists(String),

    #[error("Vault not found. Run `pm init` first.")]
    VaultNotFound,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error("Clipboard error: {0}")]
    Clipboard(String),
}
