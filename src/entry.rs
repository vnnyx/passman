use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Drop for VaultData {
    fn drop(&mut self) {
        self.entries.clear();
    }
}
