use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto;
use crate::entry::{Entry, VaultData};
use crate::error::PassmanError;

pub fn vault_path() -> PathBuf {
    if let Ok(path) = std::env::var("PASSMAN_VAULT_PATH") {
        return PathBuf::from(path);
    }
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".passman");
    path.push("vault.enc");
    path
}

pub fn init(password: &[u8]) -> Result<(), PassmanError> {
    init_at(password, &vault_path())
}

pub fn init_at(password: &[u8], path: &Path) -> Result<(), PassmanError> {
    if path.exists() {
        return Err(PassmanError::VaultAlreadyExists(
            path.display().to_string(),
        ));
    }
    let vault = VaultData {
        version: 1,
        entries: Vec::new(),
    };
    save(&vault, password, path)
}

pub fn load(password: &[u8]) -> Result<VaultData, PassmanError> {
    load_from(password, &vault_path())
}

pub fn load_from(password: &[u8], path: &Path) -> Result<VaultData, PassmanError> {
    if !path.exists() {
        return Err(PassmanError::VaultNotFound);
    }
    let data = fs::read(path)?;
    let mut plaintext = crypto::decrypt(&data, password)?;
    let vault: VaultData = serde_json::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok(vault)
}

pub fn save(vault_data: &VaultData, password: &[u8], path: &Path) -> Result<(), PassmanError> {
    let mut json = serde_json::to_vec(vault_data)?;
    let encrypted = crypto::encrypt(&json, password)?;
    json.zeroize();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, encrypted)?;
    Ok(())
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn add_entry(
    password: &[u8],
    name: &str,
    username: &str,
    entry_password: &str,
    url: Option<&str>,
    notes: Option<&str>,
) -> Result<(), PassmanError> {
    add_entry_at(password, name, username, entry_password, url, notes, &vault_path())
}

pub fn add_entry_at(
    password: &[u8],
    name: &str,
    username: &str,
    entry_password: &str,
    url: Option<&str>,
    notes: Option<&str>,
    path: &Path,
) -> Result<(), PassmanError> {
    let mut vault = load_from(password, path)?;

    if vault
        .entries
        .iter()
        .any(|e| e.name.eq_ignore_ascii_case(name))
    {
        return Err(PassmanError::DuplicateEntry(name.to_string()));
    }

    let now = now_timestamp();
    let entry = Entry {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        username: username.to_string(),
        password: entry_password.to_string(),
        url: url.map(|s| s.to_string()),
        notes: notes.map(|s| s.to_string()),
        created_at: now,
        updated_at: now,
    };
    vault.entries.push(entry);
    save(&vault, password, path)
}

pub fn get_entry(password: &[u8], name: &str) -> Result<Entry, PassmanError> {
    get_entry_from(password, name, &vault_path())
}

pub fn get_entry_from(password: &[u8], name: &str, path: &Path) -> Result<Entry, PassmanError> {
    let vault = load_from(password, path)?;
    vault
        .entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
        .cloned()
        .ok_or_else(|| PassmanError::EntryNotFound(name.to_string()))
}

pub fn list_entries(password: &[u8]) -> Result<Vec<Entry>, PassmanError> {
    list_entries_from(password, &vault_path())
}

pub fn list_entries_from(password: &[u8], path: &Path) -> Result<Vec<Entry>, PassmanError> {
    let vault = load_from(password, path)?;
    Ok(vault.entries.clone())
}

pub fn delete_entry(password: &[u8], name: &str) -> Result<(), PassmanError> {
    delete_entry_at(password, name, &vault_path())
}

pub fn delete_entry_at(password: &[u8], name: &str, path: &Path) -> Result<(), PassmanError> {
    let mut vault = load_from(password, path)?;
    let idx = vault
        .entries
        .iter()
        .position(|e| e.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| PassmanError::EntryNotFound(name.to_string()))?;
    vault.entries.remove(idx);
    save(&vault, password, path)
}

pub fn change_master_password(old_password: &[u8], new_password: &[u8]) -> Result<(), PassmanError> {
    change_master_password_at(old_password, new_password, &vault_path())
}

pub fn change_master_password_at(old_password: &[u8], new_password: &[u8], path: &Path) -> Result<(), PassmanError> {
    let vault = load_from(old_password, path)?;
    save(&vault, new_password, path)
}
