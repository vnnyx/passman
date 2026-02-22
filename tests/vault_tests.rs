use std::path::PathBuf;
use tempfile::TempDir;

fn vault_file(dir: &TempDir) -> PathBuf {
    dir.path().join("vault.enc")
}

#[test]
fn init_creates_vault() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    passman::vault::init_at(b"master-password", &path).unwrap();
    assert!(path.exists());
}

#[test]
fn init_fails_if_vault_exists() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    passman::vault::init_at(b"master-password", &path).unwrap();
    let result = passman::vault::init_at(b"master-password", &path);
    assert!(result.is_err());
}

#[test]
fn add_and_get_entry() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let pw = b"master-password";
    passman::vault::init_at(pw, &path).unwrap();
    passman::vault::add_entry_at(pw, "GitHub", "user@example.com", "s3cret", Some("https://github.com"), None, &path).unwrap();
    let entry = passman::vault::get_entry_from(pw, "github", &path).unwrap();
    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.username, "user@example.com");
    assert_eq!(entry.password, "s3cret");
    assert_eq!(entry.url.as_deref(), Some("https://github.com"));
}

#[test]
fn list_entries() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let pw = b"master-password";
    passman::vault::init_at(pw, &path).unwrap();
    passman::vault::add_entry_at(pw, "GitHub", "user1", "pass1", None, None, &path).unwrap();
    passman::vault::add_entry_at(pw, "GitLab", "user2", "pass2", None, None, &path).unwrap();
    let entries = passman::vault::list_entries_from(pw, &path).unwrap();
    assert_eq!(entries.len(), 2);
}

#[test]
fn delete_entry() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let pw = b"master-password";
    passman::vault::init_at(pw, &path).unwrap();
    passman::vault::add_entry_at(pw, "GitHub", "user", "pass", None, None, &path).unwrap();
    passman::vault::delete_entry_at(pw, "github", &path).unwrap();
    let entries = passman::vault::list_entries_from(pw, &path).unwrap();
    assert_eq!(entries.len(), 0);
}

#[test]
fn delete_nonexistent_entry_fails() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let pw = b"master-password";
    passman::vault::init_at(pw, &path).unwrap();
    let result = passman::vault::delete_entry_at(pw, "nonexistent", &path);
    assert!(result.is_err());
}

#[test]
fn wrong_password_fails() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    passman::vault::init_at(b"correct", &path).unwrap();
    let result = passman::vault::load_from(b"wrong", &path);
    assert!(result.is_err());
}

#[test]
fn duplicate_entry_fails() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let pw = b"master-password";
    passman::vault::init_at(pw, &path).unwrap();
    passman::vault::add_entry_at(pw, "GitHub", "user", "pass", None, None, &path).unwrap();
    let result = passman::vault::add_entry_at(pw, "github", "user2", "pass2", None, None, &path);
    assert!(result.is_err());
}

#[test]
fn change_master_password() {
    let dir = TempDir::new().unwrap();
    let path = vault_file(&dir);
    let old = b"old-password";
    let new = b"new-password";
    passman::vault::init_at(old, &path).unwrap();
    passman::vault::add_entry_at(old, "Test", "user", "pass", None, None, &path).unwrap();
    passman::vault::change_master_password_at(old, new, &path).unwrap();
    assert!(passman::vault::load_from(old, &path).is_err());
    let entry = passman::vault::get_entry_from(new, "Test", &path).unwrap();
    assert_eq!(entry.username, "user");
}
