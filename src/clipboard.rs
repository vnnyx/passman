use std::thread;
use std::time::Duration;

use arboard::Clipboard;

use crate::error::PassmanError;

pub fn copy_with_auto_clear(text: &str, timeout_secs: u64) -> Result<(), PassmanError> {
    let mut clipboard =
        Clipboard::new().map_err(|e| PassmanError::Clipboard(e.to_string()))?;
    clipboard
        .set_text(text)
        .map_err(|e| PassmanError::Clipboard(e.to_string()))?;

    println!("Password copied to clipboard. Clearing in {timeout_secs} seconds...");

    thread::sleep(Duration::from_secs(timeout_secs));

    clipboard
        .set_text("")
        .map_err(|e| PassmanError::Clipboard(e.to_string()))?;

    println!("Clipboard cleared.");
    Ok(())
}
