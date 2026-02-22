use rand::seq::IndexedRandom;
use rand::RngCore;

use crate::error::PassmanError;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+";

pub fn generate_password(length: usize, no_symbols: bool, no_numbers: bool) -> Result<String, PassmanError> {
    if !(8..=128).contains(&length) {
        return Err(PassmanError::Crypto(
            "Password length must be between 8 and 128".into(),
        ));
    }

    let mut charsets: Vec<&[u8]> = vec![LOWERCASE, UPPERCASE];
    if !no_numbers {
        charsets.push(DIGITS);
    }
    if !no_symbols {
        charsets.push(SYMBOLS);
    }

    let mut rng = rand::rng();
    let mut password = Vec::with_capacity(length);

    // Guarantee at least one char from each enabled set
    for charset in &charsets {
        let ch = charset.choose(&mut rng)
            .ok_or_else(|| PassmanError::Crypto("empty charset".into()))?;
        password.push(*ch);
    }

    // Build combined pool for remaining chars
    let pool: Vec<u8> = charsets.iter().flat_map(|c| c.iter().copied()).collect();

    // Fill remaining
    while password.len() < length {
        let ch = pool.choose(&mut rng)
            .ok_or_else(|| PassmanError::Crypto("empty pool".into()))?;
        password.push(*ch);
    }

    // Shuffle using Fisher-Yates
    for i in (1..password.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        password.swap(i, j);
    }

    String::from_utf8(password).map_err(|e| PassmanError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_correct_length() {
        let pw = generate_password(20, false, false).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn contains_all_charsets() {
        let pw = generate_password(50, false, false).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| "!@#$%^&*-_=+".contains(c)));
    }

    #[test]
    fn no_symbols_flag() {
        let pw = generate_password(20, true, false).unwrap();
        assert!(!pw.chars().any(|c| "!@#$%^&*-_=+".contains(c)));
    }

    #[test]
    fn no_numbers_flag() {
        let pw = generate_password(20, false, true).unwrap();
        assert!(!pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_too_short() {
        assert!(generate_password(5, false, false).is_err());
    }

    #[test]
    fn rejects_too_long() {
        assert!(generate_password(200, false, false).is_err());
    }
}
