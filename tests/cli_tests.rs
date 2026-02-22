use passman::generator::generate_password;

#[test]
fn generator_default_password() {
    let pw = generate_password(20, false, false).unwrap();
    assert_eq!(pw.len(), 20);
    assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
    assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
    assert!(pw.chars().any(|c| c.is_ascii_digit()));
}

#[test]
fn generator_no_symbols_no_numbers() {
    let pw = generate_password(16, true, true).unwrap();
    assert!(pw.chars().all(|c| c.is_ascii_alphabetic()));
}
