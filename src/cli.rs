use std::io::Write;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use crate::clipboard;
use crate::error::PassmanError;
use crate::generator;
use crate::vault;

#[derive(Parser)]
#[command(name = "pm", about = "Passman - Secure CLI Password Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init,

    /// Add a new entry to the vault
    Add {
        /// Name of the entry (e.g. "GitHub")
        name: String,

        /// Username or email
        #[arg(long)]
        username: Option<String>,

        /// URL associated with the entry
        #[arg(long)]
        url: Option<String>,

        /// Notes
        #[arg(long)]
        notes: Option<String>,

        /// Auto-generate a password
        #[arg(long)]
        generate: bool,
    },

    /// Retrieve an entry from the vault
    Get {
        /// Name of the entry to retrieve
        name: String,
    },

    /// List all entries in the vault
    List,

    /// Delete an entry from the vault
    Delete {
        /// Name of the entry to delete
        name: String,
    },

    /// Generate a random password (no vault required)
    Generate {
        /// Password length (default: 20)
        #[arg(long, default_value_t = 20)]
        length: usize,

        /// Exclude symbols
        #[arg(long)]
        no_symbols: bool,

        /// Exclude numbers
        #[arg(long)]
        no_numbers: bool,
    },

    /// Change the master password
    ChangeMaster,
}

pub fn run() -> Result<(), PassmanError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Add {
            name,
            username,
            url,
            notes,
            generate,
        } => cmd_add(&name, username.as_deref(), url.as_deref(), notes.as_deref(), generate),
        Commands::Get { name } => cmd_get(&name),
        Commands::List => cmd_list(),
        Commands::Delete { name } => cmd_delete(&name),
        Commands::Generate {
            length,
            no_symbols,
            no_numbers,
        } => cmd_generate(length, no_symbols, no_numbers),
        Commands::ChangeMaster => cmd_change_master(),
    }
}

fn prompt_password(prompt: &str) -> Result<String, PassmanError> {
    rpassword::prompt_password(prompt).map_err(PassmanError::Io)
}

fn cmd_init() -> Result<(), PassmanError> {
    let mut password = prompt_password("Enter master password: ")?;
    let mut confirm = prompt_password("Confirm master password: ")?;

    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err(PassmanError::Crypto("Passwords do not match.".into()));
    }
    confirm.zeroize();

    let result = vault::init(password.as_bytes());
    password.zeroize();
    result?;

    println!("Vault initialized successfully.");
    Ok(())
}

fn cmd_add(
    name: &str,
    username: Option<&str>,
    url: Option<&str>,
    notes: Option<&str>,
    generate: bool,
) -> Result<(), PassmanError> {
    let mut master = prompt_password("Master password: ")?;

    let mut entry_password = if generate {
        generator::generate_password(20, false, false)?
    } else {
        let mut p = prompt_password("Entry password: ")?;
        let mut c = prompt_password("Confirm entry password: ")?;
        if p != c {
            p.zeroize();
            c.zeroize();
            master.zeroize();
            return Err(PassmanError::Crypto("Passwords do not match.".into()));
        }
        c.zeroize();
        p
    };

    let username = username.unwrap_or("");

    let result = vault::add_entry(
        master.as_bytes(),
        name,
        username,
        &entry_password,
        url,
        notes,
    );
    master.zeroize();
    entry_password.zeroize();
    result?;

    if generate {
        println!("Entry '{}' added with generated password.", name);
    } else {
        println!("Entry '{}' added.", name);
    }
    Ok(())
}

fn cmd_get(name: &str) -> Result<(), PassmanError> {
    let mut master = prompt_password("Master password: ")?;
    let result = vault::get_entry(master.as_bytes(), name);
    master.zeroize();
    let entry = result?;

    println!("Name:     {}", entry.name);
    println!("Username: {}", entry.username);
    if let Some(ref url) = entry.url {
        println!("URL:      {}", url);
    }
    if let Some(ref notes) = entry.notes {
        println!("Notes:    {}", notes);
    }

    println!();
    print!("Copy password to clipboard? [y/N] ");
    std::io::stdout().flush().map_err(PassmanError::Io)?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(PassmanError::Io)?;

    if input.trim().eq_ignore_ascii_case("y") {
        match clipboard::copy_with_auto_clear(&entry.password, 10) {
            Ok(()) => {}
            Err(e) => eprintln!("Clipboard error: {e}"),
        }
    }

    Ok(())
}

fn cmd_list() -> Result<(), PassmanError> {
    let mut master = prompt_password("Master password: ")?;
    let result = vault::list_entries(master.as_bytes());
    master.zeroize();
    let entries = result?;

    if entries.is_empty() {
        println!("No entries found.");
        return Ok(());
    }

    println!(
        "{:<20} {:<25} {:<30} {:<20}",
        "Name", "Username", "URL", "Last Updated"
    );
    println!("{}", "-".repeat(95));

    for entry in &entries {
        let url = entry.url.as_deref().unwrap_or("-");
        let updated = format_timestamp(entry.updated_at);
        println!("{:<20} {:<25} {:<30} {:<20}", entry.name, entry.username, url, updated);
    }

    Ok(())
}

fn cmd_delete(name: &str) -> Result<(), PassmanError> {
    let mut master = prompt_password("Master password: ")?;

    print!("Are you sure you want to delete '{name}'? [y/N] ");
    std::io::stdout().flush().map_err(PassmanError::Io)?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(PassmanError::Io)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        master.zeroize();
        println!("Aborted.");
        return Ok(());
    }

    let result = vault::delete_entry(master.as_bytes(), name);
    master.zeroize();
    result?;

    println!("Entry '{name}' deleted.");
    Ok(())
}

fn cmd_generate(length: usize, no_symbols: bool, no_numbers: bool) -> Result<(), PassmanError> {
    let password = generator::generate_password(length, no_symbols, no_numbers)?;
    println!("{password}");
    Ok(())
}

fn cmd_change_master() -> Result<(), PassmanError> {
    let mut old = prompt_password("Current master password: ")?;
    let mut new_pw = prompt_password("New master password: ")?;
    let mut confirm = prompt_password("Confirm new master password: ")?;

    if new_pw != confirm {
        old.zeroize();
        new_pw.zeroize();
        confirm.zeroize();
        return Err(PassmanError::Crypto("Passwords do not match.".into()));
    }
    confirm.zeroize();

    let result = vault::change_master_password(old.as_bytes(), new_pw.as_bytes());
    old.zeroize();
    new_pw.zeroize();
    result?;

    println!("Master password changed successfully.");
    Ok(())
}

fn format_timestamp(ts: u64) -> String {
    let secs = ts;
    let days = secs / 86400;
    let years = days / 365 + 1970;
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    format!("{:04}-{:02}-{:02}", years, months, day)
}
