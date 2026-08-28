use std::path::{Path, PathBuf};

pub fn envault_home() -> PathBuf {
    if let Ok(h) = std::env::var("ENVAULT_HOME") {
        return PathBuf::from(h);
    }
    dirs::home_dir()
        .expect("no home directory")
        .join(".envault")
}

pub fn vault_file(home: &Path) -> PathBuf {
    home.join("vault.json")
}

pub fn recipient_file(home: &Path) -> PathBuf {
    home.join("recipient.txt")
}
