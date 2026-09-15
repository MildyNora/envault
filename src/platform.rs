//! Small cross-platform helpers so the rest of the code stays platform-clean.

use std::io;
use std::path::Path;

/// User-facing name for the platform's protected credential backend.
pub fn credential_store_label() -> &'static str {
    credential_store_label_for(std::env::consts::OS)
}

fn credential_store_label_for(target_os: &str) -> &'static str {
    match target_os {
        "macos" => "the macOS Keychain",
        "windows" => "Windows Credential Manager",
        "linux" => "Secret Service",
        _ => "the OS credential store",
    }
}

/// Restrict a file/dir to the current user. On Unix this is a chmod; on other
/// platforms (Windows) files created under the user profile are already
/// user-scoped by the default ACLs, so this is a no-op.
#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_each_supported_credential_store() {
        assert_eq!(credential_store_label_for("macos"), "the macOS Keychain");
        assert_eq!(
            credential_store_label_for("windows"),
            "Windows Credential Manager"
        );
        assert_eq!(credential_store_label_for("linux"), "Secret Service");
        assert_eq!(
            credential_store_label_for("other"),
            "the OS credential store"
        );
    }
}
