//! Small cross-platform helpers so the rest of the code stays platform-clean.

use std::io;
use std::path::Path;

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
