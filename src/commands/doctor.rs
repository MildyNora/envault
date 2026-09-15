use age::x25519;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use crate::settings::Settings;
use crate::store::{is_valid_alias, Vault};

const MAX_LOCAL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Status { Ok, Advisory, Error, NotChecked }

#[derive(Debug, Serialize)]
struct Check { name: &'static str, status: Status, detail: String }

#[derive(Debug, Serialize)]
struct Report {
    local_checks_passed: bool,
    credential_store: &'static str,
    observation_scope: &'static str,
    checks: Vec<Check>,
}

pub fn cmd_doctor(json: bool) -> anyhow::Result<i32> {
    let report = diagnose(&crate::paths::envault_home());
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("envault doctor — local observations only");
        println!("credential store: {} (not opened)", report.credential_store);
        for check in &report.checks {
            println!("[{}] {}: {}", status_name(check.status), check.name, check.detail);
        }
        println!("{}", report.observation_scope);
        println!("overall: {}", if report.local_checks_passed {
            "local checks passed; vault usability not established"
        } else { "local checks failed; vault usability not established" });
    }
    Ok(if report.local_checks_passed { 0 } else { 2 })
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok", Status::Advisory => "advisory",
        Status::Error => "error", Status::NotChecked => "not-checked",
    }
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check { name, status, detail: detail.into() }
}

// A diagnostic must not call runtime load/recovery/settings APIs. Even a
// generation lock could create files. These are uncoordinated observations.
fn diagnose(home: &Path) -> Report {
    let mut checks = Vec::new();
    match std::fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            checks.push(check("local home", Status::Advisory,
                "absent; ask the human to assess setup or recovery; safe reinitialization is not established"));
        }
        Err(_) => checks.push(check("local home", Status::Error, "metadata unavailable")),
        Ok(meta) if unsafe_link(&meta) || !meta.is_dir() => {
            checks.push(check("local home", Status::Error, "not a regular directory; inspection refused"));
        }
        Ok(_) => {
            checks.push(check_vault(&home.join("vault.json")));
            checks.push(check_recipient(&home.join("recipient.txt")));
            checks.push(check_settings(&home.join("config.json")));
            checks.push(observe_file(&home.join("identity-id"), "identity metadata",
                "absent; legacy association is possible; protected association not checked"));
            for (file, label) in [("audit.log", "audit log"), ("audit.head", "audit head"),
                ("audit.key.age", "audit key wrapper")] {
                checks.push(observe_file(&home.join(file), label,
                    "absent locally; audit authenticity and protected recovery not checked"));
            }
            match (regular_metadata(&home.join("audit.log")), regular_metadata(&home.join("audit.head"))) {
                (Ok(Some(_)), Ok(None)) | (Ok(None), Ok(Some(_))) => checks.push(check(
                    "audit evidence pair", Status::Error,
                    "incomplete local pair observed; preserve files for human assessment; authenticity and recovery not checked")),
                _ => {}
            }
        }
    }
    for (name, detail) in [
        ("credential availability", "protected credential store intentionally not opened"),
        ("key/vault matching", "authoritative identity and decryptability not checked"),
        ("protected settings", "authority and effective values not checked"),
        ("audit authenticity", "chain, anchor and wrapper authenticity not checked"),
        ("protected recovery status", "recovery records not opened; no recovery or cleanup attempted"),
        ("encrypted-payload validity", "Base64 encoding checks do not establish age format or decryptability"),
    ] { checks.push(check(name, Status::NotChecked, detail)); }
    Report {
        local_checks_passed: checks.iter().all(|c| c.status != Status::Error),
        credential_store: crate::platform::credential_store_label(),
        observation_scope: "Uncoordinated local observations, not an authenticated consistent generation. Ask the human to assess setup or recovery; do not infer safe reinitialization.",
        checks,
    }
}

fn unsafe_link(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Reject every reparse point, including junctions.
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    { meta.file_type().is_symlink() }
}

fn regular_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if unsafe_link(&meta) || !meta.is_file() => Err("non-regular file or link; inspection refused"),
        Ok(meta) if meta.len() > MAX_LOCAL_BYTES => Err("exceeds local inspection size limit"),
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("metadata unavailable"),
    }
}

fn observe_file(path: &Path, name: &'static str, absent: &'static str) -> Check {
    match regular_metadata(path) {
        Ok(None) => check(name, Status::Advisory, absent),
        Ok(Some(_)) => check(name, Status::Advisory, "regular file observed; content and authority not checked"),
        Err(detail) => check(name, Status::Error, detail),
    }
}

fn read_local(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    if regular_metadata(path)?.is_none() { return Ok(None); }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Avoid following a replaced final symlink or blocking on a replaced FIFO.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the opened object, not its target.
        options.custom_flags(0x00200000);
    }
    #[cfg(not(any(unix, windows)))]
    { return Err("bounded file inspection unsupported on this platform"); }
    let file = options.open(path).map_err(|_| "file unreadable or changed during inspection")?;
    let meta = file.metadata().map_err(|_| "opened file metadata unavailable")?;
    if unsafe_link(&meta) || !meta.is_file() { return Err("opened object is not a regular file"); }
    if meta.len() > MAX_LOCAL_BYTES { return Err("exceeds local inspection size limit"); }
    let mut raw = Vec::new();
    file.take(MAX_LOCAL_BYTES + 1).read_to_end(&mut raw)
        .map_err(|_| "file read failed")?;
    if raw.len() as u64 > MAX_LOCAL_BYTES { return Err("exceeds local inspection size limit"); }
    Ok(Some(raw))
}

fn check_vault(path: &Path) -> Check {
    let raw = match read_local(path) {
        Ok(Some(raw)) => raw,
        Ok(None) => return check("vault", Status::Advisory,
            "absent locally; protected identity/recovery may still exist; ask the human to assess setup or recovery"),
        Err(detail) => return check("vault", Status::Error, detail),
    };
    let vault: Vault = match serde_json::from_slice(&raw) {
        Ok(vault) => vault,
        Err(_) => return check("vault", Status::Error, "invalid local JSON/schema; preserve files for human assessment"),
    };
    let mut aliases = HashSet::new();
    let invalid_aliases = vault.secrets.iter()
        .filter(|entry| !is_valid_alias(&entry.alias) || !aliases.insert(&entry.alias)).count();
    let invalid_encodings = vault.secrets.iter()
        .filter(|entry| B64.decode(entry.cipher.trim()).is_err()).count();
    check("vault", if invalid_aliases + invalid_encodings == 0 { Status::Ok } else { Status::Error },
        format!("{} local records; {invalid_aliases} invalid/duplicate aliases; {invalid_encodings} invalid Base64 encodings; age format and decryptability not checked", vault.secrets.len()))
}

fn check_recipient(path: &Path) -> Check {
    let detail = match read_local(path) {
        Ok(None) => "public mirror absent; authoritative identity not checked",
        Ok(Some(raw)) => match std::str::from_utf8(&raw).ok().and_then(|s| x25519::Recipient::from_str(s.trim()).ok()) {
            Some(_) => "public mirror parses; freshness and key/vault match not checked",
            None => "public mirror malformed; this does not establish vault unusability",
        },
        Err(detail) => return check("recipient mirror", Status::Error, detail),
    };
    check("recipient mirror", Status::Advisory, detail)
}

fn check_settings(path: &Path) -> Check {
    match read_local(path) {
        Ok(None) => check("settings mirror", Status::Advisory, "absent; effective protected settings not checked"),
        Ok(Some(raw)) => match serde_json::from_slice::<Settings>(&raw) {
            Ok(_) => check("settings mirror", Status::Ok, "local structure parses; protected authority and effective values not checked"),
            Err(_) => check("settings mirror", Status::Error, "invalid local JSON/schema; protected authority and effective values not checked"),
        },
        Err(detail) => check("settings mirror", Status::Error, detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_home_is_only_an_observation_and_is_not_created() {
        let parent = tempfile::TempDir::new().unwrap();
        let home = parent.path().join("absent");
        let report = diagnose(&home);
        assert!(report.local_checks_passed);
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("healthy"));
        assert!(text.contains("safe reinitialization is not established"));
        assert!(!home.exists());
    }

    #[test]
    fn identity_metadata_without_vault_does_not_offer_reinitialization() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::write(home.path().join("identity-id"), "synthetic-id").unwrap();
        let report = diagnose(home.path());
        assert!(report.local_checks_passed);
        let text = serde_json::to_string(&report).unwrap();
        assert!(text.contains("protected identity/recovery may still exist"));
        assert!(text.contains("regular file observed"));
        assert!(!text.contains("envault init"));
        assert!(!text.contains("synthetic-id"));
    }

    #[test]
    fn mirror_and_encoding_checks_do_not_assert_authority() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::write(home.path().join("vault.json"),
            r#"{"secrets":[{"alias":"sample","label":"sample","cipher":"YWJj","created_at":"x","updated_at":"x","notes":""}]}"#).unwrap();
        let first = diagnose(home.path());
        assert!(first.local_checks_passed);
        let text = serde_json::to_string(&first).unwrap();
        assert!(text.contains("age format and decryptability not checked"));
        assert!(!text.contains("defaults apply"));
        std::fs::write(home.path().join("recipient.txt"), "invalid-public-mirror").unwrap();
        assert!(diagnose(home.path()).local_checks_passed);
        std::fs::write(home.path().join("config.json"), "private-garbage").unwrap();
        let text = serde_json::to_string(&diagnose(home.path())).unwrap();
        assert!(text.contains("invalid local JSON/schema"));
        assert!(!text.contains("private-garbage"));
        assert!(!text.contains("remain fail-closed"));
    }

    #[test]
    fn special_oversized_and_lookup_errors_are_not_absence() {
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join("vault.json");
        std::fs::create_dir(&path).unwrap();
        assert!(read_local(&path).is_err());
        assert!(!diagnose(home.path()).local_checks_passed);
        assert!(read_local(&path.join("missing")).unwrap().is_none());
        std::fs::remove_dir(&path).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LOCAL_BYTES + 1).unwrap();
        assert!(read_local(&path).is_err());
        // ENOTDIR is a lookup error, not a missing child file.
        assert!(read_local(&path.join("child")).is_err());
        let text = serde_json::to_string(&diagnose(home.path())).unwrap();
        assert!(!text.contains(&home.path().display().to_string()));
        assert!(!text.contains("os error"));
    }

    #[test]
    fn incomplete_audit_pair_is_reported_without_reading_or_repairing_it() {
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join("audit.log");
        std::fs::write(&path, "synthetic-history-preserve").unwrap();
        let report = diagnose(home.path());
        assert!(!report.local_checks_passed);
        assert!(report.checks.iter().any(|c| c.name == "audit evidence pair"));
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic-history-preserve");
        assert!(!home.path().join("audit.head").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_fifo_are_refused_without_opening_targets() {
        use std::os::unix::ffi::OsStrExt;
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join("vault.json");
        std::os::unix::fs::symlink("missing-target", &path).unwrap();
        assert!(read_local(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Synthetic FIFO only; no writer is opened, so an unsafe read would hang.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_local(&path).is_err());
        assert!(!diagnose(home.path()).local_checks_passed);
    }
}
