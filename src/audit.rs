//! Lightweight, HMAC-chained audit log of every decryption.
//!
//! Cheap (one appended line per event, no daemon), small (auto-trimmed to a
//! size cap), and tamper-evident: each entry carries an HMAC — keyed by the
//! audit key, encrypted to the current Keychain-protected identity — over its
//! fields and the previous entry's MAC, and a separate MAC'd "head" anchor
//! records the entry count + last MAC so truncation/deletion is detectable too.
//! An adversary who cannot read the Keychain identity cannot forge, edit, or
//! silently trim the log. It makes access visible; it does not prevent it.

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// Keep the log tiny — trim to the most recent entries once it passes this.
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub action: String,
    pub detail: String,
    pub prev: String, // hex MAC of the previous entry ("" for the first kept)
    pub hash: String, // hex HMAC of this entry's (ts, action, detail, prev)
}

fn log_file(home: &Path) -> PathBuf {
    home.join("audit.log")
}
fn head_file(home: &Path) -> PathBuf {
    home.join("audit.head")
}
fn key_file(home: &Path) -> PathBuf {
    home.join("audit.key.age")
}
fn staged_key_file(home: &Path) -> PathBuf {
    home.join("audit.key.age.new")
}
fn staged_log_file(home: &Path) -> PathBuf {
    home.join("audit.log.new")
}
fn staged_head_file(home: &Path) -> PathBuf {
    home.join("audit.head.new")
}

fn mac(key: &[u8], parts: &[&[u8]]) -> String {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            m.update(&[0]);
        }
        m.update(p);
    }
    hex(&m.finalize().into_bytes())
}

fn entry_mac(key: &[u8], ts: &str, action: &str, detail: &str, prev: &str) -> String {
    mac(
        key,
        &[
            ts.as_bytes(),
            action.as_bytes(),
            detail.as_bytes(),
            prev.as_bytes(),
        ],
    )
}

fn head_mac(key: &[u8], count: usize, last: &str) -> String {
    mac(key, &[count.to_string().as_bytes(), last.as_bytes()])
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Append an event, keyed by `key` (the identity's secret bytes). Returns Err
/// on any I/O failure so the caller can fail closed when auditing is required.
pub fn record(home: &Path, key: &[u8], action: &str, detail: &str) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let entries = read(home).unwrap_or_default();
    let prev = entries.last().map(|e| e.hash.clone()).unwrap_or_default();
    let ts = crate::store::now_rfc3339();
    let hash = entry_mac(key, &ts, action, detail, &prev);
    let entry = Entry {
        ts,
        action: action.to_string(),
        detail: detail.to_string(),
        prev,
        hash: hash.clone(),
    };

    let path = log_file(home);
    let mut line = serde_json::to_string(&entry)?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(line.as_bytes())?;
    drop(f);
    crate::platform::set_mode(&path, 0o600)?;

    let new_count = entries.len() + 1;
    write_head(home, key, new_count, &hash)?;
    trim(home, key)?;
    Ok(())
}

fn write_head(home: &Path, key: &[u8], count: usize, last: &str) -> Result<()> {
    let path = head_file(home);
    std::fs::write(&path, head_mac(key, count, last))?;
    crate::platform::set_mode(&path, 0o600)?;
    Ok(())
}

/// Trim the oldest lines past the cap, re-anchoring the head to the kept set.
fn trim(home: &Path, key: &[u8]) -> Result<()> {
    let path = log_file(home);
    let over = std::fs::metadata(&path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false);
    if !over {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)?;
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    let keep = &lines[lines.len() / 2..];
    std::fs::write(&path, format!("{}\n", keep.join("\n")))?;
    crate::platform::set_mode(&path, 0o600)?;
    let entries = read(home).unwrap_or_default();
    let last = entries.last().map(|e| e.hash.clone()).unwrap_or_default();
    write_head(home, key, entries.len(), &last)
}

pub fn read(home: &Path) -> Result<Vec<Entry>> {
    let path = log_file(home);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path)?;
    raw.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<Entry>(line)
                .with_context(|| format!("parsing audit entry {}", index + 1))
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Integrity {
    Ok,
    /// An entry was edited or an interior entry was removed (index given).
    Broken(usize),
    /// The head anchor is missing or doesn't match — the log was truncated,
    /// deleted, or its count altered.
    HeadMismatch,
}

/// Verify the chain and the head anchor using `key`.
pub fn verify(home: &Path, key: &[u8], entries: &[Entry]) -> Integrity {
    for (i, e) in entries.iter().enumerate() {
        if entry_mac(key, &e.ts, &e.action, &e.detail, &e.prev) != e.hash {
            return Integrity::Broken(i);
        }
        if i > 0 && e.prev != entries[i - 1].hash {
            return Integrity::Broken(i);
        }
    }
    // Head anchor: catches tail truncation / whole-log deletion.
    let last = entries.last().map(|e| e.hash.clone()).unwrap_or_default();
    let expected = head_mac(key, entries.len(), &last);
    match std::fs::read_to_string(head_file(home)) {
        Ok(h) if h.trim() == expected => Integrity::Ok,
        // No head yet AND no entries = a genuinely empty log is fine.
        Err(_) if entries.is_empty() => Integrity::Ok,
        _ => Integrity::HeadMismatch,
    }
}

/// Return the audit-MAC key for the active identity. Legacy vaults use the
/// identity itself until their first rotation migrates to a stable derived key;
/// that key is then re-encrypted to each new recipient.
pub fn verification_key(home: &Path, identity: &age::x25519::Identity) -> Result<SecretString> {
    let primary = key_file(home);
    match std::fs::read_to_string(&primary) {
        Ok(cipher) => match crate::crypto::decrypt_value(identity, &cipher) {
            Ok(key) => Ok(key.into()),
            Err(primary_error) => {
                // A failed rotation may have stored the new identity just
                // before activating the staged wrapper. Keep audit access
                // fail-safe and recoverable across that narrow window.
                let staged = staged_key_file(home);
                match std::fs::read_to_string(&staged) {
                    Ok(cipher) => crate::crypto::decrypt_value(identity, &cipher)
                        .map(Into::into)
                        .context("decrypting the staged audit verification key"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Err(primary_error).context("decrypting the audit verification key")
                    }
                    Err(error) => {
                        Err(error).with_context(|| format!("reading {}", staged.display()))
                    }
                }
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let staged = staged_key_file(home);
            match std::fs::read_to_string(&staged) {
                Ok(cipher) => match crate::crypto::decrypt_value(identity, &cipher) {
                    Ok(key) => Ok(key.into()),
                    // The identity swap may not have happened yet. With no
                    // active wrapper this remains a legacy identity-keyed log.
                    Err(_) => Ok(identity.to_string()),
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(identity.to_string())
                }
                Err(error) => Err(error).with_context(|| format!("reading {}", staged.display())),
            }
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", primary.display())),
    }
}

struct StagedFile {
    staged: PathBuf,
    target: PathBuf,
}

/// Encrypted audit-key state prepared for a new vault identity. Activation is
/// deliberately separate so verification happens before the identity swap.
pub struct PreparedKeyRotation {
    files: Vec<StagedFile>,
}

impl PreparedKeyRotation {
    pub fn activate(self) -> Result<()> {
        for file in self.files {
            std::fs::rename(&file.staged, &file.target)
                .with_context(|| format!("activating {}", file.target.display()))?;
        }
        Ok(())
    }
}

fn derived_key(identity: &age::x25519::Identity) -> SecretString {
    let identity = identity.to_string();
    let mut digest = Sha256::new();
    digest.update(b"envault audit key v1\0");
    digest.update(identity.expose_secret().as_bytes());
    hex(&digest.finalize()).into()
}

fn stage_file(staged: PathBuf, target: PathBuf, contents: &[u8]) -> Result<StagedFile> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&staged)
        .with_context(|| format!("opening {}", staged.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", staged.display()))?;
    crate::platform::set_mode(&staged, 0o600)?;
    file.sync_all()
        .with_context(|| format!("syncing {}", staged.display()))?;
    Ok(StagedFile { staged, target })
}

fn resign(entries: &mut [Entry], key: &[u8]) {
    let mut prev = entries
        .first()
        .map(|entry| entry.prev.clone())
        .unwrap_or_default();
    for entry in entries {
        entry.prev = prev;
        entry.hash = entry_mac(key, &entry.ts, &entry.action, &entry.detail, &entry.prev);
        prev = entry.hash.clone();
    }
}

/// Verify the existing audit state and wrap its MAC key to the new identity.
/// Legacy logs migrate once to a one-way derived key so rotation never retains
/// a decrypt-capable retired private identity.
pub fn prepare_key_rotation(
    home: &Path,
    old_identity: &age::x25519::Identity,
    new_identity: &age::x25519::Identity,
) -> Result<Option<PreparedKeyRotation>> {
    let has_state = log_file(home).exists() || head_file(home).exists() || key_file(home).exists();
    if !has_state {
        return Ok(None);
    }

    let current_key = verification_key(home, old_identity)?;
    let mut entries = read(home)?;
    match verify(home, current_key.expose_secret().as_bytes(), &entries) {
        Integrity::Ok => {}
        Integrity::Broken(index) => {
            bail!("refusing rotation: audit entry {index} failed verification")
        }
        Integrity::HeadMismatch => {
            bail!("refusing rotation: audit head anchor does not match the log")
        }
    }

    let legacy = !key_file(home).exists();
    let next_key = if legacy {
        derived_key(new_identity)
    } else {
        current_key
    };
    let mut files = Vec::new();

    if legacy {
        resign(&mut entries, next_key.expose_secret().as_bytes());
        if log_file(home).exists() {
            let mut raw = String::new();
            for entry in &entries {
                raw.push_str(&serde_json::to_string(entry)?);
                raw.push('\n');
            }
            files.push(stage_file(
                staged_log_file(home),
                log_file(home),
                raw.as_bytes(),
            )?);
        }
        if head_file(home).exists() || !entries.is_empty() {
            let last = entries
                .last()
                .map(|entry| entry.hash.as_str())
                .unwrap_or("");
            let head = head_mac(next_key.expose_secret().as_bytes(), entries.len(), last);
            files.push(stage_file(
                staged_head_file(home),
                head_file(home),
                head.as_bytes(),
            )?);
        }
    }

    let cipher = crate::crypto::encrypt_value(&new_identity.to_public(), next_key.expose_secret())?;
    files.push(stage_file(
        staged_key_file(home),
        key_file(home),
        cipher.as_bytes(),
    )?);

    Ok(Some(PreparedKeyRotation { files }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const KEY: &[u8] = b"test-identity-secret-bytes";

    #[test]
    fn records_and_verifies() {
        let home = TempDir::new().unwrap();
        record(home.path(), KEY, "run", "npm test").unwrap();
        record(home.path(), KEY, "reveal", "openrouter").unwrap();
        let entries = read(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev, entries[0].hash);
        assert_eq!(verify(home.path(), KEY, &entries), Integrity::Ok);
    }

    #[test]
    fn detects_edit() {
        let home = TempDir::new().unwrap();
        record(home.path(), KEY, "run", "a").unwrap();
        record(home.path(), KEY, "run", "b").unwrap();
        let mut entries = read(home.path()).unwrap();
        entries[0].detail = "TAMPERED".into();
        assert_eq!(verify(home.path(), KEY, &entries), Integrity::Broken(0));
    }

    #[test]
    fn detects_interior_deletion() {
        let home = TempDir::new().unwrap();
        for d in ["a", "b", "c"] {
            record(home.path(), KEY, "run", d).unwrap();
        }
        let mut entries = read(home.path()).unwrap();
        entries.remove(1);
        assert_eq!(verify(home.path(), KEY, &entries), Integrity::Broken(1));
    }

    #[test]
    fn detects_tail_truncation_via_head_anchor() {
        let home = TempDir::new().unwrap();
        for d in ["a", "b", "c"] {
            record(home.path(), KEY, "run", d).unwrap();
        }
        // delete the last line but leave a valid-looking chain
        let raw = std::fs::read_to_string(log_file(home.path())).unwrap();
        let kept: Vec<&str> = raw.lines().take(2).collect();
        std::fs::write(log_file(home.path()), format!("{}\n", kept.join("\n"))).unwrap();
        let entries = read(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(verify(home.path(), KEY, &entries), Integrity::HeadMismatch);
    }

    #[test]
    fn cannot_forge_without_key() {
        let home = TempDir::new().unwrap();
        record(home.path(), KEY, "run", "a").unwrap();
        let entries = read(home.path()).unwrap();
        // an attacker who guesses the algorithm but not the key can't verify
        assert_eq!(
            verify(home.path(), b"wrong-key", &entries),
            Integrity::Broken(0)
        );
    }

    #[test]
    fn entries_remain_verifiable_after_key_rotation() {
        let home = TempDir::new().unwrap();
        let old_identity = crate::crypto::generate_identity();
        let new_identity = crate::crypto::generate_identity();
        let old_key = old_identity.to_string();
        record(
            home.path(),
            old_key.expose_secret().as_bytes(),
            "run",
            "before rotation",
        )
        .unwrap();
        let original_entries = read(home.path()).unwrap();

        let prepared = prepare_key_rotation(home.path(), &old_identity, &new_identity)
            .unwrap()
            .unwrap();
        let old_key_while_staged = verification_key(home.path(), &old_identity).unwrap();
        assert_eq!(
            old_key_while_staged.expose_secret(),
            old_key.expose_secret(),
            "staging alone must not switch a legacy vault's audit key"
        );
        prepared.activate().unwrap();

        let entries = read(home.path()).unwrap();
        let new_key = verification_key(home.path(), &new_identity).unwrap();
        assert_eq!(
            verify(home.path(), new_key.expose_secret().as_bytes(), &entries),
            Integrity::Ok
        );
        assert_eq!(
            entries
                .iter()
                .map(|entry| (&entry.ts, &entry.action, &entry.detail))
                .collect::<Vec<_>>(),
            original_entries
                .iter()
                .map(|entry| (&entry.ts, &entry.action, &entry.detail))
                .collect::<Vec<_>>(),
            "rotation must preserve the historical events"
        );
        let wrapped = std::fs::read_to_string(key_file(home.path())).unwrap();
        let stored_key = crate::crypto::decrypt_value(&new_identity, &wrapped).unwrap();
        assert_ne!(stored_key, *old_key.expose_secret());

        let newest_identity = crate::crypto::generate_identity();
        let migrated_log = std::fs::read(log_file(home.path())).unwrap();
        prepare_key_rotation(home.path(), &new_identity, &newest_identity)
            .unwrap()
            .unwrap()
            .activate()
            .unwrap();
        let newest_key = verification_key(home.path(), &newest_identity).unwrap();
        assert_eq!(
            verify(home.path(), newest_key.expose_secret().as_bytes(), &entries),
            Integrity::Ok
        );
        assert_eq!(
            std::fs::read(log_file(home.path())).unwrap(),
            migrated_log,
            "later rotations only rewrap the stable audit key"
        );
    }

    #[test]
    fn key_rotation_refuses_a_truncated_audit_log() {
        let home = TempDir::new().unwrap();
        let old_identity = crate::crypto::generate_identity();
        let new_identity = crate::crypto::generate_identity();
        let old_key = old_identity.to_string();
        for detail in ["first", "second"] {
            record(
                home.path(),
                old_key.expose_secret().as_bytes(),
                "run",
                detail,
            )
            .unwrap();
        }
        let raw = std::fs::read_to_string(log_file(home.path())).unwrap();
        std::fs::write(
            log_file(home.path()),
            format!("{}\n", raw.lines().next().unwrap()),
        )
        .unwrap();

        let error = prepare_key_rotation(home.path(), &old_identity, &new_identity)
            .err()
            .expect("truncated audit must block rotation");
        assert!(error.to_string().contains("head anchor"), "{error:#}");
        assert!(!staged_key_file(home.path()).exists());
    }

    #[test]
    fn key_rotation_refuses_a_malformed_audit_entry() {
        let home = TempDir::new().unwrap();
        let old_identity = crate::crypto::generate_identity();
        let new_identity = crate::crypto::generate_identity();
        let old_key = old_identity.to_string();
        record(
            home.path(),
            old_key.expose_secret().as_bytes(),
            "run",
            "valid",
        )
        .unwrap();
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(log_file(home.path()))
                .unwrap(),
            "malformed audit data"
        )
        .unwrap();

        let error = prepare_key_rotation(home.path(), &old_identity, &new_identity)
            .err()
            .expect("malformed audit must block rotation");
        assert!(error.to_string().contains("audit entry 2"), "{error:#}");
        assert!(!staged_key_file(home.path()).exists());
    }
}
