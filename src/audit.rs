//! Lightweight, HMAC-chained audit log of every decryption.
//!
//! Cheap (one appended line per event, no daemon), small (auto-trimmed to a
//! size cap), and tamper-evident: each entry carries an HMAC — keyed by the
//! Keychain-protected identity — over its fields and the previous entry's MAC,
//! and a separate MAC'd "head" anchor records the entry count + last MAC so
//! truncation/deletion is detectable too. An adversary who cannot read the
//! Keychain identity cannot forge, edit, or silently trim the log. It makes
//! access visible; it does not prevent it.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
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
    use std::io::Write;
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
    Ok(raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect())
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
}
