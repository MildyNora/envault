//! Lightweight, hash-chained audit log of every decryption.
//!
//! Design goals: cheap (one line appended per event, no daemon), small
//! (auto-trimmed to a size cap), and tamper-evident (each entry carries the
//! previous entry's hash, so deletion or edits break the chain and show up in
//! `verify`). It does not *prevent* misuse — it makes access visible.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Keep the log tiny — trim to the most recent entries once it passes this.
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub action: String, // run | reveal | copy | fill | rotate
    pub detail: String, // the command run, or the alias accessed
    pub prev: String,   // hex hash of the previous entry ("" for the first)
    pub hash: String,   // hex hash of this entry's (ts, action, detail, prev)
}

fn log_file(home: &Path) -> PathBuf {
    home.join("audit.log")
}

fn hash_entry(ts: &str, action: &str, detail: &str, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(ts.as_bytes());
    h.update([0]);
    h.update(action.as_bytes());
    h.update([0]);
    h.update(detail.as_bytes());
    h.update([0]);
    h.update(prev.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Append an event. Best-effort: a logging failure must never break the
/// operation being logged, so errors are swallowed by the caller.
pub fn record(home: &Path, action: &str, detail: &str) -> Result<()> {
    let entries = read(home).unwrap_or_default();
    let prev = entries.last().map(|e| e.hash.clone()).unwrap_or_default();
    let ts = crate::store::now_rfc3339();
    let hash = hash_entry(&ts, action, detail, &prev);
    let entry = Entry {
        ts,
        action: action.to_string(),
        detail: detail.to_string(),
        prev,
        hash,
    };

    let path = log_file(home);
    std::fs::create_dir_all(home)?;
    let mut line = serde_json::to_string(&entry)?;
    line.push('\n');

    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    f.write_all(line.as_bytes())?;
    drop(f);
    crate::platform::set_mode(&path, 0o600)?;

    trim(home)?;
    Ok(())
}

/// Trim the oldest lines once the file grows past the cap, keeping the log
/// small. (The chain's first retained entry then references a dropped one —
/// that's a normal rotation boundary, distinct from tampering.)
fn trim(home: &Path) -> Result<()> {
    let path = log_file(home);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if meta.len() <= MAX_BYTES {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)?;
    let lines: Vec<&str> = raw.lines().collect();
    // drop the oldest half
    let keep = &lines[lines.len() / 2..];
    std::fs::write(&path, format!("{}\n", keep.join("\n")))?;
    crate::platform::set_mode(&path, 0o600)?;
    Ok(())
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

/// Verify the hash-chain. Returns the index of the first broken entry, if any
/// (a self-hash mismatch = an edited entry; a prev mismatch = a removed entry).
/// The first entry after a rotation boundary is allowed to reference an absent
/// predecessor, so we only flag a break when an entry's own hash is wrong or
/// its `prev` disagrees with the *present* previous line.
pub fn first_tamper(entries: &[Entry]) -> Option<usize> {
    for (i, e) in entries.iter().enumerate() {
        if hash_entry(&e.ts, &e.action, &e.detail, &e.prev) != e.hash {
            return Some(i); // this entry was edited
        }
        if i > 0 && e.prev != entries[i - 1].hash {
            return Some(i); // an entry between i-1 and i was removed
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn records_and_chains() {
        let home = TempDir::new().unwrap();
        record(home.path(), "run", "npm test").unwrap();
        record(home.path(), "reveal", "openrouter").unwrap();
        let entries = read(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev, ""); // first has no predecessor
        assert_eq!(entries[1].prev, entries[0].hash); // chained
        assert_eq!(first_tamper(&entries), None); // intact
    }

    #[test]
    fn detects_edited_entry() {
        let home = TempDir::new().unwrap();
        record(home.path(), "run", "a").unwrap();
        record(home.path(), "run", "b").unwrap();
        let mut entries = read(home.path()).unwrap();
        entries[0].detail = "TAMPERED".into(); // edit content, keep old hash
        assert_eq!(first_tamper(&entries), Some(0));
    }

    #[test]
    fn detects_removed_entry() {
        let home = TempDir::new().unwrap();
        record(home.path(), "run", "a").unwrap();
        record(home.path(), "run", "b").unwrap();
        record(home.path(), "run", "c").unwrap();
        let mut entries = read(home.path()).unwrap();
        entries.remove(1); // drop the middle entry
                           // now entries[1].prev points at entries[0]'s... no, at the removed one
        assert_eq!(first_tamper(&entries), Some(1));
    }
}
