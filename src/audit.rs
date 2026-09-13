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
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// Keep the log tiny — trim to the most recent entries once it passes this.
const MAX_BYTES: u64 = 256 * 1024;
const WRAPPER_VERSION: u8 = 1;
const WRAPPER_AUTH_DOMAIN: &[u8] = b"envault audit key wrapper auth v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditKeyWrapper {
    version: u8,
    cipher: String,
    auth: String,
}

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
pub(crate) fn record_locked(home: &Path, key: &[u8], action: &str, detail: &str) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let entries = read_locked(home).unwrap_or_default();
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
    let entries = read_locked(home).unwrap_or_default();
    let last = entries.last().map(|e| e.hash.clone()).unwrap_or_default();
    write_head(home, key, entries.len(), &last)
}

pub(crate) fn read_locked(home: &Path) -> Result<Vec<Entry>> {
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
pub(crate) fn verify_locked(home: &Path, key: &[u8], entries: &[Entry]) -> Integrity {
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

fn wrapper_auth_key(identity: &age::x25519::Identity) -> [u8; 32] {
    let identity = identity.to_string();
    let mut digest = Sha256::new();
    digest.update(WRAPPER_AUTH_DOMAIN);
    digest.update(identity.expose_secret().as_bytes());
    digest.finalize().into()
}

fn wrapper_authenticator(
    identity: &age::x25519::Identity,
    version: u8,
    cipher: &str,
) -> HmacSha256 {
    let key = wrapper_auth_key(identity);
    let mut authenticator = HmacSha256::new_from_slice(&key).expect("hmac accepts any key length");
    authenticator.update(WRAPPER_AUTH_DOMAIN);
    authenticator.update(&[version]);
    authenticator.update(cipher.as_bytes());
    authenticator
}

fn wrap_key(identity: &age::x25519::Identity, key: &str) -> Result<String> {
    let cipher = crate::crypto::encrypt_value(&identity.to_public(), key)?;
    let auth = B64.encode(
        wrapper_authenticator(identity, WRAPPER_VERSION, &cipher)
            .finalize()
            .into_bytes(),
    );
    serde_json::to_string(&AuditKeyWrapper {
        version: WRAPPER_VERSION,
        cipher,
        auth,
    })
    .context("serializing the authenticated audit verification key")
}

fn unwrap_key(identity: &age::x25519::Identity, raw: &str) -> Result<String> {
    let wrapper: AuditKeyWrapper = serde_json::from_str(raw)
        .context("audit verification key authentication failed: invalid wrapper")?;
    if wrapper.version != WRAPPER_VERSION {
        bail!(
            "unsupported audit verification key wrapper version {}",
            wrapper.version
        );
    }
    let auth = B64
        .decode(&wrapper.auth)
        .context("decoding the audit verification key authentication tag")?;
    wrapper_authenticator(identity, wrapper.version, &wrapper.cipher)
        .verify_slice(&auth)
        .context("audit verification key authentication failed")?;
    crate::crypto::decrypt_value(identity, &wrapper.cipher)
        .context("decrypting the authenticated audit verification key")
}

/// Return the audit-MAC key for the active identity. Legacy vaults use the
/// identity itself until their first rotation migrates to a stable derived key;
/// that key is then authenticated and re-encrypted to each new identity.
pub(crate) fn verification_key_locked(
    home: &Path,
    identity: &age::x25519::Identity,
) -> Result<SecretString> {
    // Pending rotation is recovered by load_identity_locked before this call.
    // Never select an uncommitted staged wrapper independently of vault recovery.
    match std::fs::read_to_string(key_file(home)) {
        Ok(wrapper) => unwrap_key(identity, &wrapper).map(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(identity.to_string()),
        Err(error) => Err(error).context("reading the audit verification key"),
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
    #[cfg(test)]
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
pub(crate) fn prepare_key_rotation_locked(
    home: &Path,
    old_identity: &age::x25519::Identity,
    new_identity: &age::x25519::Identity,
) -> Result<Option<PreparedKeyRotation>> {
    let has_state = log_file(home).exists() || head_file(home).exists() || key_file(home).exists();
    if !has_state {
        return Ok(None);
    }

    let current_key = verification_key_locked(home, old_identity)?;
    let mut entries = read_locked(home)?;
    match verify_locked(home, current_key.expose_secret().as_bytes(), &entries) {
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

    let wrapper = wrap_key(new_identity, next_key.expose_secret())?;
    files.push(stage_file(
        staged_key_file(home),
        key_file(home),
        wrapper.as_bytes(),
    )?);

    Ok(Some(PreparedKeyRotation { files }))
}

// All production audit calls are made under vault.lock, after protected recovery.
// Downstream PR10 may add an audit lock only *after* vault.lock, and must use
// non-reacquiring helpers. This does not add PR10's pre-append verification.
const AUDIT_FILES: [&str; 3] = ["audit.log", "audit.head", "audit.key.age"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationSnapshot {
    version: u8,
    before: [Option<Vec<u8>>; 3],
    after: [Option<Vec<u8>>; 3],
}

fn optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading audit recovery state"),
    }
}

fn capture(home: &Path) -> Result<[Option<Vec<u8>>; 3]> {
    Ok([
        optional_bytes(&log_file(home))?,
        optional_bytes(&head_file(home))?,
        optional_bytes(&key_file(home))?,
    ])
}

fn verify_snapshot(state: &[Option<Vec<u8>>; 3], identity: &age::x25519::Identity) -> Result<()> {
    let key: SecretString = match &state[2] {
        Some(raw) => unwrap_key(identity, std::str::from_utf8(raw)?)?.into(),
        None => identity.to_string(),
    };
    let raw = state[0].as_deref().unwrap_or_default();
    let entries: Vec<Entry> = std::str::from_utf8(raw)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let key = key.expose_secret().as_bytes();
    for (index, entry) in entries.iter().enumerate() {
        anyhow::ensure!(
            entry_mac(key, &entry.ts, &entry.action, &entry.detail, &entry.prev) == entry.hash
                && (index == 0 || entry.prev == entries[index - 1].hash),
            "audit recovery snapshot chain verification failed"
        );
    }
    let last = entries.last().map(|e| e.hash.as_str()).unwrap_or("");
    match &state[1] {
        Some(head) => anyhow::ensure!(
            std::str::from_utf8(head)?.trim() == head_mac(key, entries.len(), last),
            "audit recovery snapshot anchor verification failed"
        ),
        None => anyhow::ensure!(
            entries.is_empty(),
            "audit recovery snapshot anchor is missing"
        ),
    }
    Ok(())
}

pub(crate) fn sync_rotation_directory(home: &Path) -> Result<()> {
    #[cfg(test)]
    directory_sync_test_error()?;
    #[cfg(unix)]
    std::fs::File::open(home)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = home; // Directory fsync is not portable; power-loss durability unverified.
    Ok(())
}

// Inject an I/O failure at the directory-sync operation itself, after callers
// have performed their rename/deletion. Failures remain active across retries.
#[cfg(test)]
thread_local! {
    static DIRECTORY_SYNC_FAILURE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static DIRECTORY_SYNC_ERRORS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn directory_sync_test_error() -> std::io::Result<()> {
    DIRECTORY_SYNC_FAILURE.with(|remaining| match remaining.get() {
        Some(0) => {
            DIRECTORY_SYNC_ERRORS.with(|count| count.set(count.get() + 1));
            Err(std::io::Error::other(
                "injected rotation directory sync failure",
            ))
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })
}

#[cfg(test)]
pub(crate) struct DirectorySyncFailure;

#[cfg(test)]
impl DirectorySyncFailure {
    pub(crate) fn after(successful_calls: usize) -> Self {
        DIRECTORY_SYNC_FAILURE.with(|remaining| {
            assert!(remaining.get().is_none());
            remaining.set(Some(successful_calls));
        });
        DIRECTORY_SYNC_ERRORS.with(|count| count.set(0));
        Self
    }

    pub(crate) fn errors(&self) -> usize {
        DIRECTORY_SYNC_ERRORS.with(|count| count.get())
    }
}

#[cfg(test)]
impl Drop for DirectorySyncFailure {
    fn drop(&mut self) {
        DIRECTORY_SYNC_FAILURE.with(|remaining| remaining.set(None));
    }
}

fn replace_synced(home: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let target = home.join(name);
    let staged = home.join(format!("{name}.restore"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&staged)?;
    crate::platform::set_mode(&staged, 0o600)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(staged, target)?;
    sync_rotation_directory(home)
}

/// Called before any credential replacement, under vault.lock. Only the hash
/// goes into protected credentials; potentially large logs stay in this file.
/// No private identity or raw stable key is serialized in this snapshot.
pub(crate) fn prepare_snapshot_locked(
    home: &Path,
    old: &age::x25519::Identity,
    new: &age::x25519::Identity,
) -> Result<String> {
    let before = capture(home)?;
    verify_snapshot(&before, old)?;
    let mut after = before.clone();
    if let Some(prepared) = prepare_key_rotation_locked(home, old, new)? {
        for file in prepared.files {
            let index = AUDIT_FILES
                .iter()
                .position(|name| home.join(name) == file.target)
                .context("unexpected audit rotation target")?;
            after[index] = Some(std::fs::read(&file.staged)?);
            // Staged files are not authoritative and never used by key selection.
            std::fs::remove_file(file.staged)?;
        }
    }
    verify_snapshot(&after, new)?;
    let bytes = serde_json::to_vec(&RotationSnapshot {
        version: 1,
        before,
        after,
    })?;
    let digest = hex(&Sha256::digest(&bytes));
    replace_synced(home, "audit.rotation.json", &bytes)?;
    anyhow::ensure!(
        std::fs::read(home.join("audit.rotation.json"))? == bytes,
        "audit recovery snapshot was not persisted"
    );
    Ok(digest)
}

/// Recovery accepts recorded pre/post file states, including a partial install.
/// Unknown bytes fail closed before any mutation and retain the protected keys.
pub(crate) fn recover_snapshot_locked(
    home: &Path,
    digest: &str,
    activated: bool,
    identity: &age::x25519::Identity,
) -> Result<()> {
    let bytes = std::fs::read(home.join("audit.rotation.json"))?;
    anyhow::ensure!(
        hex(&Sha256::digest(&bytes)) == digest,
        "audit recovery snapshot digest mismatch"
    );
    let snapshot: RotationSnapshot = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(snapshot.version == 1, "unsupported audit recovery snapshot");
    let target = if activated {
        &snapshot.after
    } else {
        &snapshot.before
    };
    verify_snapshot(target, identity)?;
    let current = capture(home)?;
    for (index, value) in current.iter().enumerate() {
        anyhow::ensure!(
            value == &snapshot.before[index] || value == &snapshot.after[index],
            "audit files differ from protected recovery state; preserve files for recovery"
        );
    }
    for (index, name) in AUDIT_FILES.iter().enumerate() {
        if current[index] != target[index] {
            match &target[index] {
                Some(raw) => replace_synced(home, name, raw)?,
                None => {
                    std::fs::remove_file(home.join(name))?;
                    sync_rotation_directory(home)?;
                }
            }
        }
        #[cfg(test)]
        recovery_test_boundary(index)?;
    }
    let installed = capture(home)?;
    anyhow::ensure!(&installed == target, "audit recovery installation mismatch");
    verify_snapshot(&installed, identity)
}

#[cfg(test)]
thread_local! {
    static RECOVERY_FAILURE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn recovery_test_boundary(index: usize) -> Result<()> {
    RECOVERY_FAILURE.with(|failure| {
        if failure.get() == Some(index) {
            failure.set(None);
            bail!("injected audit recovery interruption");
        }
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn fail_recovery_after(index: usize) {
    RECOVERY_FAILURE.with(|failure| failure.set(Some(index)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const KEY: &[u8] = b"test-identity-secret-bytes";

    #[test]
    fn records_and_verifies() {
        let home = TempDir::new().unwrap();
        record_locked(home.path(), KEY, "run", "npm test").unwrap();
        record_locked(home.path(), KEY, "reveal", "openrouter").unwrap();
        let entries = read_locked(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev, entries[0].hash);
        assert_eq!(verify_locked(home.path(), KEY, &entries), Integrity::Ok);
    }

    #[test]
    fn detects_edit() {
        let home = TempDir::new().unwrap();
        record_locked(home.path(), KEY, "run", "a").unwrap();
        record_locked(home.path(), KEY, "run", "b").unwrap();
        let mut entries = read_locked(home.path()).unwrap();
        entries[0].detail = "TAMPERED".into();
        assert_eq!(
            verify_locked(home.path(), KEY, &entries),
            Integrity::Broken(0)
        );
    }

    #[test]
    fn detects_interior_deletion() {
        let home = TempDir::new().unwrap();
        for d in ["a", "b", "c"] {
            record_locked(home.path(), KEY, "run", d).unwrap();
        }
        let mut entries = read_locked(home.path()).unwrap();
        entries.remove(1);
        assert_eq!(
            verify_locked(home.path(), KEY, &entries),
            Integrity::Broken(1)
        );
    }

    #[test]
    fn detects_tail_truncation_via_head_anchor() {
        let home = TempDir::new().unwrap();
        for d in ["a", "b", "c"] {
            record_locked(home.path(), KEY, "run", d).unwrap();
        }
        // delete the last line but leave a valid-looking chain
        let raw = std::fs::read_to_string(log_file(home.path())).unwrap();
        let kept: Vec<&str> = raw.lines().take(2).collect();
        std::fs::write(log_file(home.path()), format!("{}\n", kept.join("\n"))).unwrap();
        let entries = read_locked(home.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            verify_locked(home.path(), KEY, &entries),
            Integrity::HeadMismatch
        );
    }

    #[test]
    fn cannot_forge_without_key() {
        let home = TempDir::new().unwrap();
        record_locked(home.path(), KEY, "run", "a").unwrap();
        let entries = read_locked(home.path()).unwrap();
        // an attacker who guesses the algorithm but not the key can't verify
        assert_eq!(
            verify_locked(home.path(), b"wrong-key", &entries),
            Integrity::Broken(0)
        );
    }

    #[test]
    fn unauthorized_wrapper_replacement_is_rejected() {
        let home = TempDir::new().unwrap();
        let identity = crate::crypto::generate_identity();
        let attacker_key = "synthetic-attacker-chosen-audit-key";
        let forged = crate::crypto::encrypt_value(&identity.to_public(), attacker_key).unwrap();
        std::fs::write(key_file(home.path()), forged).unwrap();

        let error = verification_key_locked(home.path(), &identity)
            .expect_err("a public-recipient-only replacement must be rejected");
        assert!(format!("{error:#}").contains("authentication"), "{error:#}");
    }

    #[test]
    fn authenticated_wrapper_rejects_cipher_replacement() {
        let identity = crate::crypto::generate_identity();
        let mut wrapper: AuditKeyWrapper =
            serde_json::from_str(&wrap_key(&identity, "legitimate-audit-key").unwrap()).unwrap();
        wrapper.cipher = crate::crypto::encrypt_value(
            &identity.to_public(),
            "synthetic-attacker-chosen-audit-key",
        )
        .unwrap();

        let error = unwrap_key(&identity, &serde_json::to_string(&wrapper).unwrap())
            .expect_err("changing the public-key ciphertext must invalidate its authentication");
        assert!(error.to_string().contains("authentication"), "{error:#}");
    }

    #[test]
    fn entries_remain_verifiable_after_key_rotation() {
        let home = TempDir::new().unwrap();
        let old_identity = crate::crypto::generate_identity();
        let new_identity = crate::crypto::generate_identity();
        let old_key = old_identity.to_string();
        record_locked(
            home.path(),
            old_key.expose_secret().as_bytes(),
            "run",
            "before rotation",
        )
        .unwrap();
        let original_entries = read_locked(home.path()).unwrap();

        let prepared = prepare_key_rotation_locked(home.path(), &old_identity, &new_identity)
            .unwrap()
            .unwrap();
        let old_key_while_staged = verification_key_locked(home.path(), &old_identity).unwrap();
        assert_eq!(
            old_key_while_staged.expose_secret(),
            old_key.expose_secret(),
            "staging alone must not switch a legacy vault's audit key"
        );
        prepared.activate().unwrap();

        let entries = read_locked(home.path()).unwrap();
        let new_key = verification_key_locked(home.path(), &new_identity).unwrap();
        assert_eq!(
            verify_locked(home.path(), new_key.expose_secret().as_bytes(), &entries),
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
        let stored_key = unwrap_key(&new_identity, &wrapped).unwrap();
        assert_ne!(stored_key, *old_key.expose_secret());

        let newest_identity = crate::crypto::generate_identity();
        let migrated_log = std::fs::read(log_file(home.path())).unwrap();
        prepare_key_rotation_locked(home.path(), &new_identity, &newest_identity)
            .unwrap()
            .unwrap()
            .activate()
            .unwrap();
        let newest_key = verification_key_locked(home.path(), &newest_identity).unwrap();
        assert_eq!(
            verify_locked(home.path(), newest_key.expose_secret().as_bytes(), &entries),
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
            record_locked(
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

        let error = prepare_key_rotation_locked(home.path(), &old_identity, &new_identity)
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
        record_locked(
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

        let error = prepare_key_rotation_locked(home.path(), &old_identity, &new_identity)
            .err()
            .expect("malformed audit must block rotation");
        assert!(error.to_string().contains("audit entry 2"), "{error:#}");
        assert!(!staged_key_file(home.path()).exists());
    }
}
