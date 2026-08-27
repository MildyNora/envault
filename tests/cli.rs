use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn version_flag_works() {
    Command::cargo_bin("envault")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("envault"));
}

/// Isolated envault home + project dir. Every Command gets ENVAULT_HOME and
/// ENVAULT_IDENTITY_FILE pointed inside a tempdir, so tests never touch the
/// real vault or the macOS Keychain, and are parallel-safe (env is set
/// per-child-process, not on the test process).
pub struct TestEnv {
    pub home: TempDir,
    pub project: TempDir,
}

impl TestEnv {
    pub fn new() -> TestEnv {
        TestEnv {
            home: TempDir::new().unwrap(),
            project: TempDir::new().unwrap(),
        }
    }

    pub fn identity_file(&self) -> PathBuf {
        self.home.path().join("test-identity.txt")
    }

    pub fn envault(&self) -> Command {
        let mut c = Command::cargo_bin("envault").unwrap();
        c.env("ENVAULT_HOME", self.home.path())
            .env("ENVAULT_IDENTITY_FILE", self.identity_file())
            .current_dir(self.project.path());
        c
    }

    pub fn init(&self) {
        self.envault().arg("init").assert().success();
    }
}

#[test]
fn init_creates_vault_recipient_and_identity() {
    let te = TestEnv::new();
    te.envault()
        .arg("init")
        .assert()
        .success()
        .stdout(predicates::str::contains("Initialized"));
    assert!(te.home.path().join("vault.json").exists());
    assert!(te.home.path().join("recipient.txt").exists());
    assert!(te.identity_file().exists());
}

#[test]
fn init_twice_fails() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicates::str::contains("already initialized"));
}
