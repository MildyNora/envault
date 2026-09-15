use assert_cmd::Command;
#[cfg(unix)]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::PathBuf;
#[cfg(unix)]
use std::time::{Duration, Instant};
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

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
#[test]
fn dashboard_startup_ignores_replaced_public_recipient() {
    use base64::Engine;
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    let attacker = age::x25519::Identity::generate();
    for mirror in [
        Some(attacker.to_public().to_string()),
        Some("malformed public mirror".into()),
        None,
    ] {
        let te = TestEnv::new();
        te.init();
        if let Some(mirror) = mirror {
            std::fs::write(te.home.path().join("recipient.txt"), mirror).unwrap();
        } else {
            std::fs::remove_file(te.home.path().join("recipient.txt")).unwrap();
        }
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 30,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut cmd = CommandBuilder::new(assert_cmd::cargo::cargo_bin("envault"));
        cmd.env("ENVAULT_HOME", te.home.path());
        cmd.env("ENVAULT_IDENTITY_FILE", te.identity_file());
        cmd.env("TERM", "xterm-256color");
        cmd.cwd(te.project.path());
        let mut child = pair.slave.spawn_command(cmd).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let mut writer = pair.master.take_writer().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let wait_for = |needle: &[u8]| -> bool {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut output = Vec::new();
            while Instant::now() < deadline {
                match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(bytes) => output.extend(bytes),
                    Err(_) => return false,
                }
                if output.windows(needle.len()).any(|s| s == needle) {
                    return true;
                }
            }
            false
        };
        let ready = wait_for(b"envault");
        if ready {
            writer
                .write_all(b"adashboard-key\tsynthetic-dashboard-value\r")
                .unwrap();
        }
        let saved = ready && wait_for(b"added");
        // Always terminate the isolated dashboard, including on a failed assertion.
        child.kill().ok();
        child.wait().ok();
        drop(writer);
        drop(pair.master);
        reader_thread.join().unwrap();
        assert!(ready && saved, "dashboard did not reach the save outcome");
        let vault: serde_json::Value =
            serde_json::from_slice(&std::fs::read(te.home.path().join("vault.json")).unwrap())
                .unwrap();
        let cipher = base64::engine::general_purpose::STANDARD
            .decode(vault["secrets"][0]["cipher"].as_str().unwrap())
            .unwrap();
        let identity = age::x25519::Identity::from_str(
            std::fs::read_to_string(te.identity_file()).unwrap().trim(),
        )
        .unwrap();
        assert!(
            age::decrypt(&attacker, &cipher).is_err(),
            "public recipient file redirected encryption"
        );
        assert_eq!(
            age::decrypt(&identity, &cipher).unwrap(),
            b"synthetic-dashboard-value"
        );
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
fn separate_homes_keep_separate_identities() {
    let first_home = TempDir::new().unwrap();
    let second_home = TempDir::new().unwrap();
    let first_project = TempDir::new().unwrap();
    let second_project = TempDir::new().unwrap();
    let credentials = TempDir::new().unwrap();
    let identity_file = credentials.path().join("shared-identity.txt");

    let command = |home: &std::path::Path, project: &std::path::Path| {
        let mut command = Command::cargo_bin("envault").unwrap();
        command
            .env("ENVAULT_HOME", home)
            // New builds model separate Keychain accounts in this directory.
            .env("ENVAULT_IDENTITY_DIR", credentials.path())
            // Old builds ignore the directory and collide in this one file.
            .env("ENVAULT_IDENTITY_FILE", &identity_file)
            .current_dir(project);
        command
    };

    command(first_home.path(), first_project.path())
        .arg("init")
        .assert()
        .success();
    command(first_home.path(), first_project.path())
        .args(["add", "first-key", "--stdin"])
        .write_stdin("SYNTHETIC-FIRST-HOME-9988\n")
        .assert()
        .success();

    command(second_home.path(), second_project.path())
        .arg("init")
        .assert()
        .success();
    command(second_home.path(), second_project.path())
        .args(["add", "second-key", "--stdin"])
        .write_stdin("SYNTHETIC-SECOND-HOME-7766\n")
        .assert()
        .success();
    assert!(
        !identity_file.exists(),
        "the legacy global slot stays unused"
    );
    assert_eq!(
        std::fs::read_dir(credentials.path()).unwrap().count(),
        2,
        "each home must have its own credential"
    );

    command(first_home.path(), first_project.path())
        .args([
            "run",
            "--env",
            "FIRST=first-key",
            "--",
            "sh",
            "-c",
            "test \"$FIRST\" = SYNTHETIC-FIRST-HOME-9988",
        ])
        .assert()
        .success();
    command(second_home.path(), second_project.path())
        .args([
            "run",
            "--env",
            "SECOND=second-key",
            "--",
            "sh",
            "-c",
            "test \"$SECOND\" = SYNTHETIC-SECOND-HOME-7766",
        ])
        .assert()
        .success();
}

#[test]
fn moving_a_vault_keeps_its_identity_association() {
    let parent = TempDir::new().unwrap();
    let original_home = parent.path().join("original-home");
    let moved_home = parent.path().join("moved-home");
    std::fs::create_dir(&original_home).unwrap();
    let project = TempDir::new().unwrap();
    let credentials = TempDir::new().unwrap();
    let legacy_identity = credentials.path().join("legacy-identity.txt");

    let command = |home: &std::path::Path| {
        let mut command = Command::cargo_bin("envault").unwrap();
        command
            .env("ENVAULT_HOME", home)
            .env("ENVAULT_IDENTITY_DIR", credentials.path())
            .env("ENVAULT_IDENTITY_FILE", &legacy_identity)
            .current_dir(project.path());
        command
    };

    command(&original_home).arg("init").assert().success();
    command(&original_home)
        .args(["add", "move-test", "--stdin"])
        .write_stdin("SYNTHETIC-MOVE-IDENTITY-4477\n")
        .assert()
        .success();

    std::fs::rename(&original_home, &moved_home).unwrap();
    command(&moved_home)
        .args([
            "run",
            "--env",
            "MOVED=move-test",
            "--",
            "sh",
            "-c",
            "test \"$MOVED\" = SYNTHETIC-MOVE-IDENTITY-4477",
        ])
        .assert()
        .success();
}

#[test]
fn init_refuses_to_replace_an_identity_when_the_vault_is_missing() {
    let te = TestEnv::new();
    te.init();
    let identity_before = std::fs::read(te.identity_file()).unwrap();
    let recipient_before = std::fs::read(te.home.path().join("recipient.txt")).unwrap();
    std::fs::remove_file(te.home.path().join("vault.json")).unwrap();

    te.envault()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicates::str::contains("recovery required"));
    assert_eq!(std::fs::read(te.identity_file()).unwrap(), identity_before);
    assert_eq!(
        std::fs::read(te.home.path().join("recipient.txt")).unwrap(),
        recipient_before
    );
}

#[test]
fn init_names_the_current_platform_credential_store() {
    let te = TestEnv::new();
    let output = te
        .envault()
        .arg("init")
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let expected = if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "linux") {
        "Secret Service"
    } else {
        "OS credential store"
    };
    assert!(stdout.contains(expected), "got: {stdout}");
    if !cfg!(target_os = "macos") {
        assert!(!stdout.contains("macOS Keychain"), "got: {stdout}");
    }
}

#[test]
fn doctor_reports_local_absence_without_creating_files() {
    let te = TestEnv::new();
    assert!(std::fs::read_dir(te.home.path()).unwrap().next().is_none());

    te.envault()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicates::str::contains("local checks passed"))
        .stdout(predicates::str::contains("safe reinitialization"));

    assert!(std::fs::read_dir(te.home.path()).unwrap().next().is_none());
}

#[test]
fn doctor_is_read_only_and_never_renders_secret_material() {
    let te = TestEnv::new();
    te.init();
    let plaintext = "synthetic-doctor-secret-97531";
    te.envault()
        .args(["add", "doctor-key", "--stdin"])
        .write_stdin(format!("{plaintext}\n"))
        .assert()
        .success();

    let identity_dir = te.home.path().join("identity-must-not-be-opened");
    std::fs::create_dir(&identity_dir).unwrap();
    let snapshot = snapshot_files(te.home.path());

    let mut command = te.envault();
    command.env("ENVAULT_IDENTITY_FILE", &identity_dir);
    let output = command
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(plaintext), "got: {stdout}");
    assert!(!stdout.contains("AGE-SECRET-KEY"), "got: {stdout}");
    assert!(!stdout.contains("cipher"), "got: {stdout}");
    assert!(stdout.contains("not-checked"), "got: {stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["local_checks_passed"], true);
    assert!(report.get("healthy").is_none());
    assert_eq!(snapshot_files(te.home.path()), snapshot);
}

fn snapshot_files(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            files.push((
                entry.path().strip_prefix(root).unwrap().to_path_buf(),
                std::fs::read(entry.path()).unwrap(),
            ));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

#[test]
fn add_then_ls_shows_alias_but_never_value() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "openrouter", "--label", "OpenRouter key", "--stdin"])
        .write_stdin("sk-or-v1-abcdef123456\n")
        .assert()
        .success();

    // ls --json lists it
    let out = te.envault().args(["ls", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(rows[0]["alias"], "openrouter");
    assert_eq!(rows[0]["label"], "OpenRouter key");
    assert!(
        rows[0].get("cipher").is_none(),
        "ls must not expose ciphers"
    );

    // the plaintext value exists nowhere on disk
    let vault_raw = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();
    assert!(!vault_raw.contains("sk-or-v1-abcdef123456"));
    // and never in ls output
    assert!(!stdout.contains("sk-or-v1-abcdef123456"));
}

#[test]
fn add_rejects_bad_alias_and_duplicates() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "Bad_Alias", "--stdin"])
        .write_stdin("value-123456\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("kebab-case"));

    te.envault()
        .args(["add", "dup", "--stdin"])
        .write_stdin("value-123456\n")
        .assert()
        .success();
    te.envault()
        .args(["add", "dup", "--stdin"])
        .write_stdin("value-123456\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("already exists"));
}

#[test]
fn link_writes_manifest_and_validates_alias() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "openrouter", "--stdin"])
        .write_stdin("sk-or-value-1\n")
        .assert()
        .success();

    te.envault()
        .args(["link", "OPENROUTER_API_KEY", "openrouter"])
        .assert()
        .success();
    let manifest = std::fs::read_to_string(te.project.path().join("envault.toml")).unwrap();
    assert!(manifest.contains("OPENROUTER_API_KEY = \"openrouter\""));

    te.envault()
        .args(["link", "X_KEY", "does-not-exist"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("envault add"));
}

#[test]
fn run_injects_and_masks_output() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "my-key", "--stdin"])
        .write_stdin("supersecret-value-9\n")
        .assert()
        .success();
    te.envault()
        .args(["link", "MY_KEY", "my-key"])
        .assert()
        .success();

    let out = te
        .envault()
        .args(["run", "--", "sh", "-c", "echo got: $MY_KEY"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("got: [envault:my-key]"),
        "stdout was: {stdout}"
    );
    assert!(!stdout.contains("supersecret-value-9"));
}

#[cfg(unix)]
#[test]
fn run_masks_longer_secret_when_pty_output_splits_after_its_prefix() {
    let te = TestEnv::new();
    te.init();
    for (alias, value) in [
        ("prefix-key", "SYNTHETIC-PREFIX"),
        ("long-key", "SYNTHETIC-PREFIX-TAIL-9988"),
    ] {
        te.envault()
            .args(["add", alias, "--stdin"])
            .write_stdin(value)
            .assert()
            .success();
    }

    // Keep a real terminal input open so this exercises the interactive PTY
    // path without triggering the nonterminal stdin bridge's EOF echo.
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_envault"));
    cmd.args([
        "run",
        "--env",
        "PREFIX_KEY=prefix-key",
        "--env",
        "LONG_KEY=long-key",
        "--",
        "sh",
        "-c",
        "printf %s \"$PREFIX_KEY\"; sleep 0.1; printf %s '-TAIL-9988'",
    ]);
    cmd.cwd(te.project.path());
    cmd.env("ENVAULT_HOME", te.home.path());
    cmd.env("ENVAULT_IDENTITY_FILE", te.identity_file());

    let mut child = pair.slave.spawn_command(cmd).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let writer = pair.master.take_writer().unwrap();
    let reader_thread = std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
        }
        output
    });

    let status = child.wait().unwrap();
    let output = reader_thread.join().unwrap();
    drop(writer);
    assert!(status.success());
    assert_eq!(output, b"[envault:long-key]");
}

#[test]
fn run_passes_exit_code_through() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["run", "--allow-missing", "--", "sh", "-c", "exit 3"])
        .assert()
        .code(3);
}

#[cfg(unix)]
#[test]
fn run_masks_multiline_secrets_after_pty_newline_conversion() {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::Read;

    let te = TestEnv::new();
    te.init();
    for (alias, value) in [
        ("lf-key", "SYNTHETIC-FIRST-9988\nSYNTHETIC-LAST-7766"),
        ("crlf-key", "SYNTHETIC-FIRST-9988\r\nSYNTHETIC-LAST-7766"),
    ] {
        te.envault()
            .args(["add", alias, "--stdin"])
            .write_stdin(value)
            .assert()
            .success();
        // Exercise the actual PTY with translation enabled and disabled.
        for mode in ["onlcr", "-onlcr"] {
            let script = format!(
                "stty opost {mode}; printf 'before|%s|after' \"$MULTILINE_KEY\"; \
                 printf '|stderr:%s|' \"$MULTILINE_KEY\" >&2"
            );
            let pair = native_pty_system()
                .openpty(PtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .unwrap();
            // Keep envault on its PTY path, without translating its output again.
            let mut cmd = CommandBuilder::new("sh");
            cmd.args([
                "-c",
                "stty -onlcr && exec \"$@\"",
                "sh",
                env!("CARGO_BIN_EXE_envault"),
                "run",
                "--env",
                &format!("MULTILINE_KEY={alias}"),
                "--",
                "sh",
                "-c",
                &script,
            ]);
            cmd.cwd(te.project.path());
            cmd.env("ENVAULT_HOME", te.home.path());
            cmd.env("ENVAULT_IDENTITY_FILE", te.identity_file());
            let mut child = pair.slave.spawn_command(cmd).unwrap();
            drop(pair.slave);
            let mut reader = pair.master.try_clone_reader().unwrap();
            let writer = pair.master.take_writer().unwrap();
            let reader_thread = std::thread::spawn(move || {
                let mut output = Vec::new();
                reader.read_to_end(&mut output).unwrap();
                output
            });
            let status = child.wait().unwrap();
            let output = reader_thread.join().unwrap();
            // Dropping the writer sends EOF bytes; keep it open through exit.
            drop(writer);

            assert!(status.success(), "alias {alias}, mode {mode}");
            assert_eq!(
                output,
                format!("before|[envault:{alias}]|after|stderr:[envault:{alias}]|").into_bytes(),
                "alias {alias}, mode {mode}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn run_streams_short_interactive_prompt_before_input() {
    const PROMPT: &[u8] = b"Password: ";

    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "prompt-secret", "--stdin"])
        .write_stdin("SYNTHETIC-SECRET-PROMPT-9988\n")
        .assert()
        .success();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_envault"));
    cmd.args([
        "run",
        "--env",
        "TEST_SECRET=prompt-secret",
        "--",
        "sh",
        "-c",
        "printf 'Password: '; IFS= read -r reply; printf '\\naccepted\\n'",
    ]);
    cmd.cwd(te.project.path());
    cmd.env("ENVAULT_HOME", te.home.path());
    cmd.env("ENVAULT_IDENTITY_FILE", te.identity_file());

    let mut child = pair.slave.spawn_command(cmd).unwrap();
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().unwrap();
    let mut writer = pair.master.take_writer().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) if tx.send(buf[..n].to_vec()).is_err() => break,
                Ok(_) => {}
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut output_before_input = Vec::new();
    while Instant::now() < deadline
        && !output_before_input
            .windows(PROMPT.len())
            .any(|w| w == PROMPT)
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(chunk) => output_before_input.extend(chunk),
            Err(_) => break,
        }
    }
    let prompt_was_visible = output_before_input
        .windows(PROMPT.len())
        .any(|w| w == PROMPT);

    writer.write_all(b"answer\n").unwrap();
    writer.flush().unwrap();
    let status = child.wait().unwrap();
    drop(writer);
    reader_thread.join().unwrap();

    assert!(status.success());
    assert!(
        prompt_was_visible,
        "prompt was still hidden while the child waited for input; output: {:?}",
        String::from_utf8_lossy(&output_before_input)
    );
}

#[test]
fn run_fails_listing_all_missing_aliases() {
    let te = TestEnv::new();
    te.init();
    std::fs::write(
        te.project.path().join("envault.toml"),
        "A_KEY = \"nope-a\"\nB_KEY = \"nope-b\"\n",
    )
    .unwrap();
    te.envault()
        .args(["run", "--", "true"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("nope-a"))
        .stderr(predicates::str::contains("nope-b"));
}

#[test]
fn run_extra_env_flag_maps_alias() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "extra", "--stdin"])
        .write_stdin("extra-value-123\n")
        .assert()
        .success();
    let out = te
        .envault()
        .args([
            "run",
            "--env",
            "EXTRA=extra",
            "--",
            "sh",
            "-c",
            "echo e=$EXTRA",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("e=[envault:extra]"), "stdout was: {stdout}");
}

#[test]
fn import_dotenv_encrypts_links_and_reports() {
    let te = TestEnv::new();
    te.init();
    let env_file = te.project.path().join(".env");
    std::fs::write(
        &env_file,
        "OPENROUTER_API_KEY=sk-or-import-1\nDB_PASSWORD=hunter22222\n",
    )
    .unwrap();

    te.envault()
        .args(["import", ".env"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Imported 2"))
        .stdout(predicates::str::contains("rm .env"));

    // aliases created (kebab-case of var names)
    let out = te.envault().args(["ls", "--json"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("openrouter-api-key"));
    assert!(stdout.contains("db-password"));

    // manifest linked
    let manifest = std::fs::read_to_string(te.project.path().join("envault.toml")).unwrap();
    assert!(manifest.contains("OPENROUTER_API_KEY = \"openrouter-api-key\""));
    assert!(manifest.contains("DB_PASSWORD = \"db-password\""));

    // plaintext not in the vault; original file untouched (user deletes it)
    let vault_raw = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();
    assert!(!vault_raw.contains("sk-or-import-1"));
    assert!(env_file.exists());

    // second import skips existing aliases instead of failing
    te.envault()
        .args(["import", ".env"])
        .assert()
        .success()
        .stdout(predicates::str::contains("skipped 2"));
}

#[test]
fn import_malformed_dotenv_hides_contents_and_leaves_files_unchanged() {
    for malformed in [
        "TOKEN=\"SYNTHETIC-SECRET-9988\n",
        "TOKEN='SYNTHETIC-SECRET-9988\n",
        "TOKEN=SYNTHETIC-SECRET-9988 trailing\n",
        "BAD-KEY=SYNTHETIC-SECRET-9988\n",
        "TOKEN=\"SYNTHETIC-SECRET-9988\nSECOND=SYNTHETIC-SECOND-9977\n",
    ] {
        let te = TestEnv::new();
        te.init();
        let env_file = te.project.path().join(".env");
        let contents = format!("VALID_TOKEN=SYNTHETIC-VALID-9966\n{malformed}");
        std::fs::write(&env_file, &contents).unwrap();
        let vault_path = te.home.path().join("vault.json");
        let vault_before = std::fs::read(&vault_path).unwrap();

        // Exercise main's full anyhow error-chain formatting, not just Display
        // on an outer context that could hide a secret-bearing inner error.
        te.envault()
            .args(["import", ".env"])
            .assert()
            .code(1)
            .stdout("")
            .stderr("error: parsing dotenv entry failed (contents omitted)\n");

        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
        assert!(!te.project.path().join("envault.toml").exists());
        assert_eq!(std::fs::read_to_string(&env_file).unwrap(), contents);
    }
}

#[test]
fn import_invalid_utf8_hides_contents() {
    let te = TestEnv::new();
    te.init();
    std::fs::write(
        te.project.path().join(".env"),
        b"TOKEN=SYNTHETIC-SECRET-9988\xff\n",
    )
    .unwrap();
    te.envault()
        .args(["import", ".env"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: parsing dotenv entry failed (contents omitted)\n");
}

#[test]
fn import_missing_file_keeps_reading_context() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["import", "missing.env"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicates::str::contains("reading missing.env"));
}

#[test]
fn guard_check_blocks_vault_reads_and_allows_normal() {
    let te = TestEnv::new();
    te.envault()
        .arg("guard-check")
        .write_stdin(format!(
            "{{\"tool_name\":\"Read\",\"tool_input\":{{\"file_path\":\"{}/vault.json\"}}}}",
            te.home.path().display()
        ))
        .assert()
        .code(2)
        .stderr(predicates::str::contains("off-limits"));

    te.envault()
        .arg("guard-check")
        .write_stdin("{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"envault ls --json\"}}")
        .assert()
        .code(0);

    te.envault()
        .arg("guard-check")
        .write_stdin("not json at all")
        .assert()
        .code(0); // fail open
}

#[test]
fn bare_envault_without_tty_refuses_with_hint() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .assert()
        .failure()
        .stderr(predicates::str::contains("terminal"));
}

mod mock_cdp {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Minimal CDP double: one HTTP listener answering /json/list, one
    /// websocket listener recording every message and answering
    /// {"result":{"result":{"value":"OK"}}}. Returns (http_base, received_messages).
    pub fn start(page_url: &str) -> (String, Arc<Mutex<Vec<String>>>) {
        let ws_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let ws_port = ws_listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_ws = received.clone();
        std::thread::spawn(move || {
            for stream in ws_listener.incoming().flatten() {
                let mut ws = match tungstenite::accept(stream) {
                    Ok(ws) => ws,
                    Err(_) => continue,
                };
                while let Ok(msg) = ws.read() {
                    if let tungstenite::Message::Text(t) = msg {
                        let id = serde_json::from_str::<serde_json::Value>(&t)
                            .ok()
                            .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                            .unwrap_or(0);
                        received_ws.lock().unwrap().push(t.to_string());
                        let reply = format!(
                            "{{\"id\":{id},\"result\":{{\"result\":{{\"value\":\"OK\"}}}}}}"
                        );
                        if ws.send(tungstenite::Message::Text(reply)).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        let body = format!(
            "[{{\"type\":\"page\",\"url\":\"{page_url}\",\"webSocketDebuggerUrl\":\"ws://127.0.0.1:{ws_port}/devtools/page/1\"}}]"
        );
        std::thread::spawn(move || {
            for mut stream in http_listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://127.0.0.1:{http_port}"), received)
    }
}

#[test]
fn fill_types_secret_into_browser_without_printing_it() {
    let te = TestEnv::new();
    te.init();
    // fill is opt-in now (H1); enable it via the config file (debug build reads it)
    std::fs::write(
        te.home.path().join("config.json"),
        r#"{"audit_log":false,"touch_id":false,"fill":true}"#,
    )
    .unwrap();
    te.envault()
        .args([
            "add",
            "site-login",
            "--url",
            "https://example.com",
            "--stdin",
        ])
        .write_stdin("hunter2-secret-99\n")
        .assert()
        .success();

    let (base, received) = mock_cdp::start("https://example.com/login");
    let out = te
        .envault()
        .args(["fill", "site-login", "--selector", "#pw", "--cdp", &base])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("site-login"), "{stdout}");
    assert!(
        !stdout.contains("hunter2-secret-99"),
        "value must never print"
    );

    let msgs = received.lock().unwrap();
    assert!(msgs
        .iter()
        .any(|m| m.contains("Runtime.evaluate") && m.contains("#pw")));
    let insert = msgs
        .iter()
        .find(|m| m.contains("Input.insertText"))
        .expect("insertText sent");
    assert!(
        insert.contains("hunter2-secret-99"),
        "value goes to the browser only"
    );
}

#[test]
fn fill_disabled_by_default_refuses() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "k", "--url", "https://example.com", "--stdin"])
        .write_stdin("v\n")
        .assert()
        .success();
    te.envault()
        .args(["fill", "k", "--cdp", "http://127.0.0.1:9222"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("disabled"));
}

#[test]
fn fill_refuses_non_loopback_cdp() {
    let te = TestEnv::new();
    te.init();
    std::fs::write(
        te.home.path().join("config.json"),
        r#"{"audit_log":false,"touch_id":false,"fill":true}"#,
    )
    .unwrap();
    te.envault()
        .args(["add", "k", "--url", "https://example.com", "--stdin"])
        .write_stdin("v\n")
        .assert()
        .success();
    te.envault()
        .args(["fill", "k", "--cdp", "http://10.0.0.9:9222"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("loopback"));
}

#[test]
fn fill_refuses_on_host_mismatch() {
    let te = TestEnv::new();
    te.init();
    std::fs::write(
        te.home.path().join("config.json"),
        r#"{"audit_log":false,"touch_id":false,"fill":true}"#,
    )
    .unwrap();
    te.envault()
        .args([
            "add",
            "site-login",
            "--url",
            "https://example.com",
            "--stdin",
        ])
        .write_stdin("hunter2-secret-99\n")
        .assert()
        .success();
    let (base, received) = mock_cdp::start("https://evil.test/login");
    te.envault()
        .args(["fill", "site-login", "--cdp", &base])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing"));
    assert!(
        received.lock().unwrap().is_empty(),
        "nothing may reach the browser"
    );
}

#[test]
fn rotate_reencrypts_and_values_survive() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "rot-key", "--stdin"])
        .write_stdin("rotate-me-value-1\n")
        .assert()
        .success();
    te.envault()
        .args(["add", "rot-two", "--stdin"])
        .write_stdin("second-value-22\n")
        .assert()
        .success();
    let old_recipient = std::fs::read_to_string(te.home.path().join("recipient.txt")).unwrap();
    let old_identity = std::fs::read_to_string(te.identity_file()).unwrap();
    let old_vault = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();

    te.envault()
        .arg("rotate")
        .assert()
        .success()
        .stdout(predicates::str::contains("Rotated 2"));

    // keypair and every cipher replaced; staging file cleaned up
    let new_vault = std::fs::read_to_string(te.home.path().join("vault.json")).unwrap();
    assert_ne!(
        old_recipient,
        std::fs::read_to_string(te.home.path().join("recipient.txt")).unwrap()
    );
    assert_ne!(
        old_identity,
        std::fs::read_to_string(te.identity_file()).unwrap()
    );
    assert_ne!(old_vault, new_vault);
    assert!(!new_vault.contains("rotate-me-value-1"));
    assert!(!te.home.path().join("vault.json.new").exists());

    // the decrypted value is still exactly right (compared inside the child,
    // never printed), and masking still works
    let out = te
        .envault()
        .args([
            "run",
            "--env",
            "K=rot-key",
            "--",
            "sh",
            "-c",
            "test \"$K\" = \"rotate-me-value-1\" && echo MATCH k=$K",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("MATCH"), "stdout: {stdout}");
    assert!(stdout.contains("k=[envault:rot-key]"), "stdout: {stdout}");

    // rotating again from the new key also works
    te.envault().arg("rotate").assert().success();
}

#[test]
fn request_for_existing_secret_short_circuits() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "openrouter", "--stdin"])
        .write_stdin("sk-existing-1\n")
        .assert()
        .success();
    // already present → exit 0, no window, and the value never appears
    let out = te
        .envault()
        .args(["request", "openrouter", "--reason", "need it"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("already in the vault"), "{stdout}");
    assert!(!stdout.contains("sk-existing-1"));
}

#[test]
fn request_without_window_gives_durable_recovery_guidance() {
    let te = TestEnv::new();
    te.init();
    // ENVAULT_NO_WINDOW forces the headless fallback (exit 6 + guidance)
    let output = te
        .envault()
        .env("ENVAULT_NO_WINDOW", "1")
        .args(["request", "newkey", "--reason", "need a new key"])
        .assert()
        .code(6)
        .get_output()
        .clone();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("envault add newkey"), "stderr: {stderr}");
    assert!(!stderr.contains("request-window"), "stderr: {stderr}");
    assert!(!stderr.contains("request.json"), "stderr: {stderr}");

    let requests = te.home.path().join("requests");
    assert!(
        !requests.exists() || std::fs::read_dir(requests).unwrap().next().is_none(),
        "failed request left a stale session"
    );

    let add_output = te
        .envault()
        .args(["add", "newkey", "--stdin"])
        .write_stdin("SYNTHETIC-SECRET-RECOVERY-9988\n")
        .assert()
        .success()
        .get_output()
        .clone();
    let add_stdout = String::from_utf8(add_output.stdout).unwrap();
    assert!(add_stdout.contains("Added 'newkey'"), "{add_stdout}");
    assert!(!add_stdout.contains("SYNTHETIC-SECRET-RECOVERY-9988"));
    te.envault()
        .env("ENVAULT_NO_WINDOW", "1")
        .args(["request", "newkey", "--reason", "retry after recovery"])
        .assert()
        .success()
        .stdout(predicates::str::contains("already in the vault"));
}

#[test]
fn request_rejects_bad_name() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["request", "Bad_Name", "--reason", "x"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("kebab-case"));
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

#[test]
fn init_if_needed_is_idempotent() {
    let te = TestEnv::new();
    // On a fresh vault, `--if-needed` initializes just like a normal init…
    te.envault()
        .args(["init", "--if-needed"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Initialized"));
    // …and a second run succeeds (installers re-run it) instead of failing.
    te.envault()
        .args(["init", "--if-needed"])
        .assert()
        .success()
        .stdout(predicates::str::contains("already initialized"));
}

#[test]
fn empty_legacy_explicit_init_preserves_old_keys_and_allows_first_add() {
    use age::secrecy::ExposeSecret;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    for path_scoped in [false, true] {
        for mirror in [
            None,
            Some("malformed".to_owned()),
            Some(age::x25519::Identity::generate().to_public().to_string()),
        ] {
            let te = TestEnv::new();
            let credentials = TempDir::new().unwrap();
            let old = age::x25519::Identity::generate();
            let account = if path_scoped {
                let home = std::fs::canonicalize(te.home.path()).unwrap();
                format!(
                    "age-identity-{:x}",
                    Sha256::digest(home.as_os_str().as_encoded_bytes())
                )
            } else {
                "age-identity".to_owned()
            };
            let raw = old.to_string().expose_secret().to_owned();
            std::fs::write(credentials.path().join(&account), &raw).unwrap();
            // Another migrated vault's association and old historical ciphertext.
            let other = format!("age-identity-v2-{}", "b".repeat(64));
            std::fs::write(credentials.path().join(&other), &raw).unwrap();
            let historical = age::encrypt(&old.to_public(), b"synthetic-history").unwrap();
            let empty = b"{\"secrets\":[]}";
            std::fs::write(te.home.path().join("vault.json"), empty).unwrap();
            if let Some(value) = &mirror {
                std::fs::write(te.home.path().join("recipient.txt"), value).unwrap();
            }
            let command = || {
                let mut c = te.envault();
                c.env("ENVAULT_IDENTITY_DIR", credentials.path());
                c
            };
            command()
                .args(["init", "--empty-legacy"])
                .assert()
                .success();
            assert_eq!(
                std::fs::read(te.home.path().join("vault.json")).unwrap(),
                empty
            );
            assert_eq!(
                std::fs::read_to_string(te.home.path().join("recipient.txt")).ok(),
                mirror
            );
            command()
                .args(["add", "first", "--stdin"])
                .write_stdin("synthetic-first\n")
                .assert()
                .success();
            let id = std::fs::read_to_string(te.home.path().join("identity-id")).unwrap();
            let fresh = age::x25519::Identity::from_str(
                std::fs::read_to_string(
                    credentials
                        .path()
                        .join(format!("age-identity-v2-{}", id.trim())),
                )
                .unwrap()
                .trim(),
            )
            .unwrap();
            assert_ne!(fresh.to_public(), old.to_public());
            let vault: serde_json::Value =
                serde_json::from_slice(&std::fs::read(te.home.path().join("vault.json")).unwrap())
                    .unwrap();
            let cipher = base64::engine::general_purpose::STANDARD
                .decode(vault["secrets"][0]["cipher"].as_str().unwrap())
                .unwrap();
            assert_eq!(age::decrypt(&fresh, &cipher).unwrap(), b"synthetic-first");
            assert!(age::decrypt(&old, &cipher).is_err());
            for name in [&account, &other] {
                assert_eq!(
                    std::fs::read_to_string(credentials.path().join(name)).unwrap(),
                    raw
                );
            }
            assert_eq!(
                age::decrypt(&old, &historical).unwrap(),
                b"synthetic-history"
            );
        }
    }
}

#[test]
fn empty_legacy_explicit_init_rejects_ineligible_state_without_changes() {
    for state in ["nonempty", "unreadable", "stable", "recovery"] {
        let te = TestEnv::new();
        let credentials = TempDir::new().unwrap();
        let vault = te.home.path().join("vault.json");
        if state == "unreadable" {
            std::fs::create_dir(&vault).unwrap();
        } else {
            let bytes = if state == "nonempty" {
                r#"{"secrets":[{"alias":"old","label":"Old","cipher":"preserve","created_at":"test","updated_at":"test"}]}"#
            } else {
                r#"{"secrets":[]}"#
            };
            std::fs::write(&vault, bytes).unwrap();
        }
        let before = std::fs::read(&vault).ok();
        if state == "stable" || state == "recovery" {
            let id = "a".repeat(64);
            std::fs::write(te.home.path().join("identity-id"), &id).unwrap();
            let prefix = if state == "stable" {
                "age-identity-v2-"
            } else {
                "rotation-recovery-"
            };
            std::fs::write(credentials.path().join(format!("{prefix}{id}")), "preserve").unwrap();
        }
        let metadata = std::fs::read(te.home.path().join("identity-id")).ok();
        let existing: Vec<_> = std::fs::read_dir(credentials.path())
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let bytes = std::fs::read(&p).unwrap();
                (p, bytes)
            })
            .collect();
        te.envault()
            .env("ENVAULT_IDENTITY_DIR", credentials.path())
            .args(["init", "--empty-legacy"])
            .assert()
            .failure();
        assert_eq!(std::fs::read(&vault).ok(), before);
        assert_eq!(
            std::fs::read(te.home.path().join("identity-id")).ok(),
            metadata
        );
        assert_eq!(
            std::fs::read_dir(credentials.path()).unwrap().count(),
            existing.len()
        );
        for (p, bytes) in existing {
            assert_eq!(std::fs::read(p).unwrap(), bytes);
        }
    }
}

fn wait_for_files(paths: &[&std::path::Path]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !paths.iter().all(|path| path.exists()) {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for explicit child-process signal"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn concurrent_adds_both_survive() {
    let te = TestEnv::new();
    te.init();
    let first_ready = te.home.path().join("first-ready");
    let second_ready = te.home.path().join("second-ready");
    let first_release = te.home.path().join("first-release");
    let second_release = te.home.path().join("second-release");

    let spawn_add = |alias: &str, ready: &std::path::Path, release: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_envault"))
            .env("ENVAULT_HOME", te.home.path())
            .env("ENVAULT_IDENTITY_FILE", te.identity_file())
            .env("ENVAULT_TEST_TRANSACTION_READY", ready)
            .env("ENVAULT_TEST_TRANSACTION_RELEASE", release)
            .current_dir(te.project.path())
            .args(["add", alias, "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };

    let mut first = spawn_add("concurrent-first", &first_ready, &first_release);
    let mut second = spawn_add("concurrent-second", &second_ready, &second_release);
    std::io::Write::write_all(
        first.stdin.as_mut().unwrap(),
        b"SYNTHETIC-CONCURRENT-FIRST-9988\n",
    )
    .unwrap();
    std::io::Write::write_all(
        second.stdin.as_mut().unwrap(),
        b"SYNTHETIC-CONCURRENT-SECOND-7766\n",
    )
    .unwrap();
    drop(first.stdin.take());
    drop(second.stdin.take());

    // Each child signals after it has authenticated and read stdin, then waits
    // immediately before the transaction. This makes overlap deterministic
    // without guessing how long process startup takes.
    wait_for_files(&[&first_ready, &second_ready]);
    std::fs::write(&first_release, b"release").unwrap();
    std::fs::write(&second_release, b"release").unwrap();

    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(first.status.success(), "first add failed: {first:?}");
    assert!(second.status.success(), "second add failed: {second:?}");

    let out = te.envault().args(["ls", "--json"]).assert().success();
    let listed: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    let aliases = listed.as_array().unwrap();
    assert_eq!(aliases.len(), 2, "both successful additions must remain");
}

#[test]
fn queued_add_rejects_identity_rotated_before_transaction() {
    let te = TestEnv::new();
    te.init();
    let ready = te.home.path().join("queued-add-ready");
    let release = te.home.path().join("queued-add-release");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_envault"))
        .env("ENVAULT_HOME", te.home.path())
        .env("ENVAULT_IDENTITY_FILE", te.identity_file())
        .env("ENVAULT_TEST_TRANSACTION_READY", &ready)
        .env("ENVAULT_TEST_TRANSACTION_RELEASE", &release)
        .current_dir(te.project.path())
        .args(["add", "queued-key", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        child.stdin.as_mut().unwrap(),
        b"SYNTHETIC-QUEUED-VALUE-9988\n",
    )
    .unwrap();
    drop(child.stdin.take());
    wait_for_files(&[&ready]);

    te.envault().arg("rotate").assert().success();
    std::fs::write(&release, b"release").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "queued add unexpectedly succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("identity changed"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(
        te.envault()
            .args(["ls", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .as_slice(),
    )
    .unwrap();
    assert!(listed.as_array().unwrap().is_empty());
}

#[test]
fn queued_import_rejects_identity_rotated_before_transaction() {
    let te = TestEnv::new();
    te.init();
    let dotenv = te.project.path().join("queued.env");
    std::fs::write(&dotenv, "QUEUED_KEY=SYNTHETIC-QUEUED-IMPORT-7766\n").unwrap();
    let ready = te.home.path().join("queued-import-ready");
    let release = te.home.path().join("queued-import-release");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_envault"))
        .env("ENVAULT_HOME", te.home.path())
        .env("ENVAULT_IDENTITY_FILE", te.identity_file())
        .env("ENVAULT_TEST_TRANSACTION_READY", &ready)
        .env("ENVAULT_TEST_TRANSACTION_RELEASE", &release)
        .current_dir(te.project.path())
        .args(["import", dotenv.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_files(&[&ready]);

    te.envault().arg("rotate").assert().success();
    std::fs::write(&release, b"release").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "queued import unexpectedly succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("identity changed"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(
        te.envault()
            .args(["ls", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .as_slice(),
    )
    .unwrap();
    assert!(listed.as_array().unwrap().is_empty());
    assert!(!te.project.path().join("envault.toml").exists());
}

#[test]
fn legacy_and_empty_legacy_cli_transactions_terminate_and_preserve_decryptability() {
    use age::secrecy::ExposeSecret;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::str::FromStr;
    for empty in [false, true] {
        for path_scoped in [false, true] {
            let te = TestEnv::new();
            let credentials = TempDir::new().unwrap();
            let old = age::x25519::Identity::generate();
            let account = if path_scoped {
                let home = std::fs::canonicalize(te.home.path()).unwrap();
                format!(
                    "age-identity-{:x}",
                    Sha256::digest(home.as_os_str().as_encoded_bytes())
                )
            } else {
                "age-identity".into()
            };
            std::fs::write(
                credentials.path().join(account),
                old.to_string().expose_secret(),
            )
            .unwrap();
            let cipher = base64::engine::general_purpose::STANDARD
                .encode(age::encrypt(&old.to_public(), b"synthetic-value").unwrap());
            let entries = if empty {
                serde_json::json!([])
            } else {
                serde_json::json!([{"alias":"legacy","label":"legacy","cipher":cipher,"created_at":"old","updated_at":"old","notes":""}])
            };
            std::fs::write(
                te.home.path().join("vault.json"),
                serde_json::to_vec(&serde_json::json!({"secrets":entries})).unwrap(),
            )
            .unwrap();
            let command = || {
                let mut c = te.envault();
                c.env("ENVAULT_IDENTITY_DIR", credentials.path())
                    .timeout(std::time::Duration::from_secs(15));
                c
            };
            if empty {
                command()
                    .args(["init", "--empty-legacy"])
                    .assert()
                    .success();
            }
            command()
                .args(["add", "first", "--stdin"])
                .write_stdin("synthetic-value")
                .assert()
                .success();
            command().arg("rotate").assert().success();
            let id = std::fs::read_to_string(te.home.path().join("identity-id")).unwrap();
            let identity = age::x25519::Identity::from_str(
                std::fs::read_to_string(
                    credentials
                        .path()
                        .join(format!("age-identity-v2-{}", id.trim())),
                )
                .unwrap()
                .trim(),
            )
            .unwrap();
            let vault: serde_json::Value =
                serde_json::from_slice(&std::fs::read(te.home.path().join("vault.json")).unwrap())
                    .unwrap();
            for e in vault["secrets"].as_array().unwrap() {
                let cipher = base64::engine::general_purpose::STANDARD
                    .decode(e["cipher"].as_str().unwrap())
                    .unwrap();
                assert_eq!(
                    age::decrypt(&identity, &cipher).unwrap(),
                    b"synthetic-value"
                );
            }
        }
    }
}

#[test]
fn audit_history_survives_repeated_identity_rotation() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "audited-key", "--stdin"])
        .write_stdin("SYNTHETIC-AUDIT-ROTATION-9988\n")
        .assert()
        .success();
    std::fs::write(
        te.home.path().join("config.json"),
        r#"{"audit_log":true,"touch_id":false,"fill":false}"#,
    )
    .unwrap();

    let use_secret = || {
        te.envault()
            .args([
                "run",
                "--env",
                "K=audited-key",
                "--",
                "sh",
                "-c",
                "test \"$K\" = \"SYNTHETIC-AUDIT-ROTATION-9988\"",
            ])
            .assert()
            .success();
    };

    use_secret();
    te.envault().arg("rotate").assert().success();
    use_secret();
    te.envault().arg("rotate").assert().success();
    use_secret();

    let lines = std::fs::read_to_string(te.home.path().join("audit.log")).unwrap();
    assert_eq!(lines.lines().count(), 5);
    let wrapped_key = std::fs::read_to_string(te.home.path().join("audit.key.age")).unwrap();
    assert!(!wrapped_key.contains("AGE-SECRET-KEY"));
    assert!(!te.home.path().join("audit.key.age.new").exists());
}

#[cfg(unix)]
#[test]
fn run_masks_fragments_across_child_output_handles() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "pipe-key", "--stdin"])
        .write_stdin("abcdef\n")
        .assert()
        .success();
    // Shell builtins issue writes in program order. Closing one descriptor
    // must not flush its partial secret before the other descriptor completes it.
    for script in [
        "printf abc; exec 1>&-; printf 'def ordinary abc' >&2",
        "printf abc >&2; exec 2>&-; printf 'def ordinary abc'",
    ] {
        te.envault()
            .args([
                "run",
                "--env",
                "PIPE_KEY=pipe-key",
                "--",
                "sh",
                "-c",
                script,
            ])
            .write_stdin(b"".as_slice())
            .timeout(Duration::from_secs(15))
            .assert()
            .success()
            .stdout("[envault:pipe-key] ordinary abc");
    }
}

#[cfg(unix)]
#[test]
fn run_drains_large_outputs_and_keeps_exit_status() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "pipe-key", "--stdin"])
        .write_stdin("abcdef\n")
        .assert()
        .success();
    // Both descriptors each exceed typical pipe capacity. The wrapper must
    // drain while the child runs, with memory bounded independently of volume.
    let script = "i=0; while [ $i -lt 20000 ]; do printf 'out:abcdef\n'; printf 'err:abcdef\n' >&2; i=$((i+1)); done; exit 7";
    let result = te
        .envault()
        .args([
            "run",
            "--env",
            "PIPE_KEY=pipe-key",
            "--",
            "sh",
            "-c",
            script,
        ])
        .write_stdin(b"".as_slice())
        .timeout(Duration::from_secs(30))
        .assert()
        .code(7);
    let output = String::from_utf8(result.get_output().stdout.clone()).unwrap();
    assert_eq!(output.matches("out:[envault:pipe-key]\n").count(), 20000);
    assert_eq!(output.matches("err:[envault:pipe-key]\n").count(), 20000);
    assert!(!output.contains("abcdef"));
    assert!(result.get_output().stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn run_preserves_piped_stdin_bytes() {
    let te = TestEnv::new();
    te.init();

    for input in [
        b"".as_slice(),
        b"no-final-newline".as_slice(),
        b"line-one\nline-two\r\n\0\x01\x7f".as_slice(),
        b"with-final-newline\n".as_slice(),
    ] {
        let expected = input.iter().map(|b| format!("{b:02x}")).collect::<String>();
        te.envault()
            .args([
                "run",
                "--allow-missing",
                "--",
                "sh",
                "-c",
                "od -An -v -tx1 | tr -d ' \\n'",
            ])
            .write_stdin(input)
            .timeout(Duration::from_secs(15))
            .assert()
            .success()
            .stdout(expected);
    }
}

#[test]
fn doctor_observes_missing_vault_and_mirrors_without_reinitialization_advice() {
    let te = TestEnv::new();
    std::fs::write(
        te.home.path().join("identity-id"),
        "synthetic-stable-marker",
    )
    .unwrap();
    std::fs::write(
        te.home.path().join("vault.json.new"),
        "pending-bytes-preserve",
    )
    .unwrap();
    let before = doctor_metadata_snapshot(te.home.path());
    let output = te
        .envault()
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["local_checks_passed"], true);
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("protected identity/recovery may still exist"));
    assert!(text.contains("protected recovery status"));
    assert!(!text.contains("envault init"));
    assert!(!text.contains("synthetic-stable-marker"));
    assert!(!text.contains("pending-bytes-preserve"));
    assert_eq!(doctor_metadata_snapshot(te.home.path()), before);
}

#[test]
fn doctor_sanitizes_local_parse_errors_in_text_and_json() {
    let te = TestEnv::new();
    std::fs::write(
        te.home.path().join("vault.json"),
        "SENSITIVE-SYNTHETIC-BAD-JSON",
    )
    .unwrap();
    std::fs::write(te.home.path().join("config.json"), b"\xff").unwrap();
    let before = doctor_metadata_snapshot(te.home.path());
    for json in [false, true] {
        let mut cmd = te.envault();
        cmd.arg("doctor");
        if json {
            cmd.arg("--json");
        }
        let output = cmd.assert().code(2).get_output().clone();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("SENSITIVE-SYNTHETIC-BAD-JSON"));
        assert!(!text.contains(&te.home.path().display().to_string()));
        assert!(!text.contains("healthy"));
        assert!(!text.contains("defaults apply"));
        assert!(!text.contains("remain fail-closed"));
        assert!(output.stderr.is_empty());
        if json {
            let report: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(report["local_checks_passed"], false);
        } else {
            assert!(text.contains("local checks failed"));
        }
    }
    assert_eq!(doctor_metadata_snapshot(te.home.path()), before);
}

// Include names, kinds, read-only flags, modification times and contents, including
// directories and recovery-like artifacts. Access times are OS-managed by reads.
type DoctorFileObservation = (
    PathBuf,
    bool,
    bool,
    u64,
    bool,
    Option<std::time::SystemTime>,
    Vec<u8>,
);

fn doctor_metadata_snapshot(root: &std::path::Path) -> Vec<DoctorFileObservation> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let bytes = if meta.is_file() && !meta.file_type().is_symlink() {
            std::fs::read(&path).unwrap()
        } else {
            Vec::new()
        };
        found.push((
            path.strip_prefix(root).unwrap().to_path_buf(),
            meta.is_dir(),
            meta.file_type().is_symlink(),
            meta.len(),
            meta.permissions().readonly(),
            meta.modified().ok(),
            bytes,
        ));
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}
