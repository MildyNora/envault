use assert_cmd::Command;
#[cfg(unix)]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
#[cfg(unix)]
use std::io::Read;
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

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
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
fn request_without_window_tells_agent_how_to_proceed() {
    let te = TestEnv::new();
    te.init();
    // ENVAULT_NO_WINDOW forces the headless fallback (exit 6 + guidance)
    te.envault()
        .env("ENVAULT_NO_WINDOW", "1")
        .args(["request", "newkey", "--reason", "need a new key"])
        .assert()
        .code(6)
        .stderr(predicates::str::contains("request-window"));
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
