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

#[test]
fn run_passes_exit_code_through() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["run", "--allow-missing", "--", "sh", "-c", "exit 3"])
        .assert()
        .code(3);
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
fn fill_refuses_on_host_mismatch() {
    let te = TestEnv::new();
    te.init();
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
fn init_twice_fails() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicates::str::contains("already initialized"));
}
