# envault Browser Form-Fill (Milestone 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `envault fill <alias> [--selector S]` types a decrypted secret straight into the browser page the agent is driving, over CDP — the agent orchestrates but never sees the value.

**Architecture:** `cdp.rs` speaks raw Chrome DevTools Protocol: `GET <base>/json/list` (via ureq) to find the active page target, then a tungstenite WebSocket to it — optional `Runtime.evaluate` to focus the `--selector`, then `Input.insertText` with the plaintext. `commands/fill.rs` wires vault lookup, the URL host-guard, decryption, and the CDP call. Integration tests run a mock CDP endpoint (hand-rolled HTTP listener + tungstenite server) inside the test process and assert exactly what reached the "browser".

**Tech Stack:** ureq 2 (HTTP), tungstenite 0.24 (WS client; also the test's WS server), url 2 (host parsing).

**Spec:** `docs/superpowers/specs/2026-08-26-envault-design.md` §10 (+ §11 fill error handling)

## Global Constraints

- `fill` NEVER prints the value; success output names only alias, place, and page URL.
- URL guard: when the secret has a `url`, refuse unless the page's host equals the secret URL's host (case-insensitive). Refusal names both URLs.
- Missing CDP endpoint → actionable hint: launch the browser with `--remote-debugging-port=9222`.
- All prior constraints hold (fmt, clippy -D warnings, TDD).

---

### Task 1: `cdp.rs` — targets, host guard, fill call

**Files:**
- Create: `src/cdp.rs`
- Modify: `src/main.rs` (`mod cdp;`), `Cargo.toml` (add `ureq = "2"`, `tungstenite = "0.24"`, `url = "2"`)

**Interfaces:**
- Produces:
  - `cdp::Target { kind: String, url: String, ws_url: Option<String> }` (Deserialize; serde renames: `type` → kind, `webSocketDebuggerUrl` → ws_url)
  - `cdp::list_targets(base: &str) -> Result<Vec<Target>>`
  - `cdp::pick_page_target(targets: &[Target]) -> Option<&Target>` — first `kind == "page"` with a ws_url, skipping `devtools://` pages
  - `cdp::host_matches(secret_url: &str, page_url: &str) -> bool`
  - `cdp::fill_via_cdp(ws_url: &str, selector: Option<&str>, text: &str) -> Result<String>` — returns a human description of where it typed ("into #pw" / "into the focused element"); selector that matches nothing is an error

- [ ] **Step 1: Failing unit tests** (bottom of `src/cdp.rs`) for the pure parts:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn t(kind: &str, url: &str, ws: Option<&str>) -> Target {
        Target { kind: kind.into(), url: url.into(), ws_url: ws.map(Into::into) }
    }

    #[test]
    fn picks_first_real_page() {
        let targets = vec![
            t("background_page", "chrome-extension://x", Some("ws://a")),
            t("page", "devtools://devtools/inspector.html", Some("ws://b")),
            t("page", "https://example.com/login", None),
            t("page", "https://example.com/login", Some("ws://c")),
        ];
        assert_eq!(pick_page_target(&targets).unwrap().ws_url.as_deref(), Some("ws://c"));
        assert!(pick_page_target(&[]).is_none());
    }

    #[test]
    fn host_matching_is_host_only_and_case_insensitive() {
        assert!(host_matches("https://openrouter.ai", "https://OPENROUTER.AI/login?x=1"));
        assert!(host_matches("https://example.com/settings", "http://example.com/other"));
        assert!(!host_matches("https://example.com", "https://evil-example.com"));
        assert!(!host_matches("https://example.com", "not a url"));
        assert!(!host_matches("", "https://example.com"));
    }
}
```

- [ ] **Step 2: Verify red**, **Step 3: Implement:**

```rust
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tungstenite::Message;

#[derive(Debug, Deserialize)]
pub struct Target {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub url: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    pub ws_url: Option<String>,
}

pub fn list_targets(base: &str) -> Result<Vec<Target>> {
    let listing = format!("{}/json/list", base.trim_end_matches('/'));
    let targets: Vec<Target> = ureq::get(&listing)
        .call()
        .with_context(|| format!("querying {listing}"))?
        .into_json()
        .context("parsing CDP target list")?;
    Ok(targets)
}

pub fn pick_page_target(targets: &[Target]) -> Option<&Target> {
    targets
        .iter()
        .find(|t| t.kind == "page" && t.ws_url.is_some() && !t.url.starts_with("devtools://"))
}

fn host_of(u: &str) -> Option<String> {
    url::Url::parse(u).ok()?.host_str().map(|h| h.to_lowercase())
}

pub fn host_matches(secret_url: &str, page_url: &str) -> bool {
    match (host_of(secret_url), host_of(page_url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

pub fn fill_via_cdp(ws_url: &str, selector: Option<&str>, text: &str) -> Result<String> {
    let (mut ws, _) =
        tungstenite::connect(ws_url).context("connecting to the browser's CDP websocket")?;
    let mut next_id: u64 = 1;
    if let Some(sel) = selector {
        let expr = format!(
            "(() => {{ const el = document.querySelector({sel_json}); \
             if (!el) return 'MISSING'; el.focus(); return 'OK'; }})()",
            sel_json = serde_json::to_string(sel)?
        );
        let reply = cdp_call(
            &mut ws,
            &mut next_id,
            "Runtime.evaluate",
            serde_json::json!({"expression": expr, "returnByValue": true}),
        )?;
        let verdict = reply
            .pointer("/result/result/value")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if verdict != "OK" {
            bail!("selector {sel:?} matched no element on the page");
        }
    }
    cdp_call(
        &mut ws,
        &mut next_id,
        "Input.insertText",
        serde_json::json!({"text": text}),
    )?;
    Ok(match selector {
        Some(s) => format!("into {s}"),
        None => "into the focused element".to_string(),
    })
}

fn cdp_call(
    ws: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    next_id: &mut u64,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let id = *next_id;
    *next_id += 1;
    let msg = serde_json::json!({"id": id, "method": method, "params": params});
    ws.send(Message::Text(msg.to_string()))
        .with_context(|| format!("sending {method}"))?;
    loop {
        match ws.read().with_context(|| format!("awaiting {method} reply"))? {
            Message::Text(t) => {
                let v: serde_json::Value = serde_json::from_str(&t)?;
                if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                    if let Some(err) = v.get("error") {
                        bail!("CDP {method} failed: {err}");
                    }
                    return Ok(v);
                }
            }
            _ => continue,
        }
    }
}
```

- [ ] **Step 4: Verify green**, **Step 5: Commit** — `feat: raw CDP client — target listing, host guard, insertText fill`

---

### Task 2: `fill` command + mock-browser integration tests

**Files:**
- Create: `src/commands/fill.rs`
- Modify: `src/commands/mod.rs`, `src/main.rs`
- Test: `tests/cli.rs` (+ dev-dependency `tungstenite = "0.24"` for the mock server)

**Interfaces:**
- Produces: `commands::fill::cmd_fill(alias: String, selector: Option<String>, cdp: String) -> Result<()>`; CLI `envault fill <alias> [--selector S] [--cdp URL]` (default `http://127.0.0.1:9222`).

- [ ] **Step 1: Failing integration test** with an in-test mock CDP endpoint:

```rust
mod mock_cdp {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Minimal CDP double: one HTTP listener answering /json/list, one
    /// websocket listener recording every message and answering {"result":
    /// {"result":{"value":"OK"}}}. Returns (http_base, page_url_reported,
    /// received_messages).
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
                        if ws.send(tungstenite::Message::Text(reply.into())).is_err() {
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
        .args(["add", "site-login", "--url", "https://example.com", "--stdin"])
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
    assert!(!stdout.contains("hunter2-secret-99"), "value must never print");

    let msgs = received.lock().unwrap();
    assert!(msgs.iter().any(|m| m.contains("Runtime.evaluate") && m.contains("#pw")));
    let insert = msgs
        .iter()
        .find(|m| m.contains("Input.insertText"))
        .expect("insertText sent");
    assert!(insert.contains("hunter2-secret-99"), "value goes to the browser only");
}

#[test]
fn fill_refuses_on_host_mismatch() {
    let te = TestEnv::new();
    te.init();
    te.envault()
        .args(["add", "site-login", "--url", "https://example.com", "--stdin"])
        .write_stdin("hunter2-secret-99\n")
        .assert()
        .success();
    let (base, received) = mock_cdp::start("https://evil.test/login");
    te.envault()
        .args(["fill", "site-login", "--cdp", &base])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing"));
    assert!(received.lock().unwrap().is_empty(), "nothing may reach the browser");
}
```

- [ ] **Step 2: Verify red**, **Step 3: Implement `commands/fill.rs`:**

```rust
use anyhow::{bail, Context, Result};

use crate::cdp;
use crate::crypto;
use crate::paths;
use crate::store::Vault;

pub fn cmd_fill(alias: String, selector: Option<String>, cdp_base: String) -> Result<()> {
    let home = paths::envault_home();
    let vault = Vault::load(&home)?;
    let entry = vault
        .get(&alias)
        .with_context(|| format!("alias '{alias}' is not in the vault (see `envault ls`)"))?
        .clone();

    let targets = cdp::list_targets(&cdp_base).with_context(|| {
        format!(
            "no browser CDP endpoint at {cdp_base} — launch the browser with \
             --remote-debugging-port=9222 (or pass --cdp)"
        )
    })?;
    let target = cdp::pick_page_target(&targets)
        .context("no page tab found in the browser (open the login page first)")?;

    if let Some(secret_url) = &entry.url {
        if !cdp::host_matches(secret_url, &target.url) {
            bail!(
                "refusing to fill: '{alias}' is registered for {secret_url}, \
                 but the active page is {}",
                target.url
            );
        }
    }

    let identity = crypto::load_identity()?;
    let value = crypto::decrypt_value(&identity, &entry.cipher)?;
    let ws_url = target.ws_url.clone().expect("picked target has ws url");
    let place = cdp::fill_via_cdp(&ws_url, selector.as_deref(), &value)?;
    println!("Filled '{alias}' {place} on {}", target.url);
    Ok(())
}
```

CLI additions in `src/main.rs`:

```rust
    /// Type a secret into the browser page over CDP (value never shown)
    Fill {
        alias: String,
        /// CSS selector to focus first; omit to use the focused element
        #[arg(long)]
        selector: Option<String>,
        /// DevTools endpoint of the browser
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        cdp: String,
    },
```

```rust
        Some(Cmd::Fill { alias, selector, cdp }) => commands::fill::cmd_fill(alias, selector, cdp),
```

- [ ] **Step 4: Verify green** — `cargo test` all pass.
- [ ] **Step 5: Real-browser E2E (best effort)** — if Chrome exists locally, launch it headless with `--remote-debugging-port` on a `data:` URL containing `<input id=pw>`, run `envault fill --selector '#pw'`, then read the input's value back over CDP from the test harness and compare. Skip without failing if no Chrome is installed.
- [ ] **Step 6: Commit** — `feat: envault fill — CDP form-fill with URL host guard`

---

### Task 3: Docs — skill etiquette + README

**Files:**
- Modify: `plugin/skills/envault/SKILL.md` (fill etiquette section + cheat-sheet row)
- Modify: `README.md` (fill usage + caveats)

- [ ] **Step 1:** Add to the skill: when logging into a site for the user, navigate to the form, then run `envault fill <alias> --selector '<css>'` instead of typing credentials; the value goes vault → browser directly. Never screenshot immediately after filling a *visible* (non-password) field; password inputs render masked. If fill refuses on a host mismatch, tell the user instead of overriding.
- [ ] **Step 2:** README: fill quickstart line + the same caveats + bump the cheat table.
- [ ] **Step 3: Full gate** — fmt, clippy, tests. **Commit** — `docs: form-fill etiquette and usage`
