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
    const INTERNAL: [&str; 3] = ["devtools://", "chrome://", "chrome-extension://"];
    targets.iter().find(|t| {
        t.kind == "page"
            && t.ws_url.is_some()
            && !INTERNAL.iter().any(|prefix| t.url.starts_with(prefix))
    })
}

fn host_of(u: &str) -> Option<String> {
    url::Url::parse(u)
        .ok()?
        .host_str()
        .map(|h| h.to_lowercase())
}

/// Full origin (scheme + host + port) for a strict comparison. (L2)
fn origin_of(u: &str) -> Option<(String, String, u16)> {
    let p = url::Url::parse(u).ok()?;
    let host = p.host_str()?.to_lowercase();
    let port = p.port_or_known_default()?;
    Some((p.scheme().to_lowercase(), host, port))
}

/// True only if both URLs share scheme, host, AND port — prevents an `http://`
/// or different-port page from receiving an `https://`-registered secret. (L2)
pub fn host_matches(secret_url: &str, page_url: &str) -> bool {
    match (origin_of(secret_url), origin_of(page_url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// True if the URL's host is loopback (127.0.0.0/8, ::1, localhost). We refuse
/// to speak to a non-loopback DevTools endpoint, and refuse a target whose
/// websocket points off-loopback — so a fake `/json/list` can't redirect the
/// secret to a remote collector. (H1)
pub fn is_loopback(u: &str) -> bool {
    match host_of(u).as_deref() {
        Some("localhost") | Some("::1") | Some("[::1]") => true,
        Some(h) => h
            .parse::<std::net::Ipv4Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
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
        match ws
            .read()
            .with_context(|| format!("awaiting {method} reply"))?
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn t(kind: &str, url: &str, ws: Option<&str>) -> Target {
        Target {
            kind: kind.into(),
            url: url.into(),
            ws_url: ws.map(Into::into),
        }
    }

    #[test]
    fn picks_first_real_page() {
        let targets = vec![
            t("background_page", "chrome-extension://x", Some("ws://a")),
            t("page", "devtools://devtools/inspector.html", Some("ws://b")),
            t(
                "page",
                "chrome://omnibox-popup.top-chrome/",
                Some("ws://omni"),
            ),
            t("page", "chrome-extension://abc/bg.html", Some("ws://ext")),
            t("page", "https://example.com/login", None),
            t("page", "https://example.com/login", Some("ws://c")),
        ];
        assert_eq!(
            pick_page_target(&targets).unwrap().ws_url.as_deref(),
            Some("ws://c")
        );
        assert!(pick_page_target(&[]).is_none());
    }

    #[test]
    fn origin_matching_is_scheme_host_port_and_case_insensitive() {
        // same origin (case-insensitive host, default ports) matches
        assert!(host_matches(
            "https://openrouter.ai",
            "https://OPENROUTER.AI/login?x=1"
        ));
        // scheme mismatch (http vs https) is now REFUSED (L2)
        assert!(!host_matches(
            "https://example.com/settings",
            "http://example.com/other"
        ));
        // port mismatch is refused
        assert!(!host_matches(
            "https://example.com",
            "https://example.com:8443"
        ));
        assert!(!host_matches(
            "https://example.com",
            "https://evil-example.com"
        ));
        assert!(!host_matches("https://example.com", "not a url"));
        assert!(!host_matches("", "https://example.com"));
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("http://127.0.0.1:9222"));
        assert!(is_loopback("http://localhost:9222/json"));
        assert!(is_loopback("ws://127.0.0.1:9222/devtools/page/1"));
        assert!(!is_loopback("http://10.0.0.5:9222"));
        assert!(!is_loopback("https://evil.example/json"));
    }
}
