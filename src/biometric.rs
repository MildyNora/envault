//! Cross-platform biometric / password gate (Touch ID on macOS, Windows Hello
//! on Windows) via `robius-authentication`.
//!
//! NOTE: this triggers a native system prompt that cannot be exercised in the
//! dev/CI environment — it is compile-verified per platform, but the actual
//! prompt must be tested on real hardware.

use anyhow::Result;

/// Require the user to authenticate before continuing. Ok(()) on success; Err
/// on denial, timeout, or an unsupported platform (callers fail closed).
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn require(reason: &str) -> Result<()> {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
    };

    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .build()
        .ok_or_else(|| anyhow::anyhow!("no authentication method is available"))?;

    let text = Text {
        android: AndroidText {
            title: "envault",
            subtitle: None,
            description: Some(reason),
        },
        apple: reason,
        windows: WindowsText::new("envault", reason)
            .ok_or_else(|| anyhow::anyhow!("invalid prompt text"))?,
    };

    let ctx = Context::new(());
    let (tx, rx) = std::sync::mpsc::channel();
    ctx.authenticate(text, &policy, move |res| {
        let _ = tx.send(res.is_ok());
    })
    .map_err(|e| anyhow::anyhow!("authentication error: {e:?}"))?;

    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(true) => Ok(()),
        Ok(false) => anyhow::bail!("authentication denied"),
        Err(_) => anyhow::bail!("authentication timed out"),
    }
}

/// On platforms without a supported prompt (Linux here), fail closed: if a gate
/// was requested we cannot verify the user, so deny.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn require(_reason: &str) -> Result<()> {
    anyhow::bail!("biometric/password gating is not supported on this platform")
}
