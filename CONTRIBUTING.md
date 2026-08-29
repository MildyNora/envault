# Contributing to envault

Thanks for your interest. envault is a local, encrypted secrets vault for coding
agents, and its whole reason to exist is a security boundary — so contributions
are held to that bar: **agents must only ever see names and ciphers, never
plaintext.**

## Getting started

```bash
git clone https://github.com/MildyNora/envault.git
cd envault
cargo build
cargo test        # unit + integration suite
```

You'll need [Rust](https://rustup.rs) (stable, edition 2021).

## Before you open a pull request

Run all three — review expects them green:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

If you touched anything platform-specific, cross-check Windows too:

```bash
cargo check --all-targets --target x86_64-pc-windows-gnu   # --all-targets compiles tests too
```

The runtime paths (macOS Keychain, Windows Credential Manager, Touch ID / Windows
Hello, Linux Secret Service) can only be *compile-checked* off their native OS —
say in the PR what you could and couldn't actually run.

## Pull request guidelines

- **One focused change per PR.** Small PRs get reviewed faster.
- **Explain the why, not just the what**, and link the issue it closes.
- **Add tests** for new behavior; keep the suite green.
- **Match the surrounding code** — naming, comments, idioms. Rust 2021;
  `cargo fmt` settles formatting.
- **Commits:** short imperative subject; conventional prefixes welcome
  (`feat:`, `fix:`, `docs:`, `chore:`). Squash noise before review.
- **Never commit a secret**, a real vault, or a `~/.envault` path.

### If your change touches security

These modules *are* the trust boundary — extra care, and spell out the impact in
the PR:

- `src/crypto.rs` — age keys, the keychain identity, recipient derivation
- `src/access.rs` — the single decryption choke point (biometric gate + audit)
- `src/commands/guard.rs` — what agents are blocked from
- `src/masker.rs` — output masking in `envault run`
- `src/settings.rs` — fail-closed, keychain-authoritative settings

Don't weaken the aliases-only model, and never add a command that prints
plaintext. Found a vulnerability? **Don't open a public issue** — see
[SECURITY.md](SECURITY.md).

## Project layout

- `src/` — CLI + TUI (`commands/`, `tui/`, plus `crypto`, `access`, `store`,
  `masker`, `audit`, `settings`, `guard`)
- `plugin/` — the Claude Code plugin (the agent skill + the PreToolUse guard hook)
- `docs/` — design notes and the architecture figure source (`architecture.d2`)
- `tests/` — integration tests (`cli.rs`)

## Code of conduct

Be respectful and constructive; harassment isn't tolerated. By contributing, you
agree your work is licensed under the project's [MIT License](LICENSE).
