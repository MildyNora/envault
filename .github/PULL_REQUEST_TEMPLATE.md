## What & why

<!-- What does this change, and why? Link the issue it closes, e.g. "Closes #12". -->

## Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --all` applied
- [ ] Added or updated tests for the change
- [ ] Cross-checked Windows if platform code changed (`cargo check --target x86_64-pc-windows-gnu`)
- [ ] No secrets, real vaults, or `~/.envault` paths committed

## Security

- [ ] This change does **not** let an agent see plaintext or weaken a gated action
- [ ] If it touches `crypto` / `access` / `guard` / `masker` / `settings`, the impact is explained above

<!-- Reporting a vulnerability? Do NOT open a PR/issue — see SECURITY.md. -->
