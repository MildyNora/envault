#!/usr/bin/env bash
# envault installer — builds the binary and installs the agent skill.
#
#   ./install.sh
#
# 1. Installs the `envault` binary via cargo.
# 2. Writes the envault skill into the skill directories read by Claude Code,
#    Codex, and opencode, so any of those agents learns the aliases-only
#    workflow (loaded lazily, only when a task needs a secret).
#
# Re-run any time to upgrade — it reinstalls the binary and refreshes the skill.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust from https://rustup.rs first." >&2
  exit 1
fi

echo "==> Installing the envault binary (cargo install)…"
cargo install --path "$here" --locked --force

bin="$(command -v envault || echo "${CARGO_HOME:-$HOME/.cargo}/bin/envault")"

echo
echo "==> Creating your vault (if it doesn't exist yet)…"
"$bin" init --if-needed

echo
echo "==> Installing the agent skill…"
"$bin" skill install

echo
echo "Done. Add your first secret with 'envault add <name>'."
