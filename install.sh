#!/usr/bin/env bash
# envault installer.
#
#   curl -fsSL https://raw.githubusercontent.com/MildyNora/envault/master/install.sh | bash
#   # or, from a clone:  ./install.sh
#
# Downloads a prebuilt binary (no Rust needed). If there's no prebuilt for your
# platform and you're running inside a clone with cargo, it builds from source.
# Then it creates your vault and installs the agent skill. Re-run to upgrade.
set -euo pipefail

REPO="MildyNora/envault"
BIN_DIR="${ENVAULT_BIN_DIR:-$HOME/.local/bin}"

detect_target() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  echo aarch64-apple-darwin ;;
    Darwin-x86_64) echo x86_64-apple-darwin ;;
    Linux-x86_64)  echo x86_64-unknown-linux-gnu ;;
    Linux-aarch64) echo aarch64-unknown-linux-gnu ;;
    *) echo "" ;;
  esac
}

install_prebuilt() {
  local target url tmp
  target="$(detect_target)"
  [ -n "$target" ] || return 1
  url="https://github.com/$REPO/releases/latest/download/envault-$target.tar.gz"
  echo "==> Downloading prebuilt binary ($target)…"
  tmp="$(mktemp -d)"
  if ! curl -fsSL "$url" -o "$tmp/envault.tar.gz"; then rm -rf "$tmp"; return 1; fi
  tar -xzf "$tmp/envault.tar.gz" -C "$tmp"
  mkdir -p "$BIN_DIR"
  install -m 0755 "$tmp/envault" "$BIN_DIR/envault"
  rm -rf "$tmp"
  echo "    installed $BIN_DIR/envault"
}

install_from_source() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-/nonexistent}")" 2>/dev/null && pwd || true)"
  [ -n "$here" ] && [ -f "$here/Cargo.toml" ] || return 1
  command -v cargo >/dev/null 2>&1 || return 1
  echo "==> No prebuilt for this platform — building from source (cargo)…"
  cargo install --path "$here" --locked --force
  BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
}

echo "==> Installing envault…"
if ! install_prebuilt && ! install_from_source; then
  echo "error: no prebuilt binary for your platform, and can't build from source." >&2
  echo "  Grab a binary from https://github.com/$REPO/releases, or install Rust" >&2
  echo "  (https://rustup.rs) and run ./install.sh from a clone." >&2
  exit 1
fi

bin="$(command -v envault 2>/dev/null || echo "$BIN_DIR/envault")"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo; echo "note: add $BIN_DIR to your PATH to run 'envault' directly." ;;
esac

echo
echo "==> Creating your vault (if it doesn't exist yet)…"
"$bin" init --if-needed

echo
echo "==> Installing the agent skill…"
"$bin" skill install

echo
echo "Done. Open the dashboard:  envault"
