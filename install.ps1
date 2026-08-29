# envault installer (Windows) — builds the binary and installs the agent skill.
#
#   ./install.ps1
#
# 1. Installs the `envault` binary via cargo.
# 2. Writes the envault skill into the skill directories read by Claude Code,
#    Codex, and opencode, so any of those agents learns the aliases-only
#    workflow (loaded lazily, only when a task needs a secret).
#
# Re-run any time to upgrade — it reinstalls the binary and refreshes the skill.
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo not found. Install Rust from https://rustup.rs first."
    exit 1
}

Write-Host "==> Installing the envault binary (cargo install)..."
cargo install --path $here --locked --force

$cmd = Get-Command envault -ErrorAction SilentlyContinue
if ($cmd) {
    $bin = $cmd.Source
} else {
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { "$env:USERPROFILE\.cargo" }
    $bin = Join-Path $cargoHome "bin\envault.exe"
}

Write-Host "`n==> Creating your vault (if it doesn't exist yet)..."
& $bin init --if-needed

Write-Host "`n==> Installing the agent skill..."
& $bin skill install

Write-Host "`nDone. Add your first secret with 'envault add <name>'."
