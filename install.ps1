# envault installer (Windows).
#
#   irm https://raw.githubusercontent.com/MildyNora/envault/master/install.ps1 | iex
#   # or, from a clone:  .\install.ps1
#
# Downloads a prebuilt binary (no Rust needed). If there's no prebuilt for your
# platform and you're running inside a clone with cargo, it builds from source.
# Then it creates your vault and installs the agent skill. Re-run to upgrade.
$ErrorActionPreference = "Stop"
$Repo = "MildyNora/envault"
$BinDir = if ($env:ENVAULT_BIN_DIR) { $env:ENVAULT_BIN_DIR } else { "$env:LOCALAPPDATA\envault\bin" }

function Install-Prebuilt {
    $target = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    $url = "https://github.com/$Repo/releases/latest/download/envault-$target.zip"
    Write-Host "==> Downloading prebuilt binary ($target)..."
    $zip = Join-Path $env:TEMP "envault-download.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    } catch {
        return $false
    }
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Expand-Archive -Path $zip -DestinationPath $BinDir -Force
    Remove-Item $zip -ErrorAction SilentlyContinue
    Write-Host "    installed $BinDir\envault.exe"
    return $true
}

function Install-FromSource {
    if (-not $PSScriptRoot -or -not (Test-Path (Join-Path $PSScriptRoot "Cargo.toml"))) { return $false }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { return $false }
    Write-Host "==> No prebuilt for this platform — building from source (cargo)..."
    cargo install --path $PSScriptRoot --locked --force
    $script:BinDir = if ($env:CARGO_HOME) { "$env:CARGO_HOME\bin" } else { "$env:USERPROFILE\.cargo\bin" }
    return $true
}

Write-Host "==> Installing envault..."
if (-not (Install-Prebuilt)) {
    if (-not (Install-FromSource)) {
        Write-Error "No prebuilt binary for your platform and can't build from source. Grab a binary from https://github.com/$Repo/releases, or install Rust (https://rustup.rs) and run .\install.ps1 from a clone."
        exit 1
    }
}

$bin = Join-Path $BinDir "envault.exe"
if (-not (Get-Command envault -ErrorAction SilentlyContinue)) {
    Write-Host "`nnote: add $BinDir to your PATH to run 'envault' directly."
}

Write-Host "`n==> Creating your vault (if it doesn't exist yet)..."
& $bin init --if-needed

Write-Host "`n==> Installing the agent skill..."
& $bin skill install

Write-Host "`nDone. Open the dashboard:  envault"
