# Homebrew formula for envault (installs the prebuilt release binary).
#
# To use it, this formula must live in a Homebrew tap and the release assets must
# be publicly downloadable:
#   1. make the repo public (release assets follow repo visibility), then
#   2. create a tap repo `MildyNora/homebrew-envault` and add this file, then
#      users run:  brew install MildyNora/envault/envault
#
# Bump `version` and the three `sha256` values on each release
# (shasum -a 256 envault-<target>.tar.gz).
class Envault < Formula
  desc "Local, encrypted secrets vault for coding agents — agents see names, never secrets"
  homepage "https://github.com/MildyNora/envault"
  version "0.7.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/MildyNora/envault/releases/download/v0.7.0/envault-aarch64-apple-darwin.tar.gz"
      sha256 "c0f9e678e9e640e2fceec6e2cdea9eecb0f4088163d58d8dcc5941f79981f7c8"
    else
      url "https://github.com/MildyNora/envault/releases/download/v0.7.0/envault-x86_64-apple-darwin.tar.gz"
      sha256 "b59e806d15230843e2f0f903450a0101d38d2b49e32de222675c20c3cdbfa3fd"
    end
  end

  on_linux do
    url "https://github.com/MildyNora/envault/releases/download/v0.7.0/envault-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "3d65a9d82a00d9c8f036f92c60c3fd3ddb70a907f98b8033670b6ea62113149c"
  end

  def install
    bin.install "envault"
  end

  test do
    assert_match "envault 0.7.0", shell_output("#{bin}/envault --version")
  end
end
