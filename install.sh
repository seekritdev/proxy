#!/bin/sh
# seekrit-proxy installer.
#
#   curl -fsSL https://proxy.seekrit.dev/install.sh | sh
#
# Downloads the seekrit-proxy binary for your platform from https://proxy.seekrit.dev,
# verifies its SHA-256 checksum, and installs it onto your PATH. POSIX sh only —
# no bash, no dependencies beyond curl-or-wget + tar + sha256sum/shasum.
#
# Prefer `npx -y @seekrit/proxy` if you already have Node — same binary, same
# checksum verification, nothing added to your PATH. This script is for the case
# where a persistent binary is what you want (a container image, a CI runner, a
# systemd unit) and Node is not part of the picture.
#
# Environment overrides:
#   SEEKRIT_PROXY_VERSION      version to install, e.g. 0.7.0 (default: latest)
#   SEEKRIT_PROXY_INSTALL_DIR  where to put the binary (default: first writable
#                              of /usr/local/bin, then ~/.local/bin)
#   SEEKRIT_PROXY_TARGET       force a Rust target triple, bypassing detection
#   SEEKRIT_PROXY_BASE_URL     artifact host (default: https://proxy.seekrit.dev)
set -eu

BASE_URL="${SEEKRIT_PROXY_BASE_URL:-https://proxy.seekrit.dev}"
VERSION="${SEEKRIT_PROXY_VERSION:-latest}"
BIN="seekrit-proxy"

err() { printf 'seekrit-proxy installer: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }

# --- pick a downloader -------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
else
  err "need curl or wget on PATH"
fi

# --- detect target triple ----------------------------------------------------
detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  case "$os" in
    # Static musl build: one binary that runs on glibc, musl, alpine, distroless.
    Linux) printf '%s-unknown-linux-musl' "$arch" ;;
    Darwin) printf '%s-apple-darwin' "$arch" ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      err "Windows isn't supported by this script — download the .zip from ${BASE_URL}/${VERSION}/${BIN}-x86_64-pc-windows-msvc.zip" ;;
    *) err "unsupported OS: $os" ;;
  esac
}
TARGET="${SEEKRIT_PROXY_TARGET:-$(detect_target)}"

# --- resolve version path (latest/ or v<x.y.z>/) -----------------------------
case "$VERSION" in
  latest) prefix="latest" ;;
  v*) prefix="$VERSION" ;;
  *) prefix="v$VERSION" ;;
esac

archive="${BIN}-${TARGET}.tar.gz"
# The checksum asset drops the archive extension: seekrit-proxy-<target>.sha256,
# whose contents are "<hex>  <archive>".
checksum="${BIN}-${TARGET}.sha256"
url="${BASE_URL}/${prefix}/${archive}"
checksum_url="${BASE_URL}/${prefix}/${checksum}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# --- download archive + checksum ---------------------------------------------
info "Downloading ${url}"
dl "$url" "$tmp/$archive" || err "download failed: $url"
dl "$checksum_url" "$tmp/$checksum" || err "checksum download failed: $checksum_url"

# --- verify checksum ---------------------------------------------------------
expected="$(cut -d' ' -f1 "$tmp/$checksum")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)"
else
  err "need sha256sum or shasum to verify the download"
fi
[ "$expected" = "$actual" ] || err "checksum mismatch (expected $expected, got $actual)"
info "Checksum OK"

# --- extract -----------------------------------------------------------------
tar xzf "$tmp/$archive" -C "$tmp" || err "failed to extract $archive"
binpath="$(find "$tmp" -type f -name "$BIN" | head -n1)"
[ -n "$binpath" ] || err "$BIN not found in archive"
chmod 0755 "$binpath"

# --- choose an install dir ---------------------------------------------------
if [ -n "${SEEKRIT_PROXY_INSTALL_DIR:-}" ]; then
  dir="$SEEKRIT_PROXY_INSTALL_DIR"
elif [ -w /usr/local/bin ] 2>/dev/null; then
  dir="/usr/local/bin"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" || err "cannot create install dir: $dir"

if command -v install >/dev/null 2>&1; then
  install -m 0755 "$binpath" "$dir/$BIN" || err "failed to install to $dir"
else
  cp "$binpath" "$dir/$BIN" && chmod 0755 "$dir/$BIN" || err "failed to install to $dir"
fi

info "Installed $BIN to $dir/$BIN"

# --- PATH hint ---------------------------------------------------------------
case ":$PATH:" in
  *":$dir:"*) info "Run: $BIN --help" ;;
  *) info "Add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac

# --- next steps --------------------------------------------------------------
# Unlike seekrit-run, the proxy needs a config: an allowlist is the security
# boundary, and there is no safe default for "which secret may reach which host".
info ""
info "Next: the proxy needs a config and a service token."
info "  npx -y @seekrit/cli proxy init --preset openai   # writes seekrit-proxy.toml"
info "  export SEEKRIT_TOKEN=skt_…"
info "  $BIN --config seekrit-proxy.toml"
info ""
info "Docs: https://seekrit.dev/docs/guides/agent-proxy"
