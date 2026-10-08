#!/usr/bin/env bash
# Build Sentinel for Linux on a Linux machine (or WSL on Windows):
#   - the app, as a .deb package and an AppImage (runs on most distributions),
#   - the Pillar, as one static file.
# Tested target: Ubuntu 22.04+ / Debian 12+ (x86-64).
#
# Like the Windows release script, local paths are stripped from the
# programs and the results are checked for the builder's user name.
#
# Usage:  bash scripts/build-linux.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== tools"
if command -v apt-get >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y build-essential curl wget file pkg-config xz-utils musl-tools \
    libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
fi
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
cargo tauri --version >/dev/null 2>&1 || cargo install tauri-cli --version '^2' --locked
rustup target add x86_64-unknown-linux-musl

echo "== FFmpeg (pinned build, checksum-verified)"
# Same source as the Windows build (see vendor/ffmpeg/PROVENANCE.md).
FF_REL="https://github.com/BtbN/FFmpeg-Builds/releases/download/latest"
FF_ASSET="ffmpeg-n8.1-latest-linux64-gpl-8.1.tar.xz"
OUT="$ROOT/vendor/ffmpeg/linux64"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
curl --proto '=https' --tlsv1.2 -fL "$FF_REL/$FF_ASSET" -o "$TMP/$FF_ASSET"
curl --proto '=https' --tlsv1.2 -fL "$FF_REL/checksums.sha256" -o "$TMP/checksums.sha256"
( cd "$TMP" && grep " $FF_ASSET\$" checksums.sha256 | sha256sum -c - )
tar -xJf "$TMP/$FF_ASSET" -C "$TMP"
cp "$TMP"/ffmpeg-*/bin/ffmpeg "$TMP"/ffmpeg-*/bin/ffprobe "$OUT/"
cp "$TMP"/ffmpeg-*/LICENSE.txt "$OUT/" 2>/dev/null || true
chmod 755 "$OUT/ffmpeg" "$OUT/ffprobe"
( cd "$OUT" && sha256sum ffmpeg ffprobe > SHA256SUMS.txt )
rm -rf "$TMP"

echo "== build (paths stripped)"
export RUSTFLAGS="--remap-path-prefix=$HOME=home --remap-path-prefix=$ROOT=sentinel"
( cd crates/app && cargo tauri build )
cargo build --release -p pillar --target x86_64-unknown-linux-musl

echo "== results"
mkdir -p dist
cp target/release/bundle/deb/*.deb dist/ 2>/dev/null || true
cp target/release/bundle/appimage/*.AppImage dist/ 2>/dev/null || true
cp target/x86_64-unknown-linux-musl/release/pillar dist/sentinel-pillar-linux-x86_64
USERNAME="$(id -un)"
for f in dist/*; do
  if grep -a -q -e "/home/$USERNAME/" -e "/$USERNAME/" "$f"; then
    echo "local path left in $f" >&2
    exit 1
  fi
  echo "clean: $f"
done
