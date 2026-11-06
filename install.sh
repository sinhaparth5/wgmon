#!/bin/sh
# Install or update wgmon (same command for both):
#   curl -fsSL https://raw.githubusercontent.com/sinhaparth5/wgmon/master/install.sh | sh
# Pin a version:
#   curl -fsSL https://raw.githubusercontent.com/sinhaparth5/wgmon/master/install.sh | WGMON_VERSION=2026.11.0 sh
set -eu

REPO_URL=${WGMON_REPO_URL:-https://github.com/sinhaparth5/wgmon}
DEST=${WGMON_DEST:-/usr/local/bin}

say() { printf 'wgmon: %s\n' "$*"; }
die() { say "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "Linux only"
case $(uname -m) in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "no build for $(uname -m)" ;;
esac
command -v curl > /dev/null || die "needs curl"
command -v sha256sum > /dev/null || die "needs sha256sum"
sudo=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo > /dev/null || die "run as root (no sudo found)"
    sudo=sudo
fi

# Latest release = where /releases/latest redirects to.
version=${WGMON_VERSION:-$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest" | sed 's|.*/||')}
case $version in
    20[0-9][0-9].*) ;;
    *) die "no release found at $REPO_URL/releases" ;;
esac

current=$("$DEST/wgmon" --version 2> /dev/null | awk '{print $2}') || current=""
if [ "$current" = "$version" ]; then
    say "already on $version"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bin=wgmon-linux-$arch
say "downloading $version ($arch)"
curl -fsSL -o "$tmp/$bin" "$REPO_URL/releases/download/$version/$bin"
curl -fsSL -o "$tmp/SHA256SUMS" "$REPO_URL/releases/download/$version/SHA256SUMS"
(cd "$tmp" && grep " $bin\$" SHA256SUMS | sha256sum -c -) > /dev/null 2>&1 || die "checksum mismatch, nothing installed"

# Stage next to the target, then rename: atomic, and works while an old wgmon is running.
$sudo mkdir -p "$DEST"
$sudo cp "$tmp/$bin" "$DEST/.wgmon.new"
$sudo chmod 0755 "$DEST/.wgmon.new"
if command -v setcap > /dev/null; then
    # net_raw: capture packets; net_admin: read peer status from the WireGuard module (like `wg show`).
    # File caps don't survive replacement, so redo each time.
    $sudo setcap cap_net_raw,cap_net_admin+ep "$DEST/.wgmon.new"
    caps=1
fi
$sudo mv -f "$DEST/.wgmon.new" "$DEST/wgmon"

say "installed $version${current:+ (was $current)} → $DEST/wgmon"
[ -n "${caps:-}" ] || say "setcap not found (apt install libcap2-bin): run wgmon with sudo, or install it and rerun this"
say "run: wgmon --peer 10.8.0.2=phone --peer 10.8.0.3=laptop"
