#!/bin/sh

set -eu

info() {
    echo "web-install.sh: $*"
}

die() {
    echo "web-install.sh: $*" >&2
    exit 1
}

if [ "$(uname -s)" != "Linux" ]; then
    die "uninstall.sh: Linux is required"
fi

# Download a fresh mitmwall source archive into a temporary workspace so the
# installer can run without leaving extracted files or tarballs behind.
archive_url=https://github.com/esamattis/mitmwall/archive/refs/heads/main.tar.gz
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Reuse the same downloader expectations as install.sh: prefer curl, fall back
# to wget, and fail clearly if neither is available.
info "downloading mitmwall source archive from $archive_url"
if command -v curl >/dev/null 2>&1; then
    info "using curl"
    curl -fsSL "$archive_url" -o "$tmpdir/mitmwall.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    info "using wget"
    wget -qO "$tmpdir/mitmwall.tar.gz" "$archive_url"
else
    die "either curl or wget is required"
fi

# This archive URL is pinned to the main branch, so GitHub extracts it as
# mitmwall-main. Run install.sh from there so relative paths inside the
# installer resolve exactly as in a checkout.
info "extracting source archive"
tar -xzf "$tmpdir/mitmwall.tar.gz" -C "$tmpdir"

srcdir=$tmpdir/mitmwall-main

if [ ! -f "$srcdir/install.sh" ]; then
    die "install.sh not found in downloaded archive"
fi

info "running installer from $srcdir/install.sh"
sh "$srcdir/install.sh" "$@"
