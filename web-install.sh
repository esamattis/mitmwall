#!/bin/sh

set -eu

# Download a fresh mitmwall source archive into a temporary workspace so the
# installer can run without leaving extracted files or tarballs behind.
archive_url=https://github.com/esamattis/mitmwall/archive/refs/heads/main.tar.gz
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Reuse the same downloader expectations as install.sh: prefer curl, fall back
# to wget, and fail clearly if neither is available.
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$archive_url" -o "$tmpdir/mitmwall.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmpdir/mitmwall.tar.gz" "$archive_url"
else
    echo "web-install.sh: either curl or wget is required" >&2
    exit 1
fi

# This archive URL is pinned to the main branch, so GitHub extracts it as
# mitmwall-main. Run install.sh from there so relative paths inside the
# installer resolve exactly as in a checkout.
tar -xzf "$tmpdir/mitmwall.tar.gz" -C "$tmpdir"

srcdir=$tmpdir/mitmwall-main

if [ ! -f "$srcdir/install.sh" ]; then
    echo "web-install.sh: install.sh not found in downloaded archive" >&2
    exit 1
fi

sh "$srcdir/install.sh" "$@"
