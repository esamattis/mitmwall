#!/bin/sh

set -eu

bindir=/opt/mitmwall
confdir=/home/mitmwall/.mitmproxy

echo "Starting mitmwall..."

exec "$bindir/mitmweb" \
  --set confdir="$confdir" \
  --listen-port 58080 \
  --web-port 58081 \
  --mode transparent \
  --showhost \
  -s "$bindir/mitmwall_addon.py" \
  >>"$bindir/logs/mitmweb.log" 2>&1
