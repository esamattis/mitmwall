#!/bin/sh

set -eu

optdir=/opt/mitmwall
bindir=$optdir/bin
confdir=$optdir/mitmweb
config_file=$confdir/config.yaml
addon_entrypoint=$optdir/mitmproxy_addon/main.py

if [ ! -r "$config_file" ]; then
    echo "start.sh: missing mitmweb config: $config_file" >&2
    exit 1
fi

if [ ! -r "$addon_entrypoint" ]; then
    echo "start.sh: missing mitmproxy addon entrypoint: $addon_entrypoint" >&2
    exit 1
fi

echo "Starting mitmwall..."

exec "$bindir/mitmweb" \
  --set confdir="$confdir" \
  --listen-port 58080 \
  --web-port 58081 \
  --mode transparent \
  --showhost \
  -s "$addon_entrypoint"
