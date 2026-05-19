#!/bin/sh

set -eu

optdir=/opt/mitmwall
bindir=$optdir/bin
confdir=$optdir/mitmweb
config_file=$confdir/config.yaml

if [ ! -r "$config_file" ]; then
    echo "start.sh: missing mitmweb config: $config_file" >&2
    exit 1
fi

echo "Starting mitmwall..."

exec "$bindir/mitmweb" \
  --set confdir="$confdir" \
  --listen-port 58080 \
  --web-port 58081 \
  --mode transparent \
  --showhost \
  -s "$optdir/mitmwall_addon.py"
