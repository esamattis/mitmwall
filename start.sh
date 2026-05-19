#!/bin/sh

set -eu

bindir=/opt/mitmwall
confdir=/home/mitmwall/.mitmproxy
password_file=$bindir/web_password.txt

if [ ! -r "$password_file" ]; then
    echo "start.sh: missing password file: $password_file" >&2
    exit 1
fi

password=$(cat "$password_file")


echo "Starting mitmwall..."

exec "$bindir/mitmweb" \
  --set confdir="$confdir" \
  --listen-port 58080 \
  --web-port 58081 \
  --set web_password="$password" \
  --mode transparent \
  --showhost \
  -s "$bindir/mitmwall_addon.py" \
  >>"$bindir/logs/mitmweb.log" 2>&1
