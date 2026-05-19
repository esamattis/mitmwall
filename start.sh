#!/bin/sh

set -eu

bindir=/opt/mitmwall
confdir=/home/mitmwall/.mitmproxy
password_file=$bindir/web_password.txt

password=$(openssl rand -base64 32)
umask 077
printf '%s\n' "$password" >"$password_file"
chmod 0600 "$password_file"

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
