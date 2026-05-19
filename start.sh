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

# Write password to config file so it doesn't appear in ps output
config_file="$confdir/config.yaml"
mkdir -p "$confdir"
printf 'web_password: "%s"\n' "$password" > "$config_file"
chmod 600 "$config_file"

echo "Starting mitmwall..."

exec "$bindir/mitmweb" \
  --set confdir="$confdir" \
  --listen-port 58080 \
  --web-port 58081 \
  --mode transparent \
  --showhost \
  -s "$bindir/mitmwall_addon.py" \
  >>"$bindir/logs/mitmweb.log" 2>&1
