#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must be run as root" >&2
    exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
    echo "install.sh: systemd is required" >&2
    exit 1
fi

user=mitmwall
case "$(uname -m)" in
    x86_64|amd64)
        url=https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-linux-x86_64.tar.gz
        ;;
    aarch64|arm64)
        url=https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-linux-aarch64.tar.gz
        ;;
    *)
        echo "install.sh: unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac
optdir=/opt/mitmwall
bindir=$optdir
mitmproxy_confdir=/home/$user/.mitmproxy
servicefile=/etc/systemd/system/mitmwall.service
ca_cert_dir=/usr/local/share/ca-certificates/extra
ca_cert_file=$ca_cert_dir/mitmproxy-ca-cert.crt
environment_file=/etc/environment
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

if ! id "$user" >/dev/null 2>&1; then
    useradd --create-home "$user"
fi

install -d -m 0755 "$optdir"
install -d -o "$user" -m 0700 "$optdir/logs"
touch "$optdir/logs/mitmwall.log" "$optdir/logs/mitmweb.log" "$optdir/web_password.txt"
chown "$user" "$optdir/logs" "$optdir/logs/mitmwall.log" "$optdir/logs/mitmweb.log" "$optdir/web_password.txt"
chmod 0700 "$optdir/logs"
chmod 0600 "$optdir/logs/mitmwall.log" "$optdir/logs/mitmweb.log" "$optdir/web_password.txt"
install -m 0755 "$scriptdir/add-iptables.sh" "$scriptdir/clear-iptables.sh" "$scriptdir/start.sh" "$optdir/"
install -m 0644 "$scriptdir/mitmwall_addon.py" "$optdir/"
if [ ! -f "$optdir/rules.toml" ]; then
    install -o "$user" -m 0600 "$scriptdir/rules.toml" "$optdir/rules.toml"
fi
chown "$user" "$optdir/rules.toml"
chmod 0600 "$optdir/rules.toml"

cat >"$servicefile" <<EOF
[Unit]
Description=mitmwall transparent mitmproxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
ExecStartPre=+$optdir/add-iptables.sh
ExecStart=$optdir/start.sh
ExecStopPost=+$optdir/clear-iptables.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmpdir/mitmproxy.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmpdir/mitmproxy.tar.gz" "$url"
else
    echo "install.sh: either curl or wget is required to download mitmproxy" >&2
    exit 1
fi

tar -xzf "$tmpdir/mitmproxy.tar.gz" -C "$tmpdir"

installed=0
for binary in "$tmpdir"/mitm* "$tmpdir"/*/mitm*; do
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        install -m 0755 "$binary" "$bindir/$(basename "$binary")"
        installed=1
    fi
done

if [ "$installed" -eq 0 ]; then
    echo "install.sh: no mitm* binaries found in downloaded archive" >&2
    exit 1
fi

if [ ! -f "$mitmproxy_confdir/mitmproxy-ca-cert.pem" ]; then
    # generate mitmproxy CA certificates
    echo "generating mitmproxy CA certificates"
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    else
        sudo -u "$user" "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    fi
fi

mkdir -p "$ca_cert_dir"
openssl x509 -in "$mitmproxy_confdir/mitmproxy-ca-cert.pem" -inform PEM -out "$ca_cert_file"
update-ca-certificates

environment_source=/dev/null
if [ -f "$environment_file" ]; then
    environment_source=$environment_file
fi
sed '/^# mitmwall-start$/,/^# mitmwall-end$/d' "$environment_source" >"$tmpdir/environment"
cat >>"$tmpdir/environment" <<EOF
# mitmwall-start
NODE_EXTRA_CA_CERTS="$ca_cert_file"
# mitmwall-end
EOF
install -m 0644 "$tmpdir/environment" "$environment_file"

cat <<EOF

mitmwall installed successfully.

To enable mitmwall on boot:
  sudo systemctl enable mitmwall

To enable mitmwall on boot and start it now:
  sudo systemctl enable --now mitmwall

To start mitmwall:
  sudo systemctl start mitmwall

To stop mitmwall:
  sudo systemctl stop mitmwall

To check mitmwall status:
  sudo systemctl status mitmwall

EOF
