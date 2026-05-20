#!/bin/sh

set -eu

# mitmwall is Linux-specific and installs Linux/systemd/firewall integration.
if [ "$(uname -s)" != "Linux" ]; then
    echo "uninstall.sh: Linux is required" >&2
    exit 1
fi

# Uninstalling modifies systemd units, firewall rules, /opt, trusted CA
# certificates, environment files, and the dedicated runtime user.
if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: must be run as root" >&2
    exit 1
fi

user=mitmwall
optdir=/opt/mitmwall
etcdir=/etc/mitmwall
servicefile=/etc/systemd/system/mitmwall.service
ca_cert_dir=/usr/local/share/ca-certificates/extra
ca_cert_file=$ca_cert_dir/mitmproxy-ca-cert.crt
environment_file=/etc/environment
profile_file=/etc/profile.d/mitmwall.sh
zshenv_file=/etc/zsh/zshenv

scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

warn() {
    echo "uninstall.sh: warning: $*" >&2
}

remove_managed_block() {
    file=$1
    mode=$2

    if [ ! -f "$file" ]; then
        return 0
    fi

    sed '/^# mitmwall-start$/,/^# mitmwall-end$/d' "$file" >"$tmpdir/$(basename "$file").clean"
    install -m "$mode" "$tmpdir/$(basename "$file").clean" "$file"
}

# Stop and disable the service before removing files. Stopping the service also
# runs ExecStopPost, which clears the managed iptables/ip6tables rules when the
# unit is still present.
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop mitmwall.service >/dev/null 2>&1 || true
    systemctl disable mitmwall.service >/dev/null 2>&1 || true
else
    warn "systemctl not found; skipping systemd stop/disable"
fi

# Clear firewall rules directly as well. This keeps uninstall useful if the
# service was not running, was already removed, or failed before ExecStopPost.
iptables_helper=
if [ -x "$optdir/iptables.sh" ]; then
    iptables_helper=$optdir/iptables.sh
elif [ -x "$scriptdir/iptables.sh" ]; then
    iptables_helper=$scriptdir/iptables.sh
fi

if [ -n "$iptables_helper" ]; then
    "$iptables_helper" clear || warn "failed to clear mitmwall firewall rules"
else
    warn "iptables helper not found; skipping firewall cleanup"
fi

# Remove the systemd unit and reload systemd so it forgets the service.
rm -f "$servicefile"
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || warn "failed to reload systemd"
    systemctl reset-failed mitmwall.service >/dev/null 2>&1 || true
fi

# Remove the mitmproxy CA certificate from the system trust source directory and
# rebuild the OS trust bundle when the platform provides update-ca-certificates.
rm -f "$ca_cert_file"
rmdir "$ca_cert_dir" >/dev/null 2>&1 || true
if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates || warn "failed to update CA certificates"
else
    warn "update-ca-certificates not found; skipping CA bundle refresh"
fi

# Remove environment variable integration installed by install.sh.
remove_managed_block "$environment_file" 0644
rm -f "$profile_file"
remove_managed_block "$zshenv_file" 0644

# Remove installed mitmwall files except operator-managed configuration. Keep
# /etc/mitmwall so local rules and addon settings survive uninstall/reinstall.
# Remove the installed binaries, generated mitmproxy CA material, and mitmweb
# configuration under /opt/mitmwall.
rm -rf "$optdir"

# Remove the dedicated runtime account that install.sh created. If removal
# fails because the account still owns running processes, leave it in place and
# tell the operator rather than failing after the rest of uninstall completed.
if id "$user" >/dev/null 2>&1; then
    if command -v userdel >/dev/null 2>&1; then
        if ! userdel -r "$user"; then
            warn "failed to remove user '$user'; stop its processes and remove it manually"
        fi
    else
        warn "userdel not found; user '$user' was not removed"
    fi
fi

cat <<EOF
mitmwall uninstalled.

Removed:
  - systemd unit: $servicefile
  - installation directory: $optdir
  - CA certificate source: $ca_cert_file
  - mitmwall-managed environment block: $environment_file

Preserved:
  - configuration directory: $etcdir

EOF
