#!/bin/sh

set -eu

info() {
    echo "install.sh: $*"
}

die() {
    echo "install.sh: $*" >&2
    exit 1
}

# Keep uninstall.sh up to date with every system integration point this installer
# adds so uninstall removes the same files, services, users, certificates, and
# environment changes.

# This installer is safe to run multiple times. Re-running it updates managed
# files and binaries while preserving local operator state such as
# /etc/mitmwall, mitmweb/config.yaml, and generated mitmproxy CA material.

# mitmwall depends on Linux-specific facilities such as systemd, iptables,
# ip6tables, user management commands, and the Linux mitmproxy binary.
if [ "$(uname -s)" != "Linux" ]; then
    die "Linux is required"
fi

# This installer must run as root because it creates a dedicated system user,
# writes under /opt, installs a systemd unit, updates trusted CA certificates,
# and writes environment variables to /etc/environment.
if [ "$(id -u)" -ne 0 ]; then
    die "must be run as root"
fi

# mitmwall is managed as a systemd service. Refuse to continue on systems where
# systemctl is not available, because the generated service file and reload step
# would not be useful there.
if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd is required"
fi

# The service runs as an unprivileged dedicated user. Keeping mitmproxy and the
# addon out of root's runtime context reduces the blast radius if either the web
# UI or proxy process is compromised.
user=mitmwall

# Select the prebuilt mitmproxy archive that matches the host CPU architecture.
# Unsupported architectures stop here instead of downloading an incompatible
# binary that would fail later during service startup. Sadly the mitmproxy
# package on Ubuntu is broken so we cannot use that.
arch=$(uname -m)
case "$arch" in
    x86_64|amd64)
        url=https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-linux-x86_64.tar.gz
        ;;
    aarch64|arm64)
        url=https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-linux-aarch64.tar.gz
        ;;
    *)
        die "unsupported architecture: $arch"
        ;;
esac

# Centralized installation paths. Executables and mitmproxy runtime state live
# under /opt/mitmwall, while operator-managed configuration lives under
# /etc/mitmwall.
optdir=/opt/mitmwall
bindir=$optdir/bin
etcdir=/etc/mitmwall
rulesdir=$etcdir/rules.d
addon_config_file=$etcdir/config.toml
addon_dir=$optdir/mitmproxy_addon
mitmproxy_confdir=$optdir/mitmweb
mitmweb_config_file=$mitmproxy_confdir/config.yaml
servicefile=/etc/systemd/system/mitmwall.service
ca_cert_dir=/usr/local/share/ca-certificates/extra
ca_cert_file=$ca_cert_dir/mitmproxy-ca-cert.crt
environment_file=/etc/environment
profile_file=/etc/profile.d/mitmwall.sh

# Resolve the directory containing this installer so files can be copied from
# the source checkout regardless of the caller's current working directory.
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
system_environment_source=$scriptdir/system_enviroment

# Use a temporary workspace for downloaded archives and generated intermediate
# files. The trap removes the workspace on both success and failure so repeated
# installs do not leave stale tarballs behind.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

info "starting installation from $scriptdir for architecture $arch"

# Create the dedicated runtime user if it does not already exist. mitmproxy's
# config and generated CA material are kept under /opt/mitmwall/mitmweb and are
# referenced explicitly via confdir, so the account's OS home is not used for
# mitmwall runtime state. Create a system account without a home directory or
# login shell to reduce filesystem footprint and interactive use.
if ! id "$user" >/dev/null 2>&1; then
    info "creating system user $user"
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
else
    info "reusing existing system user $user"
fi
user_group=$(id -gn "$user")

# Create /opt/mitmwall for executables and /etc/mitmwall for operator-managed
# configuration. The top-level and binary directories are world-readable/
# executable so systemd can locate scripts and mitmproxy binaries, while
# mitmproxy state is kept private because it may include generated CA keys and
# the web UI password. Service logs are handled by systemd journal.
info "preparing installation directories under $optdir and $etcdir"
install -d -m 0755 "$optdir" "$bindir"
install -d -o root -g "$user_group" -m 0750 "$etcdir" "$rulesdir"
chown root:"$user_group" "$etcdir" "$rulesdir"
chmod 0750 "$etcdir" "$rulesdir"

# Create the addon configuration once so local logging preferences are
# preserved across reinstallation.
if [ ! -f "$addon_config_file" ]; then
    info "creating default addon config at $addon_config_file"
    install -o root -g "$user_group" -m 0640 "$scriptdir/addon-config.toml" "$addon_config_file"
fi
chown root:"$user_group" "$addon_config_file"
chmod 0640 "$addon_config_file"
if [ -e "$mitmproxy_confdir" ] && [ ! -d "$mitmproxy_confdir" ]; then
    rm -f "$mitmproxy_confdir"
fi
install -d -o "$user" -m 0700 "$mitmproxy_confdir"

# Generate mitmweb's YAML config once during installation. Keeping the file if
# it already exists avoids changing the web UI password on every reinstall or
# service restart.
generated_web_password=
if [ ! -f "$mitmweb_config_file" ]; then
    info "creating mitmweb config at $mitmweb_config_file"
    # Keep the generated password private from the moment the file is created.
    # Without this, the file could briefly be world-readable before chmod below.
    umask 077
    password=$(openssl rand -base64 20 | tr -d '+/=' )
    generated_web_password=$password
    printf 'web_password: "%s"\n' "$password" >"$mitmweb_config_file"
fi

# Lock down ownership and permissions for runtime state. The mitmweb confdir is
# readable only by the mitmwall user/root, preventing other local users from
# reading generated CA keys or the generated admin password.
chown "$user" "$mitmproxy_confdir" "$mitmweb_config_file"
chmod 0700 "$mitmproxy_confdir"
chmod 0600 "$mitmweb_config_file"

# Install the helper scripts used by systemd. iptables.sh is run as privileged
# ExecStartPre/ExecStopPost hooks, while start.sh launches mitmweb in transparent
# HTTP(S) mode and DNS mode as the unprivileged mitmwall user.
info "installing service helper scripts into $optdir"
install -m 0755 "$scriptdir/iptables.sh" "$scriptdir/start.sh" "$scriptdir/custom_iptables.py" "$optdir/"

# Install the mitmproxy addon package that enforces the allow/block rules.
# Remove the previous single-file addon path and any old package directory so
# upgrades do not leave stale code behind.
info "installing mitmproxy addon into $addon_dir"
rm -f "$optdir/mitmwall_addon.py"
rm -rf "$optdir/mitmwall_addon" "$addon_dir"
install -d -m 0755 "$addon_dir"
install -m 0644 "$scriptdir"/mitmproxy_addon/*.py "$addon_dir/"

# Install the repository-provided example rules into the rules directory. Rule
# files are loaded in alphabetical filename order, so the numeric prefix gives
# operators a predictable place for the managed examples relative to their own
# files. Remove the legacy managed filename first so upgrades do not leave a
# duplicate example ruleset behind.
rm -f "$rulesdir/examples.toml"
install -o root -g "$user_group" -m 0640 "$scriptdir/example-rules.toml" "$rulesdir/5-examples.toml"

# Register the systemd service. The iptables hooks are prefixed with '+' so they
# run with elevated privileges even though the main service process runs as the
# unprivileged mitmwall user. The service waits for network-online.target because
# transparent proxying depends on networking being configured.
info "writing systemd unit to $servicefile"
cat >"$servicefile" <<EOF
[Unit]
Description=mitmwall transparent HTTP(S) and DNS mitmproxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$user
ExecStartPre=+$optdir/iptables.sh add
ExecStart=$optdir/start.sh
ExecStopPost=+$optdir/iptables.sh clear
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Tell systemd to reload unit definitions so the newly written/updated service
# file is visible to systemctl without requiring a reboot.
info "reloading systemd unit definitions"
systemctl daemon-reload

# Download the selected mitmproxy archive. Prefer curl when available, with wget
# as a fallback, and stop with a clear error if neither downloader is installed.
if command -v curl >/dev/null 2>&1; then
    info "downloading mitmproxy archive with curl from $url"
    curl -fsSL "$url" -o "$tmpdir/mitmproxy.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    info "downloading mitmproxy archive with wget from $url"
    wget -qO "$tmpdir/mitmproxy.tar.gz" "$url"
else
    die "either curl or wget is required to download mitmproxy"
fi

# Unpack the downloaded archive into the temporary workspace. The following
# install loop searches both the archive root and one nested directory because
# release archive layouts can vary.
info "extracting mitmproxy archive"
tar -xzf "$tmpdir/mitmproxy.tar.gz" -C "$tmpdir"

# Copy every executable mitm* binary from the archive into /opt/mitmwall/bin.
# This includes mitmweb, mitmdump, mitmproxy, and any companion binaries shipped by
# the release. Track whether anything was installed so archive/layout problems
# are caught immediately.
installed=0
for binary in "$tmpdir"/mitm* "$tmpdir"/*/mitm*; do
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        install -m 0755 "$binary" "$bindir/$(basename "$binary")"
        installed=$((installed + 1))
    fi
done

# Fail loudly if the archive did not contain executable mitm* binaries. Without
# this check, the service could be installed but fail later with a missing
# mitmweb/mitmdump executable.
if [ "$installed" -eq 0 ]; then
    die "no mitm* binaries found in downloaded archive"
fi
info "installed $installed mitmproxy binaries into $bindir"

# Generate mitmproxy's local certificate authority if it does not already exist.
# mitmproxy creates the CA bundle lazily on first startup, so this runs mitmdump
# in a no-server mode as the mitmwall user to create the files with the correct
# ownership and under the correct confdir.
if [ ! -f "$mitmproxy_confdir/mitmproxy-ca-cert.pem" ]; then
    info "generating mitmproxy CA certificates"
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    else
        sudo -u "$user" "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    fi
fi

# Install the generated mitmproxy CA certificate into the system trust store.
# This lets local tools trust TLS certificates generated by mitmproxy while
# traffic is transparently intercepted. update-ca-certificates rebuilds the OS
# CA bundle after the new certificate is written. The certificate must be
# world-readable because runtimes such as Node.js read NODE_EXTRA_CA_CERTS as
# the invoking user, not as root.
info "installing mitmproxy CA certificate into the system trust store"
install -d -m 0755 "$ca_cert_dir"
openssl x509 -in "$mitmproxy_confdir/mitmproxy-ca-cert.pem" -inform PEM -out "$tmpdir/mitmproxy-ca-cert.crt"
install -m 0644 "$tmpdir/mitmproxy-ca-cert.crt" "$ca_cert_file"
update-ca-certificates

# Update /etc/environment with trust-store variables for common runtimes and
# libraries. Read the variable definitions from the repository-managed
# system_enviroment file so the list exists outside this installer. The managed
# marker block makes the file idempotent: on each install, the old mitmwall
# block is removed and a fresh one is appended without disturbing unrelated
# environment settings.
if [ ! -f "$system_environment_source" ]; then
    die "missing system environment source: $system_environment_source"
fi

info "updating environment integration in $environment_file and $profile_file"

environment_values=$(cat "$system_environment_source")

environment_block=$(cat <<EOF
# mitmwall-start
$environment_values
# mitmwall-end
EOF
)

# Start from /dev/null when /etc/environment does not exist so the same sed
# pipeline can be used for both fresh installs and updates.
environment_source=/dev/null
if [ -f "$environment_file" ]; then
    environment_source=$environment_file
fi

# Remove any previously managed block before appending the current values. This
# keeps repeated installs from accumulating duplicate mitmwall settings.
sed '/^# mitmwall-start$/,/^# mitmwall-end$/d' "$environment_source" >"$tmpdir/environment"
printf '%s\n' "$environment_block" >>"$tmpdir/environment"
install -m 0644 "$tmpdir/environment" "$environment_file"

# Also install a profile script containing the same assignments so operators can
# source it immediately in their current shell session, as shown after install.
# Export the variable names before assignment so the sourced values are inherited
# by child processes.
cat >"$tmpdir/profile" <<EOF
# mitmwall-start
export NODE_EXTRA_CA_CERTS SSL_CERT_FILE REQUESTS_CA_BUNDLE
$environment_values
# mitmwall-end
EOF
install -m 0644 "$tmpdir/profile" "$profile_file"

# If this install is updating an already-running service, restart it so the new
# unit file, helper scripts, mitmproxy binaries, addon code, rules, and trust
# integration take effect. Leave inactive installations stopped so fresh installs
# do not unexpectedly begin changing network traffic.
if systemctl is-active --quiet mitmwall; then
    info "mitmwall already runnning, restarting for the updates to take effect"
    systemctl restart mitmwall
fi

# Print next-step commands instead of enabling or starting the service
# automatically. This keeps installation side effects explicit and lets the
# operator decide when mitmwall should begin changing network traffic.
cat <<EOF

mitmwall installed successfully.

Rule files in /etc/mitmwall/rules.d are loaded in alphabetical filename order.
The managed example rules were installed as /etc/mitmwall/rules.d/5-examples.toml.

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

To view logs:
  sudo journalctl -u mitmwall --no-pager

Apply the new CA environment variables:
   . /etc/profile.d/mitmwall.sh

EOF

if [ -n "$generated_web_password" ]; then
    printf 'Generated mitmweb password: %s\n' "$generated_web_password"
    printf 'Visit http://127.0.0.1:58081/?token=%s\n' "$generated_web_password"
fi
