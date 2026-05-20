#!/bin/sh

set -eu

# This installer is safe to run multiple times. Re-running it updates managed
# files and binaries while preserving local runtime state such as rules.toml,
# mitmweb/config.yaml, and generated mitmproxy CA material.

# This installer must run as root because it creates a dedicated system user,
# writes under /opt, installs a systemd unit, updates trusted CA certificates,
# and writes environment variables to /etc/environment.
if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must be run as root" >&2
    exit 1
fi

# mitmwall is managed as a systemd service. Refuse to continue on systems where
# systemctl is not available, because the generated service file and reload step
# would not be useful there.
if ! command -v systemctl >/dev/null 2>&1; then
    echo "install.sh: systemd is required" >&2
    exit 1
fi

# The service runs as an unprivileged dedicated user. Keeping mitmproxy and the
# addon out of root's runtime context reduces the blast radius if either the web
# UI or proxy process is compromised.
user=mitmwall

# Select the prebuilt mitmproxy archive that matches the host CPU architecture.
# Unsupported architectures stop here instead of downloading an incompatible
# binary that would fail later during service startup. Sadly the mitmproxy
# package on Ubuntu is broken so we cannot use that.
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

# Centralized installation paths. Everything that belongs to mitmwall itself is
# kept under /opt/mitmwall, while OS integration points live in their standard
# system locations.
optdir=/opt/mitmwall
bindir=$optdir/bin
mitmproxy_confdir=$optdir/mitmweb
mitmweb_config_file=$mitmproxy_confdir/config.yaml
servicefile=/etc/systemd/system/mitmwall.service
ca_cert_dir=/usr/local/share/ca-certificates/extra
ca_cert_file=$ca_cert_dir/mitmproxy-ca-cert.crt
ca_bundle_file=/etc/ssl/certs/ca-certificates.crt
environment_file=/etc/environment
profile_file=/etc/profile.d/mitmwall.sh
zshenv_file=/etc/zsh/zshenv

# Resolve the directory containing this installer so files can be copied from
# the source checkout regardless of the caller's current working directory.
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
system_environment_source=$scriptdir/system_enviroment

# Use a temporary workspace for downloaded archives and generated intermediate
# files. The trap removes the workspace on both success and failure so repeated
# installs do not leave stale tarballs behind.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Create the dedicated runtime user if it does not already exist. mitmproxy's
# config and generated CA material are kept under /opt/mitmwall/mitmweb and are
# referenced explicitly via confdir, so the account's OS home is not used for
# mitmwall runtime state.
if ! id "$user" >/dev/null 2>&1; then
    useradd --create-home "$user"
fi

# Create /opt/mitmwall and the private runtime directories. The top-level and
# binary directories are world-readable/executable so systemd can locate scripts
# and mitmproxy binaries, while mitmproxy state is kept private because it may
# include generated CA keys and the web UI password. Service logs are handled by
# systemd journal.
install -d -m 0755 "$optdir" "$bindir"
if [ -e "$mitmproxy_confdir" ] && [ ! -d "$mitmproxy_confdir" ]; then
    rm -f "$mitmproxy_confdir"
fi
install -d -o "$user" -m 0700 "$mitmproxy_confdir"

# Generate mitmweb's YAML config once during installation. Keeping the file if
# it already exists avoids changing the web UI password on every reinstall or
# service restart.
if [ ! -f "$mitmweb_config_file" ]; then
    # Keep the generated password private from the moment the file is created.
    # Without this, the file could briefly be world-readable before chmod below.
    umask 077
    password=$(openssl rand -base64 32)
    printf 'web_password: "%s"\n' "$password" >"$mitmweb_config_file"
fi

# Lock down ownership and permissions for runtime state. The mitmweb confdir is
# readable only by the mitmwall user/root, preventing other local users from
# reading generated CA keys or the generated admin password.
chown "$user" "$mitmproxy_confdir" "$mitmweb_config_file"
chmod 0700 "$mitmproxy_confdir"
chmod 0600 "$mitmweb_config_file"

# Install the helper scripts used by systemd. iptables.sh is run as privileged
# ExecStartPre/ExecStopPost hooks, while start.sh launches mitmweb as the
# unprivileged mitmwall user.
install -m 0755 "$scriptdir/iptables.sh" "$scriptdir/start.sh" "$optdir/"

# Install the mitmproxy addon that enforces the allow/block rules.
install -m 0644 "$scriptdir/mitmwall_addon.py" "$optdir/"

# Install the default rules file only on first install. Existing rules are
# preserved so local policy changes are not overwritten by upgrades or reruns of
# this installer.
if [ ! -f "$optdir/rules.toml" ]; then
    install -o "$user" -m 0600 "$scriptdir/rules.toml" "$optdir/rules.toml"
fi
chown "$user" "$optdir/rules.toml"
chmod 0600 "$optdir/rules.toml"

# Register the systemd service. The iptables hooks are prefixed with '+' so they
# run with elevated privileges even though the main service process runs as the
# unprivileged mitmwall user. The service waits for network-online.target because
# transparent proxying depends on networking being configured.
cat >"$servicefile" <<EOF
[Unit]
Description=mitmwall transparent mitmproxy service
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
systemctl daemon-reload

# Download the selected mitmproxy archive. Prefer curl when available, with wget
# as a fallback, and stop with a clear error if neither downloader is installed.
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$tmpdir/mitmproxy.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmpdir/mitmproxy.tar.gz" "$url"
else
    echo "install.sh: either curl or wget is required to download mitmproxy" >&2
    exit 1
fi

# Unpack the downloaded archive into the temporary workspace. The following
# install loop searches both the archive root and one nested directory because
# release archive layouts can vary.
tar -xzf "$tmpdir/mitmproxy.tar.gz" -C "$tmpdir"

# Copy every executable mitm* binary from the archive into /opt/mitmwall/bin.
# This includes mitmweb, mitmdump, mitmproxy, and any companion binaries shipped by
# the release. Track whether anything was installed so archive/layout problems
# are caught immediately.
installed=0
for binary in "$tmpdir"/mitm* "$tmpdir"/*/mitm*; do
    if [ -f "$binary" ] && [ -x "$binary" ]; then
        install -m 0755 "$binary" "$bindir/$(basename "$binary")"
        installed=1
    fi
done

# Fail loudly if the archive did not contain executable mitm* binaries. Without
# this check, the service could be installed but fail later with a missing
# mitmweb/mitmdump executable.
if [ "$installed" -eq 0 ]; then
    echo "install.sh: no mitm* binaries found in downloaded archive" >&2
    exit 1
fi

# Generate mitmproxy's local certificate authority if it does not already exist.
# mitmproxy creates the CA bundle lazily on first startup, so this runs mitmdump
# in a no-server mode as the mitmwall user to create the files with the correct
# ownership and under the correct confdir.
if [ ! -f "$mitmproxy_confdir/mitmproxy-ca-cert.pem" ]; then
    echo "generating mitmproxy CA certificates"
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    else
        sudo -u "$user" "$bindir/mitmdump" --set confdir="$mitmproxy_confdir" --no-server --rfile /dev/null
    fi
fi

# Install the generated mitmproxy CA certificate into the system trust store.
# This lets local tools trust TLS certificates generated by mitmproxy while
# traffic is transparently intercepted. update-ca-certificates rebuilds the OS
# CA bundle after the new certificate is written.
mkdir -p "$ca_cert_dir"
openssl x509 -in "$mitmproxy_confdir/mitmproxy-ca-cert.pem" -inform PEM -out "$ca_cert_file"
update-ca-certificates

# Update /etc/environment and shell startup files with trust-store variables
# for common runtimes and libraries. Read the variable definitions from the
# repository-managed system_enviroment file so the list exists outside this
# installer. The managed marker block makes the files idempotent: on each
# install, the old mitmwall block is removed and a fresh one is appended without
# disturbing unrelated environment settings.
if [ ! -f "$system_environment_source" ]; then
    echo "install.sh: missing system environment source: $system_environment_source" >&2
    exit 1
fi

environment_values=$(cat "$system_environment_source")

environment_block=$(cat <<EOF
# mitmwall-start
$environment_values
# mitmwall-end
EOF
)

# Shell startup files need export prefixes, unlike /etc/environment. Derive this
# from the same block so the variable list only exists in one place.
shell_environment_block=$(printf '%s\n' "$environment_block" | sed '/^[A-Za-z_][A-Za-z0-9_]*=/s/^/export /')

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

# /etc/environment is read by PAM at login time, but POSIX-style login shells
# also source /etc/profile.d/*.sh. Write the same values there so new sh/bash
# sessions can pick them up.
printf '%s\n' "$shell_environment_block" >"$tmpdir/profile"
install -d -m 0755 /etc/profile.d
install -m 0644 "$tmpdir/profile" "$profile_file"

# Print next-step commands instead of enabling or starting the service
# automatically. This keeps installation side effects explicit and lets the
# operator decide when mitmwall should begin changing network traffic.
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

To load mitmwall CA environment variables in your current shell:
  . /etc/profile.d/mitmwall.sh

EOF
