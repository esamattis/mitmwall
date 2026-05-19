# mitmwall

mitmwall locks down outbound network access on an Ubuntu server by combining
Linux packet filtering with [mitmproxy](https://mitmproxy.org/) running as a
transparent proxy.

mitmwall uses `iptables`/`ip6tables` for the network-level enforcement that
prevents bypasses, while mitmproxy handles HTTP(S) hostname allowlist decisions
for traffic redirected to it.

The goal is to prevent misbehaving AI agents, compromised npm packages, or other
untrusted local processes from making unexpected outbound connections. Direct
outbound HTTP and HTTPS traffic is transparently redirected through mitmproxy and
blocked unless the destination hostname matches an allow rule.

## How it works

- `mitmwall.service` starts `mitmweb` in transparent proxy mode
- `ExecStartPre` installs `iptables`/`ip6tables` rules that:
  - redirect outbound TCP port `80` and `443` traffic to the local proxy;
  - allow the dedicated `mitmwall` proxy user to make upstream connections;
  - allow DNS so clients can resolve hostnames;
  - drop other new outbound traffic so applications cannot bypass the proxy.
- The mitmproxy addon in `/opt/mitmwall/mitmwall_addon.py` loads
  `/opt/mitmwall/rules.toml` and kills HTTP(S) flows whose host does not match
  the allowlist.
- `ExecStopPost` removes the firewall rules when the service stops.

If `/opt/mitmwall/rules.toml` is missing or invalid, mitmwall fails closed and
blocks all proxied HTTP(S) traffic.

## Install

Run on the Ubuntu server as a sudo-capable user:

```console
sudo ./install.sh
```

The installer creates a `mitmwall` system user, installs mitmproxy under
`/opt/mitmwall`, installs the systemd service, generates the mitmproxy CA, and
adds the CA to the system trust store with `update-ca-certificates`.


## Usage

Enable at boot and start immediately:

```console
sudo systemctl enable --now mitmwall
```

Restart after changing rules:

```console
sudo systemctl restart mitmwall
```

Stop mitmwall and remove its iptables/ip6tables rules:

```console
sudo systemctl stop mitmwall
```

Start again with

```console
sudo systemctl start mitmwall
```

## Allowlist rules

Rules are stored in `/opt/mitmwall/rules.toml`. The file is TOML and contains
zero or more `[[allow]]` tables. Traffic is blocked unless the request hostname
matches at least one allow rule.

```toml
# Each [[allow]] table must use exactly one of:
# - domain: a non-empty hostname string
# - domain_regex: a non-empty Python regular expression string
#
# include_subdomains is optional, valid only with domain, and defaults to false.
# Unsupported keys are rejected. A rule cannot contain both domain and domain_regex.
# Hostnames are normalized before matching by trimming whitespace, removing a
# trailing dot, and lowercasing.

# Exact domain only: allows github.com, but not api.github.com.
[[allow]]
domain = "github.com"
include_subdomains = false

# Domain and all subdomains: allows example.com and api.example.com.
[[allow]]
domain = "example.com"
include_subdomains = true

# Python regex, compiled case-insensitively against the normalized hostname.
[[allow]]
domain_regex = '(^|\.)ipinfo\.io$'
```

After editing `/opt/mitmwall/rules.toml`, restart the service:

```console
sudo systemctl restart mitmwall
```

## Logs

mitmwall writes logs under:

```text
# The plugin logs
/opt/mitmwall/logs/mitmwall.log

# The mitmweb logs
/opt/mitmwall/logs/mitmweb.log
```

The main service can also be inspected through systemd:

```console
sudo journalctl -u mitmwall
```

## System environment variables

The installer reads the plain env file [`system_enviroment`](system_enviroment)
to build the mitmwall-managed CA environment block written to `/etc/environment`
and `/etc/profile.d/mitmwall.sh`. These variables point common runtimes and TLS
libraries, at the mitmproxy CA certificate or the rebuilt system CA bundle so
HTTPS clients can trust certificates generated while mitmwall is intercepting
traffic.

## Web interface

mitmweb listens on port `58081`.

The password can be viewed as an administrator from the generated mitmweb config:

```console
sudo grep '^web_password:' /opt/mitmwall/mitmweb.yaml
```
