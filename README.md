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

Rules are stored in:

```text
/opt/mitmwall/rules.toml
```

The file is TOML. It contains zero or more `[[allow]]` tables. Traffic is blocked
unless the request hostname matches at least one allow rule.

### Exact domain rule

```toml
[[allow]]
domain = "github.com"
include_subdomains = false
```

This allows only `github.com`. It does not allow `api.github.com` or
`www.github.com`.

### Domain with subdomains

```toml
[[allow]]
domain = "example.com"
include_subdomains = true
```

This allows `example.com` and any subdomain, such as `api.example.com` or
`downloads.example.com`.

### Regular expression rule

```toml
[[allow]]
domain_regex = '(^|\.)ipinfo\.io$'
```

This allows any hostname matched by the Python regular expression. Regex rules
are compiled case-insensitively and are matched against the normalized hostname.

### Full example

```toml
# /opt/mitmwall/rules.toml

[[allow]]
domain = "github.com"
include_subdomains = true

[[allow]]
domain = "downloads.mitmproxy.org"
include_subdomains = false

[[allow]]
domain = "esamatti.fi"
include_subdomains = false

[[allow]]
domain_regex = '(^|\.)ipinfo\.io$'
```

### Rule format reference

Each `[[allow]]` table must use exactly one of:

- `domain`: a non-empty hostname string.
- `domain_regex`: a non-empty Python regular expression string.

Optional keys:

- `include_subdomains`: boolean, only valid with `domain`; defaults to `false`.

Unsupported keys are rejected. A rule cannot contain both `domain` and
`domain_regex`.

Hostnames are normalized before matching by trimming whitespace, removing a
trailing dot, and lowercasing.

After editing `/opt/mitmwall/rules.toml`, restart the service:

```console
sudo systemctl restart mitmwall
```

## Logs

mitmwall writes logs under:

```text
/opt/mitmwall/logs/
```

Important files:

- `/opt/mitmwall/logs/mitmwall.log` — allowlist loading, allowed requests, and
  blocked requests.
- `/opt/mitmwall/logs/mitmweb.log` — mitmweb/mitmproxy process output.

The main service can also be inspected through systemd:

```console
sudo journalctl -u mitmwall
```
