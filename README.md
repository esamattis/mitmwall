# mitmwall

mitmwall is a transparent outbound firewall for Ubuntu. It combines `iptables`
with [mitmproxy](https://mitmproxy.org/) to ensure that only explicitly allowed
HTTP(s) routes can be reached. Any network connection that does not match the
allowlist is blocked. This prevents:

- **Data exfiltration** — compromised npm packages, rogue AI agents, or other
  untrusted processes stealing credentials, API keys, or source code.
- **Backdoor connections** — malware phoning home to command-and-control servers.

The built-in mitmweb interface can be used to monitor all proxied traffic in
real time.

The name is a wordplay for mitmproxy + firewall = mitmwall.

## How?

- `mitmwall.service` starts `mitmweb` in transparent proxy mode
- `ExecStartPre` installs `iptables`/`ip6tables` rules that:
  - redirect outbound TCP port `80` and `443` traffic to the local proxy
  - only allow root and the dedicated `mitmwall` user to make upstream connections
    - the proxy is running as the `mitmwall` user
    - root is left unrestricted for host administration and troubleshooting
  - allow DNS only to the local resolver so clients can resolve hostnames
    - only the `systemd-resolve` user can make DNS queries
  - drop other new outbound traffic so applications cannot bypass the proxy
- The mitmproxy addon in `/opt/mitmwall/mitmwall_addon.py` loads TOML files
  from `/opt/mitmwall/rules.d` and kills HTTP(S) flows whose host does not
  match the allowlist.
- `ExecStopPost` removes the firewall rules when the service stops.

If `/opt/mitmwall/rules.d` is missing or any rule file is invalid, mitmwall
fails closed and blocks all proxied HTTP(S) traffic.

## Install

Run on the Ubuntu server as a sudo-capable user:

```console
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/mitmwall/main/web-install.sh)"
```

Or, from a local checkout:

```console
sudo ./install.sh
```

The installer creates a `mitmwall` system user, installs mitmproxy under
`/opt/mitmwall`, creates the initial plugin configuration at
`/opt/mitmwall/plugin_config.toml`, installs the systemd service, generates the
mitmproxy CA, and adds the CA to the system trust store with
`update-ca-certificates`.


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

View logs:

```console
sudo journalctl -u mitmwall.service -f
```


## Allowlist rules

Rules are stored as TOML files in `/opt/mitmwall/rules.d`. Each `*.toml` file
can contain zero or more `[[allow]]` tables. Traffic is blocked unless the
request hostname, HTTP method, and optional pathname filter match at least one
allow rule.

The [example rules](example-rules.toml) from this repository are installed to
`/opt/mitmwall/rules.d/examples.toml`.

### Syntax

```toml
[[allow]]
domain = "example.com"            # Exact hostname to allow (required*).
include_subdomains = true         # Also match *.example.com (default: false).
methods = ["GET", "POST"]         # Allowed HTTP methods (default: ["GET", "HEAD"]).
                                  # Use methods = "ANY" to allow all methods.
pathname_pattern = "/api/:ver/upload"  # URLPattern-style path filter (optional).
pathname_regex = '^/files/.*$'         # Python regex path filter (optional).

[[allow]]
domain_regex = '(^|\.)example\.(com|org)$'  # Python regex for hostname (required*).
methods = "ANY"
```

### Rule constraints

- Each `[[allow]]` must have exactly one of `domain` or `domain_regex`.
- `include_subdomains` is only valid with `domain`.
- At most one of `pathname_pattern` or `pathname_regex` per rule.
- Unknown keys are rejected.

### Matching behavior

- `domain_regex` is matched case-insensitively (partial match).
- `pathname_regex` need only match part of the pathname (partial match).
- `pathname_pattern` must match the entire pathname (full match) and supports:
  - `:param` — matches exactly one path segment (no `/`).
  - `*wildcard` — matches one or more characters (spans `/`).
  - `{optional}` — optional group of tokens.
- Hostnames are normalized before matching (trimmed, trailing dot removed,
  lowercased).
- Methods are normalized (trimmed, uppercased).

### Examples

```toml
# Exact domain only: allows GET and HEAD to github.com, but not api.github.com.
[[allow]]
domain = "github.com"

# Domain and all subdomains: allows GET and HEAD to example.com and *.example.com.
[[allow]]
domain = "example.com"
include_subdomains = true

# Method-restricted rule: allows only GET requests to pie.dev.
[[allow]]
domain = "pie.dev"
methods = ["GET"]

# Allow every HTTP method for a matching host.
[[allow]]
domain = "webhook.example.com"
methods = "ANY"

# Allow `git fetch` for repositories owned by `esamattis`.
# The :repo parameter matches exactly one pathname segment.
[[allow]]
domain = "github.com"
methods = ["POST"]
pathname_pattern = "/esamattis/:repo.git/git-upload-pack"

# Same for `git push`
[[allow]]
domain = "github.com"
methods = ["POST"]
pathname_pattern = "/esamattis/:repo.git/git-receive-pack"

# Python regex, compiled case-insensitively against the normalized hostname.
[[allow]]
domain_regex = '(^|\.)ipinfo\.io$'
```

After editing files in `/opt/mitmwall/rules.d`, restart the service:

```console
sudo systemctl restart mitmwall
```


## System environment variables

The installer reads the plain env file [`system_enviroment`](system_enviroment)
to build the mitmwall-managed CA environment block written to `/etc/environment`
and `/etc/profile.d/mitmwall.sh`. These variables point common runtimes and TLS
libraries, at the mitmproxy CA certificate or the rebuilt system CA bundle so
HTTPS clients can trust certificates generated while mitmwall is intercepting
traffic.

## Plugin configuration

Plugin settings are stored in `/opt/mitmwall/plugin_config.toml`. The installer
creates this file if it does not already exist.

The available setting is:

```toml
log_level = "info"
```

`log_level` controls the mitmproxy addon logging verbosity. It defaults to
`info` when the setting or file is missing. Valid values are `debug`, `info`,
`warning`, `error`, and `critical`.

Restart the service after changing plugin configuration:

```console
sudo systemctl restart mitmwall
```

## Web interface

mitmweb listens on port `58081`.

The password can be viewed as an administrator from the generated mitmweb config:

```console
sudo grep '^web_password:' /opt/mitmwall/mitmweb/config.yaml
```

## How secure this is?

Well, first of, AI agents helped creating this. So there is that 😅

The security model relies on Linux user permissions: Only root and the
`mitmwall` user can access the network freely. Root is intentionally exempt so
administrators can manage and troubleshoot the host without going through the
proxy. So if the attacker can do privilege escalation:

  - to the `mitmwall` user they can access the network
  - to root they can access the network and can just stop the service

### Allowlisted-domain exfiltration

Allowed domains can still be used for credentials dumping, especially when a
rule allows write-capable methods such as `POST`, `PUT`, or `PATCH`, or uses
`methods = "ANY"`. For example, if `github.com` is allowed with a method that
can create or update content, malware could post secrets to an
attacker-controlled issue, gist, repository, or workflow log without violating
the hostname and method allowlist.

The default method policy only allows `GET` and `HEAD`, which blocks many common
write paths. When a write-capable method is needed, prefer narrowing the rule
with `pathname_pattern` or `pathname_regex` instead of allowing the whole domain.
For example, a GitHub rule can allow only the repository path needed for a Git
operation rather than every issue, gist, repository, or workflow endpoint on the
host.

Pathname filters reduce accidental exfiltration risk, but they do not make an
allowed domain safe: secrets may still be leaked through URLs, query strings,
headers, or any endpoint where an allowed method causes data to leave the host.

### DNS leaks

DNS from applications is restricted to local resolvers. The firewall permits
TCP/UDP port 53 only when the destination is local, such as the system resolver
(`systemd-resolved` on `127.0.0.53`). The `systemd-resolve` user is allowed to
make upstream connections so `systemd-resolved` can resolve names; other users
cannot send traffic directly to remote DNS servers on port 53.

This does not prevent DNS-name-based exfiltration. A malicious process can still
ask the local resolver to look up names that contain encoded data, such as
`secret-token.attacker-controlled-domain.example`. If the attacker controls that
domain's authoritative DNS server, the normal DNS resolution path can reveal the
queried name to them. This channel is limited and noisy, but it can still be
enough to leak small secrets such as API keys or tokens.

Closing this channel would require a DNS proxy/filter similar in spirit to the
HTTP/HTTPS proxy. Applications would only be allowed to query the local DNS
proxy, and only that proxy user would be allowed to make upstream DNS queries.
The proxy would need to apply policy before forwarding a name upstream, for
example by allowing only domains that match the same allowlist used for web
traffic and rejecting suspicious names such as long, high-entropy, or constantly
changing subdomains.

But the idea is not to protect from targeted attacks, but from rogue AI agents
gone mad and from general credentials dumping malware as seen on the npm
registry lately.
