# mitmwall

mitmwall is a outbound firewall/proxy for Ubuntu. It combines `iptables` with
[mitmproxy](https://mitmproxy.org/) to ensure that only explicitly allowed
HTTP(s) routes can be reached. Any network connection that does not match the
allowlist is blocked. This prevents:

- **Data exfiltration** — compromised npm/pypi/cargo etc. packages, rogue AI
  agents, or other untrusted processes stealing credentials, API keys, or source
  code.
- **Backdoor connections** — malware phoning home to command-and-control servers.

The built-in mitmweb interface can be used to monitor all proxied traffic in
real time.

The name is a wordplay for mitmproxy + firewall = mitmwall.

## How?

- systemd `mitmwall.service` starts `mitmweb` in transparent proxy mode
- `ExecStartPre` installs `iptables`/`ip6tables` rules that:
  - redirect outbound TCP port `80` and `443` traffic to the proxy
  - only allow root and the dedicated `mitmwall` user to make upstream connections
    - the proxy is running as the `mitmwall` user
    - root is left unrestricted for host administration and troubleshooting
  - allow DNS only to the local resolver so clients can resolve hostnames
    - only the `systemd-resolve` user can make DNS queries
  - drop other new outbound traffic so applications cannot bypass the proxy
- The mitmproxy addon in `/opt/mitmwall/mitmproxy_addon/main.py` loads TOML files
  from `/etc/mitmwall/rules.d` and kills HTTP(S) flows whose host does not
  match the allowlist.
- `ExecStopPost` removes the firewall rules when the service stops.

If `/etc/mitmwall/rules.d` is missing or any rule file is invalid, mitmwall
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
`/opt/mitmwall`, creates `/etc/mitmwall/config.toml` and `/etc/mitmwall/rules.d`,
installs the systemd service, generates the mitmproxy CA, and adds the CA to
the system trust store with `update-ca-certificates`.

The scripts can be also used for upgrading mitmwall.


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

Rules are stored as TOML files in `/etc/mitmwall/rules.d`. Each `*.toml` file
can contain zero or more `[[allow]]` tables. Traffic is blocked unless the
request hostname, HTTP method, and optional pathname filter match at least one
allow rule. Files are loaded in alphabetical filename order.

The [example rules](example-rules.toml) from this repository are installed to
`/etc/mitmwall/rules.d/5-examples.toml`.

### Syntax

```toml
[[allow]]
domain = "example.com"            # Exact hostname to allow (required*).
include_subdomains = true         # Also match *.example.com (default: false).
methods = ["GET", "POST"]         # Allowed HTTP methods (default: ["GET", "HEAD"]).
                                  # Use methods = "ANY" to allow all methods.

pathname_pattern = "/api/:ver/upload"  # URL pathname filter (optional).
                                           # Matches only the path, not ?query or #fragment.
pathname_regex = '^/files/.*$'             # Python regex pathname filter (optional).
                                           # Also matched only against the path.

# Add or replace upstream request headers.
inject_headers = [
  { name = "Authorization", value = "Secret" },
  { name = "X-Trace-Id", value = "example" },
]

[[allow]]
domain_regex = '(^|\.)example\.(com|org)$'  # Python regex for hostname (required*).
methods = "ANY"
```

### Rule constraints

- Each `[[allow]]` must have exactly one of `domain` or `domain_regex`.
- `include_subdomains` is only valid with `domain`.
- At most one of `pathname_pattern` or `pathname_regex` per rule.
- `inject_headers` must be a non-empty list of `{ name = "Header-Name", value = "..." }` tables.
- Unknown keys are rejected.

### Matching behavior

- `domain_regex` is matched case-insensitively (partial match).
- `pathname_regex` need only match part of the pathname (partial match).
- `pathname_pattern` must match the entire pathname (full match) and supports:
  - matching is done against the URL pathname only
  - query strings (`?foo=bar`) and fragments (`#section`) are ignored
  - for example, `/search?q=test` is matched as pathname `/search`
  - `:param` — matches exactly one path segment (no `/`).
  - `*wildcard` — matches one or more characters (spans `/`).
  - `{optional}` — optional group of tokens.
- Hostnames are normalized before matching (trimmed, trailing dot removed,
  lowercased).
- Exact `domain` rules do not match subdomains unless `include_subdomains = true`.
- Methods are normalized (trimmed, uppercased).
- `inject_headers` adds or replaces each listed request header before the
  upstream request is sent.
- If multiple rules match, `inject_headers` is taken from the first matching
  rule that defines it. Headers are not merged across matching rules.

### Examples

```toml
# Exact domain only: allows GET and HEAD to github.com, but not api.github.com.
[[allow]]
domain = "github.com"

# Another exact-only example: esamatti.fi is allowed, but www.esamatti.fi is not
# unless include_subdomains is enabled.
[[allow]]
domain = "esamatti.fi"

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

# Add multiple headers to a specific upstream endpoint.
[[allow]]
domain = "pie.dev"
pathname_pattern = "/headers"
methods = ["GET"]
inject_headers = [
  { name = "Authorization", value = "Secret" },
  { name = "X-Mitmwall-Test", value = "enabled" },
]

# Query strings are not part of pathname_pattern matching.
# This allows GET https://pie.dev/headers?x=1 because the pathname is /headers.
[[allow]]
domain = "pie.dev"
pathname_pattern = "/headers"
methods = ["GET"]

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

After editing files in `/etc/mitmwall/rules.d`, restart the service:

```console
sudo systemctl restart mitmwall
```

## Credential injection

`inject_headers` can add custom headers to requests, which can be used to
transparently supply credentials. This can be a powerful way to avoid exposing
credentials to untrusted users. A typical workflow is to first configure the
tools that require the credentials, inspect in mitmweb how the credentials are
used, write a matching rule that injects the credential headers, and finally
replace the real credentials with dummy values so the tool still thinks
credentials are configured. Credential injection also prevents
malware from using their own credentials.

## System environment variables

The installer reads the plain env file [`system_enviroment`](system_enviroment)
to build the mitmwall-managed CA environment block written to `/etc/environment`.
These variables point common runtimes and TLS libraries at the mitmproxy CA
certificate or the rebuilt system CA bundle so HTTPS clients can trust
certificates generated while mitmwall is intercepting traffic. The values apply
to new login sessions after installation.

## Addon configuration

Addon settings are stored in `/etc/mitmwall/config.toml`. The installer creates
this file if it does not already exist.

Available settings:

```toml
# Available log_level values: "debug", "info", "warning", "error", "critical".
# The default is "info".
log_level = "info"
```

Restart the service after changing addon configuration:

```console
sudo systemctl restart mitmwall
```

## Web interface

mitmweb listens on port `58081`.

The password can be viewed as an administrator from the generated mitmweb config:

```console
sudo grep '^web_password:' /opt/mitmwall/mitmweb/config.yaml
```

## How secure is this?

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

UPDATE: mitmproxy actually has [dns-support](https://docs.mitmproxy.org/stable/addons/examples/#dns-simple)
