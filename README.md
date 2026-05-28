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


<img width="1334" height="682" alt="image" src="https://github.com/user-attachments/assets/6627274a-315f-4520-804f-48b82d1b2c76" />


## How?

- systemd `mitmwall.service` starts `mitmweb` in transparent HTTP(S) proxy mode
  and DNS proxy mode.
- `ExecStartPre` installs `iptables`/`ip6tables` rules that:
  - redirect outbound TCP port `80` and `443` traffic to the HTTP(S) proxy
  - redirect outbound TCP/UDP port `53` traffic to the DNS proxy
  - only allow root, the dedicated `mitmwall` user, `systemd-resolve`, and
    installed time-sync service users to make required upstream connections
    - the proxy is running as the `mitmwall` user
    - root is left unrestricted for host administration and troubleshooting
    - `systemd-resolve` is left able to perform resolver recursion without
      looping back into the DNS proxy
    - installed time-sync service users such as `systemd-timesync`, `_chrony`,
      or `ntp` are left able to perform NTP synchronization on UDP/123
  - drop other new outbound traffic so applications cannot bypass the proxies
- The mitmproxy addon in `/opt/mitmwall/mitmproxy_addon/main.py` loads TOML files
  from `/etc/mitmwall/rules.d` and:
  - kills HTTP(S) flows whose host, method, and pathname do not match the
    allowlist
  - refuses DNS queries whose hostname does not match any allow rule
- `ExecStopPost` removes the firewall rules when the service stops.

If `/etc/mitmwall/rules.d` is missing or any rule file is invalid, mitmwall
fails closed and blocks all proxied HTTP(S) traffic and DNS resolution.

You should also read the [How mitmproxy works](https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/) -article.

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
                                   # May be a single string or an array of hostnames.
include_subdomains = true         # Also match *.example.com (default: false).
methods = ["GET", "POST"]         # Allowed HTTP methods (default: ["GET", "HEAD"]).
                                  # Use methods = "ANY" to allow all methods.

pathname_pattern = "/api/:ver/upload"  # URL pathname filter (optional).
                                           # Matches only the path, not ?query or #fragment.
                                           # May be a single string or an array of patterns.
pathname_regex = '^/files/.*$'             # Python regex pathname filter (optional).
                                           # Also matched only against the path.
                                           # May be a single string or an array of patterns.

# Add or replace upstream request headers.
inject_headers = [
  { name = "Authorization", value = "Secret" },
  { name = "X-Trace-Id", value = "example" },
]

[[allow]]
domain_regex = '(^|\.)example\.(com|org)$'  # Python regex for hostname (required*).
                                            # May be a single string or an array of patterns.
methods = "ANY"
```

### Rule constraints

- Each `[[allow]]` must have exactly one of `domain` or `domain_regex`.
- `include_subdomains` is only valid with `domain`.
- `pathname_regex` and `pathname_pattern` may both be set; a request matches
  if it satisfies any of the configured pathname filters.
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

# Multiple exact hostnames in a single rule.
[[allow]]
domain = ["registry.npmjs.org", "registry.yarnpkg.com"]

# Multiple regex patterns in a single rule.
[[allow]]
domain_regex = ['(^|\.)npmjs\.org$', '(^|\.)yarnpkg\.com$']

# Multiple pathname patterns — matches if any pattern matches.
[[allow]]
domain = "example.com"
pathname_pattern = ["/api/v1/:resource", "/api/v2/:resource"]
methods = ["GET"]

# Multiple pathname regexes — matches if any regex matches.
[[allow]]
domain = "example.com"
pathname_regex = ['^/static/.*$', '^/assets/.*$']
methods = ["GET"]
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

# When true, DNS queries must match allow rules. Set to false to let the addon
# pass through all DNS queries while keeping the firewall redirection rules.
# The default is true.
block_dns = true

# Clear mitmproxy's in-memory flow history after this many HTTP requests.
# The default is 1000.
flow_history_clear_interval = 1000

# Keep this many newest flow-history entries when trimming flow history.
# The default is 500. If trimming fails, mitmwall falls back to clearing all
# flow history entries.
flow_history_keep_entries = 500
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

## DNS filtering

mitmwall runs mitmproxy in both transparent HTTP(S) mode and DNS mode. The
firewall redirects ordinary users' TCP/UDP port 53 traffic, including attempts to
query local resolvers such as `127.0.0.53` or public resolvers such as `1.1.1.1`,
to mitmproxy's local DNS listener. Root, the `mitmwall` proxy user, and the
`systemd-resolve` user are excluded so administration, proxy upstream lookups,
and system resolver recursion do not loop back into the proxy.

By default, the mitmproxy addon applies the same rule files in
`/etc/mitmwall/rules.d` to DNS queries before forwarding them upstream. DNS
policy is hostname-only: `domain`, `domain_regex`, and `include_subdomains`
decide whether a query may be resolved, while HTTP-specific filters such as
`methods`, `pathname_pattern`, `pathname_regex`, and `inject_headers` still
apply only to web requests. Queries for the machine's local hostname are also
allowed. Other queries that do not match any allow rule are answered with DNS
`REFUSED` and are not resolved upstream.

Set `block_dns = false` in `/etc/mitmwall/config.toml` to disable addon-level DNS
filtering and pass through all DNS queries. This does not change the firewall
redirection rules.

## How secure is this?

Well, first of, AI agents helped creating this. So there is that 😅

The security model relies on Linux user permissions: Only root and the
`mitmwall` user can access the network freely. Root is intentionally exempt so
administrators can manage and troubleshoot the host without going through the
proxy. So if the attacker can do privilege escalation:

  - to the `mitmwall` user they can access the network
  - to root they can access the network and can just stop the service

### DNS-based exfiltration

DNS filtering closes the obvious DNS-based exfiltration path where a process
encodes data into lookup names, for example `secret-token.attacker.example`, and
relies on the normal DNS resolution path to reveal that full query to an
attacker-controlled authoritative nameserver. Because mitmwall refuses names
outside the configured allowlist before resolving them, those synthetic
exfiltration domains are never sent upstream.

Allowed domains should still be chosen carefully: if an attacker can control a
subdomain under an allowed rule, or if a broad `domain_regex` allows untrusted
names, DNS can still be used as a data channel within that allowed namespace.

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


But the idea is not to protect from targeted attacks, but from rogue AI agents
gone mad and from general credentials dumping malware as seen on the npm
registry lately.
