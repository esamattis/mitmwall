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

View logs:

```console
sudo journalctl -u mitmwall.service -f
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
sudo grep '^web_password:' /opt/mitmwall/mitmweb/config.yaml
```

## How secure this is?

Well, first of, AI agents helped creating this. The security model relies on
Linux user permissions: Only root and the `mitmwall` user can access the network
freely. Root is intentionally exempt so administrators can manage and troubleshoot
the host without going through the proxy. So if the attacker can do privilege
escalation:

  - to the `mitmwall` user they can access the network
  - to root they can access the network and can just stop the service

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
