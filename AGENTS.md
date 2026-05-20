# Agent notes

## Architecture

mitmwall is a transparent outbound firewall for Ubuntu. `systemd` runs `mitmweb`
as the dedicated `mitmwall` user, `iptables`/`ip6tables` redirect outbound HTTP
and HTTPS traffic to the local transparent proxy, and `mitmwall_addon.py` loads
TOML files in `/opt/mitmwall/rules.d` to allow or block requests by hostname.
Non-proxy users can only make DNS queries and proxied web requests; the proxy
user is allowed to connect upstream.

Ensure all python functions, classes etc. have doc comments.

Never use any pypi packages. Only use stdlib.

After changes install with ./dev-install.sh and test with ./test.sh

See logs with:

sudo journalctl -u mitmwall --no-pager
