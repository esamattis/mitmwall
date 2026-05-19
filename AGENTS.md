# Agent notes

## Architecture

mitmwall is a transparent outbound firewall for Ubuntu. `systemd` runs `mitmweb`
as the dedicated `mitmwall` user, `iptables`/`ip6tables` redirect outbound HTTP
and HTTPS traffic to the local transparent proxy, and `mitmwall_addon.py` loads
`/opt/mitmwall/rules.toml` to allow or block requests by hostname. Non-proxy
users can only make DNS queries and proxied web requests; the proxy user is
allowed to connect upstream.

After changes install with ./dev-install.sh

test with ./test.sh

See logs with:

  sudo journalctl -u mitmwall
