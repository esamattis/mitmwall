mitmwall is a transparent outbound firewall for Ubuntu. `systemd` runs `mitmweb`
as the dedicated `mitmwall` user, `iptables`/`ip6tables` redirect outbound HTTP
and HTTPS traffic to the local transparent proxy, and `mitmproxy_addon/main.py`
loads TOML files in `/etc/mitmwall/rules.d` to allow or block requests by
hostname.
Non-proxy users can only make DNS queries and proxied web requests; the proxy
user is allowed to connect upstream.

Ensure all python functions, classes etc. have doc comments.

Ensure valid types by running `basedpyright`

Never use any pypi packages. Only use stdlib.

After any changes run `./test.sh` and `./integration_tests.sh`

`integration-test-rules.toml` is installed during integration tests.

See logs with:

sudo journalctl -u mitmwall --no-pager
