# TCP Blocking Issue

## Summary

`[[allow_tcp]]` rule matching works for identifying destinations, but blocking raw TCP in the mitmproxy addon is not sufficient to stop SSH traffic such as `github.com:22`.

Observed behavior:

- `tcp_start` is called for SSH connections.
- The addon logs that the connection is blocked.
- Despite that, `ssh` and `git clone` over SSH can still proceed.

## Reproduction

Manual test:

```python
import socket

sock = socket.create_connection(("github.com", 22), timeout=5)
data = sock.recv(1024)
print(data)
```

Observed output included an SSH banner such as:

```text
b'SSH-2.0-6279353\r\n'
```

## Relevant Logs

The addon logs show the connection is detected and marked blocked:

```text
INFO tcp connection host=140.82.121.4 port=22
WARNING blocked TCP connection host=140.82.121.4 port=22; no allow_tcp rule matched
```

At the same time, the client still receives the upstream SSH banner.

## Findings

### 1. `tcp_start` is too late to prevent initial upstream TCP data

For raw TCP connections in mitmproxy transparent mode:

1. The client connects to mitmproxy.
2. mitmproxy establishes the upstream TCP connection.
3. `tcp_start` runs.
4. By then, the upstream peer may already have sent data.

So calling `flow.kill()` in `tcp_start` can terminate the flow, but it does not reliably prevent the first bytes from already reaching the client.

This explains why an SSH banner is still received.

### 2. `server_connect` is not directly usable as a replacement

I tested using `server_connect` to block earlier.

Findings:

- `server_connect` is called.
- It receives a `ServerConnectionHookData` object, not a `TCPFlow`.
- That object does not expose `server_conn` or a killable flow interface.

Observed error from the failed attempt:

```text
AttributeError: 'ServerConnectionHookData' object has no attribute 'server_conn'
```

Even after correcting for object shape, this hook does not provide the same direct flow-kill path as `tcp_start`.

### 3. This is not just a test issue

This is not only a false positive from `socket.create_connection()`.

The connection is actually usable enough for SSH/Git to proceed, which means the current addon-level blocking is insufficient for the intended firewall behavior.

## Conclusion

Blocking raw TCP in the mitmproxy addon is not enough to enforce `allow_tcp` securely for protocols like SSH.

The current design can:

- detect raw TCP destinations,
- log them,
- and attempt to kill flows,

but it cannot reliably prevent early upstream data exchange.

## Recommended Direction

To truly block non-allowed raw TCP, enforcement should move to netfilter/iptables instead of relying on mitmproxy's raw TCP hooks.

Possible approach:

1. Continue using mitmproxy for HTTP/HTTPS and DNS policy.
2. Use iptables/ip6tables rules to enforce non-HTTP raw TCP restrictions.
3. If hostname-based TCP allow rules are needed, maintain a hostname-to-IP allowlist outside mitmproxy and program iptables/ipset/nftables from DNS results.

In short:

- HTTP/HTTPS policy fits mitmproxy.
- Raw TCP firewalling needs kernel-level enforcement.

## Current Status

Current code status at time of investigation:

- `allow_tcp` parsing works.
- DNS allowance for `allow_tcp` hostnames works.
- Resolved IP tracking works.
- `towel.blinkenlights.nl:23` matching works.
- Raw TCP blocking in mitmproxy is not strong enough to stop SSH cloning to `github.com:22`.
