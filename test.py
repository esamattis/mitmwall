#!/usr/bin/env python3
"""Integration tests for mitmwall network allow/block rules."""

import socket
import ssl
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

CONNECT_TIMEOUT_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 20
SYSTEM_CA_CERTIFICATES = Path("/etc/ssl/certs/ca-certificates.crt")
PUBLIC_DNS_SERVER = "1.1.1.1"
DNS_QUERY_TIMEOUT_SECONDS = 5


class HeadRequest(urllib.request.Request):
    def get_method(self):
        return "HEAD"


class MitmwallNetworkTests(unittest.TestCase):
    def assert_url_allowed(self, name, url):
        with self.subTest(name=name, url=url):
            print(f"Testing allowed: {name} ({url})")
            reachable, error = self._url_reachability(url)
            self.assertTrue(
                reachable,
                f"{name} should have been allowed; request failed with {error!r}",
            )

    def assert_url_blocked(self, name, url):
        with self.subTest(name=name, url=url):
            print(f"Testing blocked: {name} ({url})")
            reachable, error = self._url_reachability(url)
            self.assertFalse(
                reachable, f"{name} should have been blocked but reached successfully"
            )

    def assert_tcp_allowed(self, name, host, port):
        with self.subTest(name=name, host=host, port=port):
            print(f"Testing TCP allowed: {name} ({host}:{port})")
            self.assertTrue(
                self._tcp_is_reachable(host, port), f"{name} should have been allowed"
            )

    def assert_tcp_blocked(self, name, host, port):
        with self.subTest(name=name, host=host, port=port):
            print(f"Testing TCP blocked: {name} ({host}:{port})")
            self.assertFalse(
                self._tcp_is_reachable(host, port), f"{name} should have been blocked"
            )

    def assert_dns_query_blocked(self, name, server, hostname):
        with self.subTest(name=name, server=server, hostname=hostname):
            print(f"Testing DNS blocked: {name} ({hostname} via {server})")
            self.assertFalse(
                self._dns_udp_query_is_answered(server, hostname),
                f"{name} should have been blocked but returned a DNS response",
            )

    def test_exact_domain_rule_is_allowed(self):
        self.assert_url_allowed("exact domain rule", "https://github.com/")

    def test_domain_regex_rule_is_allowed(self):
        self.assert_url_allowed("domain_regex rule", "https://ipinfo.io/")

    def test_include_subdomains_rule_is_allowed(self):
        self.assert_url_allowed("include_subdomains rule", "https://www.esamatti.fi/")

    def test_subdomain_without_include_subdomains_is_blocked(self):
        self.assert_url_blocked(
            "subdomain when include_subdomains=false", "https://api.github.com/"
        )

    def test_unlisted_domain_is_blocked(self):
        self.assert_url_blocked("unlisted domain", "https://example.com/")

    def test_direct_ssh_to_github_is_blocked(self):
        self.assert_tcp_blocked("direct SSH to github.com", "github.com", 22)

    def test_direct_dns_queries_to_public_resolver_are_blocked(self):
        self.assert_dns_query_blocked(
            "direct DNS-over-UDP query to public resolver",
            PUBLIC_DNS_SERVER,
            "github.com",
        )
        self.assert_tcp_blocked(
            "direct DNS-over-TCP connection to public resolver", PUBLIC_DNS_SERVER, 53
        )

    def test_tcp_connections_to_localhost_are_allowed(self):
        host, port, stop_server = self._start_local_tcp_server()
        try:
            self.assert_tcp_allowed("loopback TCP connection", host, port)
        finally:
            stop_server()

    def _url_reachability(self, url):
        request = HeadRequest(url, headers={"User-Agent": "mitmwall-test/1.0"})
        # The installer adds mitmproxy's CA to Ubuntu's system trust bundle with
        # update-ca-certificates. Use that same bundle explicitly so the test has
        # the same trust roots as curl even when Python was built with different
        # OpenSSL default paths.
        context = ssl.create_default_context(cafile=SYSTEM_CA_CERTIFICATES)
        try:
            with urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT_SECONDS,
                context=context,
            ):
                return True, None
        except urllib.error.HTTPError:
            # curl without --fail treats HTTP error status responses as a successful
            # connection, so keep the same behavior here.
            return True, None
        except (OSError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            return False, exc

    def _tcp_is_reachable(self, host, port):
        try:
            with socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT_SECONDS
            ):
                return True
        except OSError:
            return False

    def _start_local_tcp_server(self):
        ready = threading.Event()
        stopped = threading.Event()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(CONNECT_TIMEOUT_SECONDS)
        host, port = server.getsockname()

        def serve_one_connection():
            ready.set()
            try:
                connection, _ = server.accept()
                connection.close()
            except OSError:
                pass
            finally:
                server.close()
                stopped.set()

        thread = threading.Thread(target=serve_one_connection, daemon=True)
        thread.start()
        ready.wait(CONNECT_TIMEOUT_SECONDS)

        def stop_server():
            try:
                server.close()
            except OSError:
                pass
            stopped.wait(CONNECT_TIMEOUT_SECONDS)

        return host, port, stop_server

    def _dns_udp_query_is_answered(self, server, hostname):
        query = self._build_dns_query(hostname)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(DNS_QUERY_TIMEOUT_SECONDS)
                sock.sendto(query, (server, 53))
                response, _ = sock.recvfrom(512)
                return len(response) >= 2 and response[:2] == query[:2]
        except OSError:
            return False

    def _build_dns_query(self, hostname):
        labels = hostname.rstrip(".").split(".")
        question = b"".join(
            len(label).to_bytes(1, "big") + label.encode("ascii") for label in labels
        )
        question += b"\x00"
        header = b"\x12\x34"  # Transaction ID.
        header += b"\x01\x00"  # Standard recursive query.
        header += b"\x00\x01"  # One question.
        header += b"\x00\x00"  # No answers.
        header += b"\x00\x00"  # No authority records.
        header += b"\x00\x00"  # No additional records.
        return header + question + b"\x00\x01" + b"\x00\x01"  # A record, IN class.


if __name__ == "__main__":
    unittest.main(verbosity=2)
