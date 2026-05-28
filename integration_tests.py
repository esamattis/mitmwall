#!/usr/bin/env python3
"""
Integration tests for mitmwall network allow/block rules.
"""

import json
import socket
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Protocol, TypeGuard, cast, override

CONNECT_TIMEOUT_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 20
SYSTEM_CA_CERTIFICATES = Path("/etc/ssl/certs/ca-certificates.crt")
PUBLIC_DNS_SERVER = "1.1.1.1"
DNS_QUERY_TIMEOUT_SECONDS = 5
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 58080
SERVICE_READY_TIMEOUT_SECONDS = 20
SERVICE_READY_POLL_INTERVAL_SECONDS = 0.1


def wait_for_tcp_listener(host: str, port: int, timeout_seconds: float) -> bool:
    """
    Return whether a TCP listener accepts connections before the timeout.
    """

    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            with socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT_SECONDS
            ):
                return True
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(SERVICE_READY_POLL_INTERVAL_SECONDS, remaining))


def is_ipv4_socket_address(address: object) -> TypeGuard[tuple[str, int]]:
    """
    Return whether a socket address is an IPv4 host/port pair.
    """

    match address:
        case (str(), int()):
            return True
        case _:
            return False


def is_string_key_dict(value: object) -> TypeGuard[dict[str, object]]:
    """
    Return whether a value is a dictionary with string keys.
    """

    if not isinstance(value, dict):
        return False

    dictionary = cast(dict[object, object], value)
    for key_object in dictionary.keys():
        if not isinstance(key_object, str):
            return False
    return True


class ReadableResponse(Protocol):
    """
    Minimal response interface needed from urllib responses in tests.
    """

    def read(self) -> bytes:
        """
        Read the full response body as bytes.
        """

        ...

    def __enter__(self) -> "ReadableResponse":
        """
        Enter the response context manager.
        """

        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Exit the response context manager.
        """

        ...


class MitmwallNetworkTests(unittest.TestCase):
    """
    Integration tests for mitmwall firewall and allowlist behavior.
    """

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Wait for the local mitmwall proxy to accept connections.
        """

        if not wait_for_tcp_listener(
            PROXY_HOST,
            PROXY_PORT,
            SERVICE_READY_TIMEOUT_SECONDS,
        ):
            raise RuntimeError(
                f"mitmwall proxy did not start listening on {PROXY_HOST}:{PROXY_PORT} within {SERVICE_READY_TIMEOUT_SECONDS} seconds"
            )

    def assert_url_allowed(self, name: str, url: str, method: str = "GET") -> None:
        """
        Assert that an HTTP request reaches the target URL.
        """

        with self.subTest(name=name, url=url, method=method):
            print(f"Testing allowed: {name} ({method} {url})")
            reachable, error = self._url_reachability(url, method=method)
            self.assertTrue(
                reachable,
                f"{name} should have been allowed; request failed with {error!r}",
            )

    def assert_url_blocked(self, name: str, url: str, method: str = "GET") -> None:
        """
        Assert that an HTTP request is blocked before reaching the target URL.
        """

        with self.subTest(name=name, url=url, method=method):
            print(f"Testing blocked: {name} ({method} {url})")
            reachable, _error = self._url_reachability(url, method=method)
            self.assertFalse(
                reachable,
                f"{name} should have been blocked but reached successfully",
            )

    def assert_tcp_allowed(self, name: str, host: str, port: int) -> None:
        """
        Assert that a direct TCP connection can be established.
        """

        with self.subTest(name=name, host=host, port=port):
            print(f"Testing TCP allowed: {name} ({host}:{port})")
            self.assertTrue(
                self._tcp_is_reachable(host, port), f"{name} should have been allowed"
            )

    def assert_tcp_blocked(self, name: str, host: str, port: int) -> None:
        """
        Assert that a direct TCP connection is blocked.
        """

        with self.subTest(name=name, host=host, port=port):
            print(f"Testing TCP blocked: {name} ({host}:{port})")
            self.assertFalse(
                self._tcp_is_reachable(host, port), f"{name} should have been blocked"
            )

    def assert_dns_query_allowed(self, name: str, server: str, hostname: str) -> None:
        """
        Assert that a UDP DNS query receives a successful response.
        """

        with self.subTest(name=name, server=server, hostname=hostname):
            print(f"Testing DNS allowed: {name} ({hostname} via {server})")
            self.assertEqual(
                self._dns_udp_query_rcode(server, hostname),
                0,
                f"{name} should have returned a successful DNS response",
            )

    def assert_dns_query_refused(self, name: str, server: str, hostname: str) -> None:
        """
        Assert that a UDP DNS query is refused by the DNS proxy.
        """

        with self.subTest(name=name, server=server, hostname=hostname):
            print(f"Testing DNS refused: {name} ({hostname} via {server})")
            self.assertEqual(
                self._dns_udp_query_rcode(server, hostname),
                5,
                f"{name} should have returned DNS REFUSED",
            )

    def test_exact_domain_rule_is_allowed(self) -> None:
        """
        Verify that an exact domain allow rule permits the domain.
        """

        self.assert_url_allowed("exact domain rule", "https://github.com/")

    def test_domain_regex_rule_is_allowed(self) -> None:
        """
        Verify that a domain_regex allow rule permits a matching domain.
        """

        self.assert_url_allowed("domain_regex rule", "https://ipinfo.io/")

    def test_include_subdomains_rule_is_allowed(self) -> None:
        """
        Verify that include_subdomains permits matching subdomains.
        """

        self.assert_url_allowed(
            "include_subdomains rule", "https://raw.githubusercontent.com/"
        )

    def test_subdomain_without_include_subdomains_is_blocked(self) -> None:
        """
        Verify that subdomains are blocked when not explicitly included.
        """

        self.assert_url_blocked(
            "subdomain when include_subdomains=false", "https://www.esamatti.fi/"
        )

    def test_unlisted_domain_is_blocked(self) -> None:
        """
        Verify that domains absent from the allowlist are blocked.
        """

        self.assert_url_blocked("unlisted domain", "https://example.com/")

    def test_methods_rule_allows_get(self) -> None:
        """
        Verify that a methods rule permits an allowed GET request.
        """

        self.assert_url_allowed("methods GET rule", "https://pie.dev/get")

    def test_methods_rule_blocks_post(self) -> None:
        """
        Verify that a methods rule blocks a disallowed POST request.
        """

        self.assert_url_blocked(
            "methods GET rule blocks POST", "https://pie.dev/post", method="POST"
        )

    def test_default_methods_rule_allows_head(self) -> None:
        """
        Verify that default methods include HEAD requests.
        """

        self.assert_url_allowed(
            "default methods rule allows HEAD", "https://github.com/", method="HEAD"
        )

    def test_inject_headers_rule_adds_configured_headers(self) -> None:
        """
        Verify that inject_headers adds the configured request headers.
        """

        headers = self._url_reported_headers("https://pie.dev/headers")

        self.assertEqual(headers.get("authorization"), "Secret")
        self.assertEqual(headers.get("x-mitmwall-test"), "enabled")

    def test_pathname_pattern_rule_allows_matching_post(self) -> None:
        """
        Verify that pathname_pattern permits a matching POST request.
        """

        self.assert_url_allowed(
            "pathname_pattern rule matching POST",
            "https://pie.dev/pathname-pattern/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_wrong_static_segment(self) -> None:
        """
        Verify that pathname_pattern blocks a wrong static path segment.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks wrong static segment",
            "https://pie.dev/other/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_extra_path_segment(self) -> None:
        """
        Verify that pathname_pattern blocks an extra path segment.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks extra path segment",
            "https://pie.dev/pathname-pattern/nested/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_nonmatching_pathname(self) -> None:
        """
        Verify that pathname_pattern blocks nonmatching paths.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks nonmatching pathname",
            "https://pie.dev/pathname-pattern/mitmwall/other",
            method="POST",
        )

    def test_pathname_pattern_array_allows_first_pattern(self) -> None:
        """
        Verify that pathname_pattern array permits a request matching the first pattern.
        """

        self.assert_url_allowed(
            "pathname_pattern array first pattern",
            "https://pie.dev/anything/mitmwall/foo",
            method="POST",
        )

    def test_pathname_pattern_array_allows_second_pattern(self) -> None:
        """
        Verify that pathname_pattern array permits a request matching the second pattern.
        """

        self.assert_url_allowed(
            "pathname_pattern array second pattern",
            "https://pie.dev/anything/mitmwall/bar",
            method="POST",
        )

    def test_pathname_pattern_array_blocks_nonmatching_path(self) -> None:
        """
        Verify that pathname_pattern array blocks a request matching no pattern.
        """

        self.assert_url_blocked(
            "pathname_pattern array blocks nonmatching path",
            "https://pie.dev/anything/mitmwall/baz",
            method="POST",
        )

    def test_pathname_regex_rule_allows_matching_post(self) -> None:
        """
        Verify that pathname_regex permits a matching POST request.
        """

        self.assert_url_allowed(
            "pathname_regex rule matching POST",
            "https://pie.dev/pathname-regex/mitmwall/info",
            method="POST",
        )

    def test_pathname_regex_rule_blocks_wrong_static_segment(self) -> None:
        """
        Verify that pathname_regex blocks a wrong static path segment.
        """

        self.assert_url_blocked(
            "pathname_regex rule blocks wrong static segment",
            "https://pie.dev/other/mitmwall/info",
            method="POST",
        )

    def test_pathname_regex_rule_blocks_nonmatching_pathname(self) -> None:
        """
        Verify that pathname_regex blocks nonmatching paths.
        """

        self.assert_url_blocked(
            "pathname_regex rule blocks nonmatching pathname",
            "https://pie.dev/pathname-regex/mitmwall/info/extra",
            method="POST",
        )

    def test_pathname_regex_array_allows_first_pattern(self) -> None:
        """
        Verify that pathname_regex array permits a request matching the first pattern.
        """

        self.assert_url_allowed(
            "pathname_regex array first pattern",
            "https://pie.dev/regex-array/mitmwall/alpha",
            method="POST",
        )

    def test_pathname_regex_array_allows_second_pattern(self) -> None:
        """
        Verify that pathname_regex array permits a request matching the second pattern.
        """

        self.assert_url_allowed(
            "pathname_regex array second pattern",
            "https://pie.dev/regex-array/mitmwall/beta",
            method="POST",
        )

    def test_pathname_regex_array_blocks_nonmatching_path(self) -> None:
        """
        Verify that pathname_regex array blocks a request matching no pattern.
        """

        self.assert_url_blocked(
            "pathname_regex array blocks nonmatching path",
            "https://pie.dev/regex-array/mitmwall/gamma",
            method="POST",
        )

    def test_pathname_regex_and_pattern_allows_regex_match(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern permits
        a request matching the regex.
        """

        self.assert_url_allowed(
            "pathname_regex and pattern allows regex match",
            "https://pie.dev/both/regex/mitmwall",
            method="POST",
        )

    def test_pathname_regex_and_pattern_allows_pattern_match(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern permits
        a request matching the pattern.
        """

        self.assert_url_allowed(
            "pathname_regex and pattern allows pattern match",
            "https://pie.dev/both/pattern/mitmwall",
            method="POST",
        )

    def test_pathname_regex_and_pattern_blocks_nonmatching_path(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern blocks
        a request matching neither.
        """

        self.assert_url_blocked(
            "pathname_regex and pattern blocks nonmatching path",
            "https://pie.dev/both/other/mitmwall",
            method="POST",
        )

    def test_direct_ssh_to_github_is_blocked(self) -> None:
        """
        Verify that direct SSH connections are blocked.
        """

        self.assert_tcp_blocked("direct SSH to github.com", "github.com", 22)

    def test_direct_dns_queries_to_public_resolver_are_proxied(self) -> None:
        """
        Verify that direct DNS queries are transparently filtered by mitmproxy.
        """

        self.assert_dns_query_allowed(
            "allowed direct DNS-over-UDP query to public resolver",
            PUBLIC_DNS_SERVER,
            "github.com",
        )
        self.assert_dns_query_allowed(
            "allowed direct DNS-over-UDP query matching domain_regex",
            PUBLIC_DNS_SERVER,
            "ipinfo.io",
        )
        self.assert_dns_query_refused(
            "blocked direct DNS-over-UDP query to public resolver",
            PUBLIC_DNS_SERVER,
            "not-allowed.mitmwall.invalid",
        )

    def test_tcp_connections_to_localhost_are_allowed(self) -> None:
        """
        Verify that loopback TCP connections remain allowed.
        """

        host, port, stop_server = self._start_local_tcp_server()
        try:
            self.assert_tcp_allowed("loopback TCP connection", host, port)
        finally:
            stop_server()

    def _url_reachability(
        self, url: str, method: str = "GET"
    ) -> tuple[bool, BaseException | None]:
        """
        Return whether an HTTP request can reach a URL and any failure.
        """

        request = urllib.request.Request(
            url, headers={"User-Agent": "mitmwall-test/1.0"}, method=method
        )
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

    def _url_reported_headers(self, url: str, method: str = "GET") -> dict[str, str]:
        """
        Return request headers echoed back by a JSON test endpoint.
        """

        request = urllib.request.Request(
            url, headers={"User-Agent": "mitmwall-test/1.0"}, method=method
        )
        context = ssl.create_default_context(cafile=SYSTEM_CA_CERTIFICATES)
        with cast(
            ReadableResponse,
            urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT_SECONDS,
                context=context,
            ),
        ) as response:
            response_text = response.read().decode("utf-8")

        payload = cast(object, json.loads(response_text))
        if not is_string_key_dict(payload):
            raise AssertionError(f"expected JSON object response, got {payload!r}")

        headers = payload.get("headers")
        if not is_string_key_dict(headers):
            raise AssertionError(
                f"expected JSON object response with headers, got {payload!r}"
            )

        normalized_headers: dict[str, str] = {}
        for key, value in headers.items():
            if isinstance(value, str):
                normalized_headers[key.lower()] = value

        return normalized_headers

    def _tcp_is_reachable(self, host: str, port: int) -> bool:
        """
        Return whether a TCP connection to a host and port succeeds.
        """

        try:
            with socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT_SECONDS
            ):
                return True
        except OSError:
            return False

    def _start_local_tcp_server(self) -> tuple[str, int, Callable[[], None]]:
        """
        Start a one-shot loopback TCP server and return its stop callback.
        """

        ready = threading.Event()
        stopped = threading.Event()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(CONNECT_TIMEOUT_SECONDS)
        get_socket_address: Callable[[], object] = server.getsockname
        address = get_socket_address()
        if not is_ipv4_socket_address(address):
            raise RuntimeError(f"unexpected local socket address: {address!r}")
        host, port = address

        def serve_one_connection() -> None:
            """
            Accept and close one local TCP connection.
            """

            ready.set()
            try:
                connection = server.accept()[0]
                connection.close()
            except OSError:
                pass
            finally:
                server.close()
                stopped.set()

        thread = threading.Thread(target=serve_one_connection, daemon=True)
        thread.start()
        _ready = ready.wait(CONNECT_TIMEOUT_SECONDS)

        def stop_server() -> None:
            """
            Close the local TCP server and wait for its worker to stop.
            """

            try:
                server.close()
            except OSError:
                pass
            _stopped = stopped.wait(CONNECT_TIMEOUT_SECONDS)

        return host, port, stop_server

    def _dns_udp_query_rcode(self, server: str, hostname: str) -> int | None:
        """
        Return the DNS response code for a UDP query, or None on no response.
        """

        query = self._build_dns_query(hostname)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(DNS_QUERY_TIMEOUT_SECONDS)
                _sent = sock.sendto(query, (server, 53))
                response = sock.recv(512)
                if len(response) < 4 or response[:2] != query[:2]:
                    return None
                return response[3] & 0x0F
        except OSError:
            return None

    def _build_dns_query(self, hostname: str) -> bytes:
        """
        Build a minimal DNS A-record query for a hostname.
        """

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
    _test_program = unittest.main(verbosity=2)
