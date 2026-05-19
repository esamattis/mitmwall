#!/usr/bin/env python3
"""Integration tests for mitmwall network allow/block rules."""

import socket
import ssl
import unittest
import urllib.error
import urllib.request
from pathlib import Path

CONNECT_TIMEOUT_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 20
SYSTEM_CA_CERTIFICATES = Path("/etc/ssl/certs/ca-certificates.crt")


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

    def assert_tcp_blocked(self, name, host, port):
        with self.subTest(name=name, host=host, port=port):
            print(f"Testing TCP blocked: {name} ({host}:{port})")
            self.assertFalse(
                self._tcp_is_reachable(host, port), f"{name} should have been blocked"
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
