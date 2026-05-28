"""
Unit tests for allow-rule parsing and request header injections.
"""

import re
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import final, override

from mitmproxy_addon.addon import (
    DNSFlowLike,
    DNSQuestionLike,
    DNSRequestLike,
    FlowLike,
    HeadersLike,
    Mitmwall,
    RequestLike,
    ServerConnLike,
    TCPFlowLike,
    trim_mitmproxy_view_flow_history,
)
from mitmproxy_addon.pathname_pattern import compile_pathname_pattern
from mitmproxy_addon.rules import (
    DomainRule,
    InjectedHeader,
    PathnameFilter,
    describe_rule,
    load_rules,
    parse_rules_file,
)


@final
class FakeHeaders(HeadersLike):
    """
    Minimal mutable header container for addon unit tests.
    """

    _values: dict[str, str]

    def __init__(self) -> None:
        """
        Initialize an empty fake header container.
        """

        self._values = {}

    @override
    def __setitem__(self, key: str, value: str, /) -> None:
        """
        Set or replace a fake header value.
        """

        self._values[key] = value

    @override
    def __getitem__(self, key: str, /) -> str:
        """
        Return a fake header value.
        """

        return self._values[key]


@final
class FakeRequest:
    """
    Minimal request object for addon unit tests.
    """

    pretty_host: str
    host: str
    method: str
    pretty_url: str
    headers: HeadersLike

    def __init__(self, host: str, method: str, url: str) -> None:
        """
        Initialize a fake request with mutable headers.
        """

        self.pretty_host = host
        self.host = host
        self.method = method
        self.pretty_url = url
        self.headers = FakeHeaders()


@final
class FakeFlow(FlowLike):
    """
    Minimal flow object for addon unit tests.
    """

    request: RequestLike
    killed: bool

    def __init__(self, request: RequestLike) -> None:
        """
        Initialize a fake flow that records whether it was killed.
        """

        self.request = request
        self.killed = False

    @override
    def kill(self) -> None:
        """
        Record that the addon blocked this flow.
        """

        self.killed = True


@final
class FakeDNSQuestion(DNSQuestionLike):
    """
    Minimal DNS question object for addon unit tests.
    """

    name: str

    def __init__(self, name: str) -> None:
        """
        Initialize a fake DNS question with a hostname.
        """

        self.name = name


@final
class FakeDNSRequest(DNSRequestLike):
    """
    Minimal DNS request object for addon unit tests.
    """

    question: DNSQuestionLike | None

    def __init__(self, name: str | None) -> None:
        """
        Initialize a fake DNS request with an optional question.
        """

        self.question = None if name is None else FakeDNSQuestion(name)

    @override
    def fail(self, response_code: int) -> object:
        """
        Return a fake DNS error response marker.
        """

        return ("failed", response_code)


@final
class FakeDNSFlow(DNSFlowLike):
    """
    Minimal DNS flow object for addon unit tests.
    """

    request: DNSRequestLike
    response: object | None

    def __init__(self, name: str | None) -> None:
        """
        Initialize a fake DNS flow without a response.
        """

        self.request = FakeDNSRequest(name)
        self.response = None


@final
class FakeServerConn(ServerConnLike):
    """
    Minimal server connection object for addon unit tests.
    """

    address: tuple[str, int] | None

    def __init__(self, address: tuple[str, int] | None) -> None:
        """
        Initialize a fake server connection with an optional address.
        """

        self.address = address


@final
class FakeTCPFlow(TCPFlowLike):
    """
    Minimal TCP flow object for addon unit tests.
    """

    server_conn: ServerConnLike

    def __init__(self, address: tuple[str, int] | None) -> None:
        """
        Initialize a fake TCP flow with an optional server address.
        """

        self.server_conn = FakeServerConn(address)


class RuleParsingTests(unittest.TestCase):
    """
    Verify allow-rule parsing behavior, including load order.
    """

    def test_parse_rules_file_accepts_inject_headers(self) -> None:
        """
        Parse an inject_headers rule into structured header definitions.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
inject_headers = [
    { name = "Authorization", value = "Secret" },
    { name = "X-Mitmwall-Test", value = "enabled" },
]
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(
            rule.inject_headers,
            (
                InjectedHeader(name="Authorization", value="Secret"),
                InjectedHeader(name="X-Mitmwall-Test", value="enabled"),
            ),
        )

    def test_parse_rules_file_rejects_string_inject_headers_items(self) -> None:
        """
        Reject inject_headers items that are not TOML tables.
        """

        with self.assertRaisesRegex(ValueError, "must be a table"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
inject_headers = ["Authorization: Secret"]
""".strip()
            )

    def test_parse_rules_file_rejects_legacy_inject_header(self) -> None:
        """
        Reject the legacy inject_header key.
        """

        with self.assertRaisesRegex(
            ValueError, r"unsupported key\(s\): 'inject_header'"
        ):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
inject_header = "Authorization: Secret"
""".strip()
            )

    def test_describe_rule_redacts_injected_header_values(self) -> None:
        """
        Log rule descriptions without exposing injected header secrets.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
inject_headers = [
    { name = "Authorization", value = "Secret" },
    { name = "X-Mitmwall-Test", value = "enabled" },
]
""".strip()
        )

        description = describe_rule(1, rule)

        self.assertIn(
            "inject_header_names=['Authorization', 'X-Mitmwall-Test']",
            description,
        )
        self.assertNotIn("Secret", description)
        self.assertNotIn("enabled", description)

    def test_load_rules_sorts_files_alphabetically(self) -> None:
        """
        Load TOML rule files in alphabetical filename order.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir)
            _ = (rules_dir / "20-second.toml").write_text(
                '[[allow]]\ndomain = "second.example"\n',
                encoding="utf-8",
            )
            _ = (rules_dir / "10-first.toml").write_text(
                '[[allow]]\ndomain = "first.example"\n',
                encoding="utf-8",
            )

            rules = load_rules(rules_dir)

        self.assertEqual(
            [rule.domain for rule in rules],
            [("first.example",), ("second.example",)],
        )

    def test_load_rules_ignores_hidden_toml_files(self) -> None:
        """
        Skip dot-prefixed TOML files when loading a rules directory.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir)
            _ = (rules_dir / ".10-hidden.toml").write_text(
                '[[allow]]\ndomain = "hidden.example"\n',
                encoding="utf-8",
            )
            _ = (rules_dir / "20-visible.toml").write_text(
                '[[allow]]\ndomain = "visible.example"\n',
                encoding="utf-8",
            )

            rules = load_rules(rules_dir)

        self.assertEqual(
            [rule.domain for rule in rules],
            [("visible.example",)],
        )

    def test_parse_rules_file_accepts_pathname_pattern_array(self) -> None:
        """
        Parse pathname_pattern as an array and match any of the patterns.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
pathname_pattern = ["/headers", "/status/:code"]
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(len(rule.pathname_filters), 2)
        self.assertEqual(rule.pathname_filters[0].kind, "pathname_pattern")
        self.assertEqual(rule.pathname_filters[1].kind, "pathname_pattern")
        self.assertTrue(rule.pathname_filters[0].matches("/headers"))
        self.assertTrue(rule.pathname_filters[0].matches("/headers/"))
        self.assertFalse(rule.pathname_filters[0].matches("/status/200"))
        self.assertTrue(rule.pathname_filters[1].matches("/status/200"))
        self.assertFalse(rule.pathname_filters[1].matches("/other"))

    def test_parse_rules_file_accepts_pathname_regex_array(self) -> None:
        """
        Parse pathname_regex as an array and match any of the patterns.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
pathname_regex = ['^/foo/[^/]+/info$', '^/bar/[^/]+/data$']
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(len(rule.pathname_filters), 2)
        self.assertEqual(rule.pathname_filters[0].kind, "pathname_regex")
        self.assertEqual(rule.pathname_filters[1].kind, "pathname_regex")
        self.assertTrue(rule.pathname_filters[0].matches("/foo/abc/info"))
        self.assertFalse(rule.pathname_filters[0].matches("/bar/xyz/data"))
        self.assertTrue(rule.pathname_filters[1].matches("/bar/xyz/data"))
        self.assertFalse(rule.pathname_filters[1].matches("/baz/abc/info"))

    def test_parse_rules_file_accepts_both_pathname_regex_and_pattern(self) -> None:
        """
        Parse both pathname_regex and pathname_pattern in the same rule.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
pathname_regex = '^/api/.*$'
pathname_pattern = "/status/:code"
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(len(rule.pathname_filters), 2)
        self.assertEqual(rule.pathname_filters[0].kind, "pathname_regex")
        self.assertEqual(rule.pathname_filters[1].kind, "pathname_pattern")
        self.assertTrue(rule.matches("pie.dev", "GET", "/api/test"))
        self.assertTrue(rule.matches("pie.dev", "GET", "/status/200"))
        self.assertFalse(rule.matches("pie.dev", "GET", "/other"))

    def test_parse_rules_file_rejects_empty_pathname_regex_array(self) -> None:
        """
        Reject an empty pathname_regex array.
        """

        with self.assertRaisesRegex(ValueError, "non-empty string or a non-empty list"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
pathname_regex = []
""".strip()
            )

    def test_parse_rules_file_rejects_non_string_pathname_regex_array_items(
        self,
    ) -> None:
        """
        Reject pathname_regex array items that are not non-empty strings.
        """

        with self.assertRaisesRegex(ValueError, "must be a non-empty string"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
pathname_regex = ['^/foo$', 123]
""".strip()
            )

    def test_parse_rules_file_rejects_empty_pathname_pattern_array(self) -> None:
        """
        Reject an empty pathname_pattern array.
        """

        with self.assertRaisesRegex(ValueError, "non-empty string or a non-empty list"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
pathname_pattern = []
""".strip()
            )

    def test_parse_rules_file_rejects_non_string_pathname_pattern_array_items(
        self,
    ) -> None:
        """
        Reject pathname_pattern array items that are not non-empty strings.
        """

        with self.assertRaisesRegex(ValueError, "must be a non-empty string"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
pathname_pattern = ["/headers", 123]
""".strip()
            )

    def test_parse_rules_file_accepts_domain_array(self) -> None:
        """
        Parse domain as an array and match any of the listed domains.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = ["github.com", "api.github.com"]
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(rule.domain, ("github.com", "api.github.com"))
        self.assertTrue(rule.matches_host("github.com"))
        self.assertTrue(rule.matches_host("api.github.com"))
        self.assertFalse(rule.matches_host("other.example"))

    def test_parse_rules_file_accepts_domain_array_with_include_subdomains(self) -> None:
        """
        Parse domain as an array with include_subdomains applying to all entries.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = ["example.com", "example.org"]
include_subdomains = true
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(rule.domain, ("example.com", "example.org"))
        self.assertTrue(rule.matches_host("example.com"))
        self.assertTrue(rule.matches_host("sub.example.com"))
        self.assertTrue(rule.matches_host("example.org"))
        self.assertTrue(rule.matches_host("sub.example.org"))
        self.assertFalse(rule.matches_host("other.example"))

    def test_parse_rules_file_rejects_empty_domain_array(self) -> None:
        """
        Reject an empty domain array.
        """

        with self.assertRaisesRegex(ValueError, "non-empty string or a non-empty list"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = []
""".strip()
            )

    def test_parse_rules_file_rejects_non_string_domain_array_items(self) -> None:
        """
        Reject domain array items that are not non-empty strings.
        """

        with self.assertRaisesRegex(ValueError, "must be a non-empty string"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = ["github.com", 123]
""".strip()
            )

    def test_parse_rules_file_accepts_domain_regex_array(self) -> None:
        """
        Parse domain_regex as an array and match any of the listed patterns.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain_regex = ['(^|\\.)example\\.com$', '(^|\\.)example\\.org$']
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(len(rule.domain), 2)
        self.assertTrue(rule.matches_host("example.com"))
        self.assertTrue(rule.matches_host("sub.example.com"))
        self.assertTrue(rule.matches_host("example.org"))
        self.assertTrue(rule.matches_host("sub.example.org"))
        self.assertFalse(rule.matches_host("other.example"))

    def test_parse_rules_file_rejects_empty_domain_regex_array(self) -> None:
        """
        Reject an empty domain_regex array.
        """

        with self.assertRaisesRegex(ValueError, "non-empty string or a non-empty list"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain_regex = []
""".strip()
            )

    def test_parse_rules_file_rejects_non_string_domain_regex_array_items(self) -> None:
        """
        Reject domain_regex array items that are not non-empty strings.
        """

        with self.assertRaisesRegex(ValueError, "must be a non-empty string"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain_regex = ['^example\\.com$', 123]
""".strip()
            )

    def test_parse_rules_file_rejects_invalid_domain_regex_in_array(self) -> None:
        """
        Reject invalid regex patterns in a domain_regex array.
        """

        with self.assertRaisesRegex(ValueError, "invalid domain_regex"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain_regex = ['^example\\.com$', '[invalid']
""".strip()
            )

    def _parse_single_rule(self, content: str) -> DomainRule:
        """
        Parse one domain rule from temporary TOML content.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.toml"
            _ = path.write_text(content, encoding="utf-8")
            rules = parse_rules_file(path)

        self.assertEqual(len(rules), 1)
        return rules[0]


class DNSAddonTests(unittest.TestCase):
    """
    Verify addon behavior for DNS allowlist enforcement.
    """

    def test_dns_request_allows_pathname_and_method_restricted_rule_domain(
        self,
    ) -> None:
        """
        Allow DNS for a matching domain even when HTTP filters would not match.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev, pathname_pattern '/headers'",
                domain=("pie.dev",),
                include_subdomains=False,
                methods=("POST",),
                pathname_filters=(
                    PathnameFilter(
                        name="pathname_pattern '/headers'",
                        pattern=compile_pathname_pattern("/headers"),
                        uses_search=False,
                        kind="pathname_pattern",
                        source="/headers",
                    ),
                ),
            )
        ]
        flow = FakeDNSFlow("pie.dev")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_allows_matching_domain_regex(self) -> None:
        """
        Allow DNS for a hostname matching a domain_regex rule.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain_regex '^api[.]example[.]com$'",
                domain=(re.compile(r"^api[.]example[.]com$", re.IGNORECASE),),
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("api.example.com")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_refuses_unmatched_domain_regex(self) -> None:
        """
        Refuse DNS for a hostname that does not match a domain_regex rule.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain_regex '^api[.]example[.]com$'",
                domain=(re.compile(r"^api[.]example[.]com$", re.IGNORECASE),),
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("www.example.com")

        addon.dns_request(flow)

        self.assertEqual(flow.response, ("failed", 5))

    def test_dns_request_refuses_unmatched_domain(self) -> None:
        """
        Refuse DNS queries that do not match any rule hostname.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain=("pie.dev",),
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertEqual(flow.response, ("failed", 5))

    def test_dns_request_allows_local_hostname(self) -> None:
        """
        Allow resolving the local machine hostname without an allow rule.
        """

        addon = Mitmwall()
        addon.local_hostname = "localbox"
        flow = FakeDNSFlow("LOCALBOX.")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_passes_unmatched_domain_when_block_dns_is_false(self) -> None:
        """
        Allow unmatched DNS queries through when DNS blocking is disabled.
        """

        addon = Mitmwall()
        addon.block_dns = False
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain=("pie.dev",),
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_without_question_passes_when_block_dns_is_false(self) -> None:
        """
        Allow malformed DNS requests through when DNS blocking is disabled.
        """

        addon = Mitmwall()
        addon.block_dns = False
        flow = FakeDNSFlow(None)

        addon.dns_request(flow)

        self.assertIsNone(flow.response)


class HeaderInjectionAddonTests(unittest.TestCase):
    """
    Verify addon behavior when matching rules inject headers.
    """

    def test_request_injects_headers_for_matching_rule(self) -> None:
        """
        Inject the configured headers into an allowed matching request.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain=("pie.dev",),
                include_subdomains=False,
                methods=("GET",),
            ),
            DomainRule(
                name="domain pie.dev, pathname_pattern '/headers'",
                domain=("pie.dev",),
                include_subdomains=False,
                methods=("GET",),
                pathname_filters=(
                    PathnameFilter(
                        name="pathname_pattern '/headers'",
                        pattern=compile_pathname_pattern("/headers"),
                        uses_search=False,
                        kind="pathname_pattern",
                        source="/headers",
                    ),
                ),
                inject_headers=(
                    InjectedHeader(
                        name="Authorization",
                        value="Secret",
                    ),
                    InjectedHeader(
                        name="X-Mitmwall-Test",
                        value="enabled",
                    ),
                ),
            ),
        ]

        flow = FakeFlow(FakeRequest("pie.dev", "GET", "https://pie.dev/headers"))

        addon.request(flow)

        self.assertFalse(flow.killed)
        self.assertEqual(flow.request.headers["Authorization"], "Secret")
        self.assertEqual(flow.request.headers["X-Mitmwall-Test"], "enabled")


@final
class FakeFlowHistoryClearer:
    """
    Callable test double that records flow history clear calls.
    """

    calls: int
    keep_entries_values: list[int]

    def __init__(self) -> None:
        """
        Initialize the clear call counter.
        """

        self.calls = 0
        self.keep_entries_values = []

    def __call__(self, keep_entries: int) -> int:
        """
        Record a flow history trim request.
        """

        self.calls += 1
        self.keep_entries_values.append(keep_entries)
        return keep_entries


@final
class FakeMitmproxyView:
    """
    Minimal mitmproxy view test double for flow history trimming.
    """

    _store: dict[str, object]

    def __init__(self, flows: list[object]) -> None:
        """
        Initialize a fake view with insertion-ordered flow history.
        """

        self._store = {str(index): flow for index, flow in enumerate(flows)}

    def clear(self) -> None:
        """
        Clear all fake stored flows.
        """

        self._store.clear()

    def add(self, flows: Sequence[object]) -> None:
        """
        Add fake flows back to the store.
        """

        self._store.update(
            (str(index), flow) for index, flow in enumerate(flows, start=len(self._store))
        )

    def stored_flows(self) -> list[object]:
        """
        Return fake stored flows in insertion order.
        """

        return list(self._store.values())


class FlowHistoryAddonTests(unittest.TestCase):
    """
    Verify addon-driven mitmproxy flow history cleanup.
    """

    def test_request_clears_flow_history_at_configured_interval(self) -> None:
        """
        Clear mitmproxy flow history after the configured number of requests.
        """

        addon = Mitmwall()
        addon.flow_history_clear_interval = 2
        flow_history_clearer = FakeFlowHistoryClearer()
        addon.flow_history_clearer = flow_history_clearer
        flow = FakeFlow(FakeRequest("pie.dev", "GET", "https://pie.dev/"))

        addon.request(flow)
        addon.request(flow)
        addon.request(flow)

        self.assertEqual(flow_history_clearer.calls, 1)
        self.assertEqual(flow_history_clearer.keep_entries_values, [500])
        self.assertEqual(addon.requests_since_flow_history_clear, 1)

    def test_dns_request_clears_flow_history_at_configured_interval(self) -> None:
        """
        Count DNS requests toward the configured flow history clear interval.
        """

        addon = Mitmwall()
        addon.flow_history_clear_interval = 2
        flow_history_clearer = FakeFlowHistoryClearer()
        addon.flow_history_clearer = flow_history_clearer
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)
        addon.dns_request(flow)
        addon.dns_request(flow)

        self.assertEqual(flow_history_clearer.calls, 1)
        self.assertEqual(flow_history_clearer.keep_entries_values, [500])
        self.assertEqual(addon.requests_since_flow_history_clear, 1)

    def test_trim_flow_history_keeps_newest_entries(self) -> None:
        """
        Preserve the newest flow history entries when trimming mitmproxy's view.
        """

        view = FakeMitmproxyView(["oldest", "middle", "newest"])

        retained_entries = trim_mitmproxy_view_flow_history(view, 2)

        self.assertEqual(retained_entries, 2)
        self.assertEqual(view.stored_flows(), ["middle", "newest"])


class AllowAllTrafficAddonTests(unittest.TestCase):
    """
    Verify addon behavior when allow_all_traffic option is enabled.
    """

    def test_request_allowed_when_allow_all_traffic_is_enabled(self) -> None:
        """
        Allow all requests without filtering when allow_all_traffic is enabled.
        """

        addon = Mitmwall()
        addon.rules = []
        addon.is_allow_all_traffic = lambda: True
        flow = FakeFlow(FakeRequest("blocked.example", "GET", "https://blocked.example/"))

        addon.request(flow)

        self.assertFalse(flow.killed)

    def test_request_blocked_when_allow_all_traffic_is_disabled(self) -> None:
        """
        Block unmatched requests when allow_all_traffic is disabled.
        """

        addon = Mitmwall()
        addon.rules = []
        addon.is_allow_all_traffic = lambda: False
        flow = FakeFlow(FakeRequest("blocked.example", "GET", "https://blocked.example/"))

        addon.request(flow)

        self.assertTrue(flow.killed)

    def test_dns_request_allowed_when_allow_all_traffic_is_enabled(self) -> None:
        """
        Allow all DNS requests without filtering when allow_all_traffic is enabled.
        """

        addon = Mitmwall()
        addon.rules = []
        addon.is_allow_all_traffic = lambda: True
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_blocked_when_allow_all_traffic_is_disabled(self) -> None:
        """
        Block unmatched DNS requests when allow_all_traffic is disabled.
        """

        addon = Mitmwall()
        addon.rules = []
        addon.is_allow_all_traffic = lambda: False
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertEqual(flow.response, ("failed", 5))


class TCPAddonTests(unittest.TestCase):
    """
    Verify addon behavior for non-HTTP TCP connections.
    """

    def test_tcp_start_logs_connection_with_address(self) -> None:
        """
        Log the destination host and port when a TCP connection starts.
        """

        addon = Mitmwall()
        flow = FakeTCPFlow(("github.com", 22))

        addon.tcp_start(flow)

    def test_tcp_start_logs_connection_with_unknown_address(self) -> None:
        """
        Log an unknown destination when a TCP connection has no server address.
        """

        addon = Mitmwall()
        flow = FakeTCPFlow(None)

        addon.tcp_start(flow)

    def test_tcp_start_does_not_apply_rules(self) -> None:
        """
        Verify that tcp_start does not apply any allow rules to TCP traffic.
        """

        addon = Mitmwall()
        addon.rules = []
        addon.is_allow_all_traffic = lambda: False
        flow = FakeTCPFlow(("blocked.example", 443))

        addon.tcp_start(flow)


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
